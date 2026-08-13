from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Iterator, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from aegis.effects.durable import EffectOutboxRecord, SyntheticEffectExecution, SyntheticWorkerCrash
from aegis.effects.revalidation import RevalidatingEffectOutboxStore
from aegis.effects.signed_authorization import (
    AuthorizationDecisionSigner,
    AuthorizationProvenanceError,
    ProvenanceFencedSyntheticEffectService,
    SignedAuthorizationDecision,
    TrustedAuthorizationKeyStore,
)
from aegis.effects.versioned_revalidation import CachedAuthorizationDecision, CachedAuthorizationReplica


ROLLBACK_ANCHOR_SCHEMA = "aegis.authz-envelope.v1"


class RollbackAnchorReason(StrEnum):
    OUTBOX_CANCELLED = "outbox_cancelled"
    ANCHOR_NOT_INITIALIZED = "anchor_not_initialized"
    CONTROL_PLANE_GENERATION_MISMATCH = "control_plane_generation_mismatch"
    ENVELOPE_SIGNATURE_INVALID = "envelope_signature_invalid"


class RollbackAnchorError(RuntimeError):
    """Fail-closed rollback-fence failure with a non-sensitive reason code."""

    def __init__(self, reason: RollbackAnchorReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class AnchoredAuthorizationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.authz-envelope.v1"] = ROLLBACK_ANCHOR_SCHEMA
    control_plane_generation: int = Field(ge=1)
    decision: SignedAuthorizationDecision


class AnchoredAuthorizationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: AnchoredAuthorizationPayload
    envelope_signature_b64url: str = Field(min_length=1, max_length=256)


def canonical_anchored_payload(payload: AnchoredAuthorizationPayload) -> bytes:
    return json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url") from exc


class ControlPlaneGenerationStore:
    """Independent monotonic generation used to detect execution-database rollback."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._setup()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _setup(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS control_plane_generations (
                    authority_id TEXT PRIMARY KEY,
                    current_generation INTEGER NOT NULL CHECK (current_generation >= 1)
                )
                """
            )

    @staticmethod
    def _read_locked(connection: sqlite3.Connection, authority_id: str) -> int | None:
        row = connection.execute(
            """
            SELECT current_generation
            FROM control_plane_generations
            WHERE authority_id = ?
            """,
            (authority_id,),
        ).fetchone()
        return None if row is None else int(row["current_generation"])

    def initialize(self, *, authority_id: str, generation: int = 1) -> int:
        if not authority_id or generation < 1:
            raise ValueError("invalid control-plane generation initialization")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, authority_id)
            if current is not None and current != generation:
                raise ValueError("control-plane generation already initialized")
            connection.execute(
                """
                INSERT OR IGNORE INTO control_plane_generations (
                    authority_id, current_generation
                ) VALUES (?, ?)
                """,
                (authority_id, generation),
            )
        return self.current(authority_id)

    def current(self, authority_id: str) -> int:
        with self._connect() as connection:
            current = self._read_locked(connection, authority_id)
        if current is None:
            raise KeyError("control-plane generation not initialized")
        return current

    def advance(self, *, authority_id: str, expected_current: int | None = None) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, authority_id)
            if current is None:
                raise KeyError("control-plane generation not initialized")
            if expected_current is not None and current != expected_current:
                raise ValueError("control-plane generation compare-and-swap failed")
            next_generation = current + 1
            connection.execute(
                """
                UPDATE control_plane_generations
                SET current_generation = ?
                WHERE authority_id = ?
                """,
                (next_generation, authority_id),
            )
        return next_generation

    @contextmanager
    def locked_current(self, authority_id: str) -> Iterator[int]:
        """Hold the anchor write lock while the downstream commits one effect decision."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, authority_id)
            if current is None:
                raise RollbackAnchorError(RollbackAnchorReason.ANCHOR_NOT_INITIALIZED)
            yield current
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


class AnchoredAuthorizationSigner:
    """Adds an independently monotonic generation to a P2-O signed decision."""

    def __init__(self, decision_signer: AuthorizationDecisionSigner) -> None:
        self.decision_signer = decision_signer

    def issue(
        self,
        decision: CachedAuthorizationDecision,
        *,
        control_plane_generation: int,
    ) -> AnchoredAuthorizationDecision:
        signed_decision = self.decision_signer.issue(decision)
        payload = AnchoredAuthorizationPayload(
            control_plane_generation=control_plane_generation,
            decision=signed_decision,
        )
        signature = self.decision_signer.private_key.sign(canonical_anchored_payload(payload))
        return AnchoredAuthorizationDecision(
            payload=payload,
            envelope_signature_b64url=_b64url_encode(signature),
        )


class AnchoredAuthorizationReplica:
    """Issues authorization evidence bound to the independent current generation."""

    def __init__(
        self,
        *,
        authorization_replica: CachedAuthorizationReplica,
        signer: AnchoredAuthorizationSigner,
        generation_store: ControlPlaneGenerationStore,
        authority_id: str,
    ) -> None:
        self.authorization_replica = authorization_replica
        self.signer = signer
        self.generation_store = generation_store
        self.authority_id = authority_id

    def evaluate(self, record: EffectOutboxRecord) -> AnchoredAuthorizationDecision:
        generation = self.generation_store.current(self.authority_id)
        decision = self.authorization_replica.evaluate(record)
        return self.signer.issue(decision, control_plane_generation=generation)


class RollbackResistantSyntheticEffectService(ProvenanceFencedSyntheticEffectService):
    """Extends P2-O with an independently durable monotonic generation fence."""

    def __init__(
        self,
        database_path: Path,
        *,
        authoritative_versions,
        trusted_keys: TrustedAuthorizationKeyStore,
        generation_store: ControlPlaneGenerationStore,
        authority_id: str,
        expected_issuer_id: str,
        expected_audience: str,
        clock=None,
    ) -> None:
        database_path = Path(database_path)
        if database_path.resolve() == generation_store.database_path.resolve():
            raise ValueError("rollback anchor must be independent of the execution database")
        self.generation_store = generation_store
        self.authority_id = authority_id
        super().__init__(
            database_path,
            authoritative_versions=authoritative_versions,
            trusted_keys=trusted_keys,
            expected_issuer_id=expected_issuer_id,
            expected_audience=expected_audience,
            clock=clock,
        )

    def _verify_envelope_signature(self, envelope: AnchoredAuthorizationDecision) -> None:
        claims = envelope.payload.decision.claims
        with self._connect() as connection:
            key_row = TrustedAuthorizationKeyStore._key_locked(
                connection,
                issuer_id=claims.issuer_id,
                audience=claims.audience,
                key_id=claims.key_id,
            )
        if key_row is None:
            raise RollbackAnchorError(RollbackAnchorReason.ENVELOPE_SIGNATURE_INVALID)
        try:
            signature = _b64url_decode(envelope.envelope_signature_b64url)
            if len(signature) != 64:
                raise ValueError("invalid Ed25519 signature length")
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(key_row["public_key_hex"])))
            public_key.verify(signature, canonical_anchored_payload(envelope.payload))
        except (InvalidSignature, ValueError):
            raise RollbackAnchorError(RollbackAnchorReason.ENVELOPE_SIGNATURE_INVALID) from None

    def execute_with_anchored_decision(
        self,
        record: EffectOutboxRecord,
        envelope: AnchoredAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        with self.generation_store.locked_current(self.authority_id) as current_generation:
            if envelope.payload.control_plane_generation != current_generation:
                raise RollbackAnchorError(
                    RollbackAnchorReason.CONTROL_PLANE_GENERATION_MISMATCH
                )
            self._verify_envelope_signature(envelope)
            return super().execute_with_decision(record, envelope.payload.decision)


class RollbackResistantDurableEffectWorker:
    """At-least-once worker that requires P2-O provenance plus the P2-P anchor."""

    def __init__(
        self,
        *,
        outbox_store: RevalidatingEffectOutboxStore,
        effect_service: RollbackResistantSyntheticEffectService,
        authorization_replica: AnchoredAuthorizationReplica,
        crash_after_effect_once: bool = False,
    ) -> None:
        self._outbox_store = outbox_store
        self._effect_service = effect_service
        self._authorization_replica = authorization_replica
        self._crash_after_effect_once = crash_after_effect_once

    def deliver(self, approval_id: str) -> SyntheticEffectExecution:
        current = self._outbox_store.get(approval_id)
        if current.status == "cancelled":
            raise RollbackAnchorError(RollbackAnchorReason.OUTBOX_CANCELLED)

        record = self._outbox_store.begin_delivery(approval_id)
        envelope = self._authorization_replica.evaluate(record)
        try:
            execution = self._effect_service.execute_with_anchored_decision(record, envelope)
        except (RollbackAnchorError, AuthorizationProvenanceError):
            self._outbox_store.cancel(
                approval_id=approval_id,
                idempotency_key=record.idempotency_key,
            )
            raise

        if self._crash_after_effect_once:
            self._crash_after_effect_once = False
            raise SyntheticWorkerCrash("synthetic crash after effect before outbox acknowledgement")

        self._outbox_store.complete(
            approval_id=approval_id,
            idempotency_key=record.idempotency_key,
        )
        return execution
