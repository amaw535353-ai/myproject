from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.effects.durable import (
    EffectBindingError,
    EffectOutboxRecord,
    SyntheticEffectExecution,
    SyntheticIdempotentEffectService,
    SyntheticWorkerCrash,
)
from aegis.effects.revalidation import ExecutionAuthorizationReason, RevalidatingEffectOutboxStore
from aegis.effects.versioned_revalidation import (
    AuthorizationVersionStore,
    CachedAuthorizationDecision,
    CachedAuthorizationReplica,
    authorization_record_binding,
)


AUTHORIZATION_DECISION_SCHEMA = "aegis.authz-decision.v1"


class AuthorizationProvenanceReason(StrEnum):
    OUTBOX_CANCELLED = "outbox_cancelled"
    ISSUER_MISMATCH = "issuer_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    UNTRUSTED_SIGNING_KEY = "untrusted_signing_key"
    KEY_EPOCH_MISMATCH = "key_epoch_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    DECISION_NOT_YET_VALID = "decision_not_yet_valid"
    DECISION_EXPIRED = "decision_expired"
    TENANT_BINDING_MISMATCH = "tenant_binding_mismatch"
    DECISION_BINDING_MISMATCH = "decision_binding_mismatch"
    AUTHORITATIVE_VERSION_NOT_FOUND = "authoritative_version_not_found"
    REVOCATION_EPOCH_MISMATCH = "revocation_epoch_mismatch"
    POLICY_VERSION_MISMATCH = "policy_version_mismatch"
    CACHED_AUTHORIZATION_DENIED = "cached_authorization_denied"


class AuthorizationProvenanceError(RuntimeError):
    """Fail-closed authorization-evidence failure with a non-sensitive reason code."""

    def __init__(self, reason: AuthorizationProvenanceReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class AuthorizationDecisionClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.authz-decision.v1"] = AUTHORIZATION_DECISION_SCHEMA
    issuer_id: str = Field(min_length=1, max_length=128)
    audience: str = Field(min_length=1, max_length=128)
    key_id: str = Field(min_length=1, max_length=128)
    key_epoch: int = Field(ge=1)
    tenant_id: str = Field(min_length=1, max_length=256)
    record_binding_hash: str = Field(min_length=64, max_length=64)
    policy_version: int = Field(ge=1)
    revocation_epoch: int = Field(ge=1)
    reason: ExecutionAuthorizationReason
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)

    @model_validator(mode="after")
    def _expiry_after_issue(self) -> "AuthorizationDecisionClaims":
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization decision expiry must follow issue time")
        return self


class SignedAuthorizationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claims: AuthorizationDecisionClaims
    signature_b64url: str = Field(min_length=1, max_length=256)


def canonical_authorization_claims(claims: AuthorizationDecisionClaims) -> bytes:
    return json.dumps(
        claims.model_dump(mode="json"),
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


class AuthorizationDecisionSigner:
    """Synthetic decision issuer holding an Ed25519 private key outside the effect node."""

    def __init__(
        self,
        *,
        issuer_id: str,
        audience: str,
        key_id: str,
        key_epoch: int,
        private_key: Ed25519PrivateKey,
        ttl_seconds: int = 300,
        clock=None,
    ) -> None:
        if key_epoch < 1:
            raise ValueError("key epoch must be positive")
        if ttl_seconds < 1:
            raise ValueError("decision TTL must be positive")
        self.issuer_id = issuer_id
        self.audience = audience
        self.key_id = key_id
        self.key_epoch = key_epoch
        self.private_key = private_key
        self.ttl_seconds = ttl_seconds
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def issue(self, decision: CachedAuthorizationDecision) -> SignedAuthorizationDecision:
        issued_at = int(self._clock().timestamp())
        claims = AuthorizationDecisionClaims(
            issuer_id=self.issuer_id,
            audience=self.audience,
            key_id=self.key_id,
            key_epoch=self.key_epoch,
            tenant_id=decision.tenant_id,
            record_binding_hash=decision.record_binding_hash,
            policy_version=decision.policy_version,
            revocation_epoch=decision.revocation_epoch,
            reason=decision.reason,
            issued_at=issued_at,
            expires_at=issued_at + self.ttl_seconds,
        )
        signature = self.private_key.sign(canonical_authorization_claims(claims))
        return SignedAuthorizationDecision(
            claims=claims,
            signature_b64url=_b64url_encode(signature),
        )

    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class SignedAuthorizationReplica:
    """Signs a local cached authorization result before it crosses the effect boundary."""

    def __init__(
        self,
        *,
        authorization_replica: CachedAuthorizationReplica,
        signer: AuthorizationDecisionSigner,
    ) -> None:
        self.authorization_replica = authorization_replica
        self.signer = signer

    def evaluate(self, record: EffectOutboxRecord) -> SignedAuthorizationDecision:
        return self.signer.issue(self.authorization_replica.evaluate(record))


class TrustedAuthorizationKeyStore:
    """Authoritative public-key trust state and monotonic signing-key epoch."""

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
                CREATE TABLE IF NOT EXISTS authorization_trusted_keys (
                    issuer_id TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    key_epoch INTEGER NOT NULL CHECK (key_epoch >= 1),
                    public_key_hex TEXT NOT NULL,
                    PRIMARY KEY (issuer_id, audience, key_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authorization_trusted_key_epochs (
                    issuer_id TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    current_key_epoch INTEGER NOT NULL CHECK (current_key_epoch >= 1),
                    PRIMARY KEY (issuer_id, audience)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authorization_provenance_denials (
                    approval_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    denied_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _current_epoch_locked(
        connection: sqlite3.Connection,
        *,
        issuer_id: str,
        audience: str,
    ) -> int | None:
        row = connection.execute(
            """
            SELECT current_key_epoch
            FROM authorization_trusted_key_epochs
            WHERE issuer_id = ? AND audience = ?
            """,
            (issuer_id, audience),
        ).fetchone()
        return None if row is None else int(row["current_key_epoch"])

    @staticmethod
    def _key_locked(
        connection: sqlite3.Connection,
        *,
        issuer_id: str,
        audience: str,
        key_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT issuer_id, audience, key_id, key_epoch, public_key_hex
            FROM authorization_trusted_keys
            WHERE issuer_id = ? AND audience = ? AND key_id = ?
            """,
            (issuer_id, audience, key_id),
        ).fetchone()

    def trust_initial_key(
        self,
        *,
        issuer_id: str,
        audience: str,
        key_id: str,
        key_epoch: int,
        public_key_bytes: bytes,
    ) -> None:
        if key_epoch < 1 or len(public_key_bytes) != 32:
            raise ValueError("invalid Ed25519 trust key")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._current_epoch_locked(
                connection,
                issuer_id=issuer_id,
                audience=audience,
            )
            if current is not None and current != key_epoch:
                raise ValueError("initial trust epoch already established")
            connection.execute(
                """
                INSERT INTO authorization_trusted_keys (
                    issuer_id, audience, key_id, key_epoch, public_key_hex
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(issuer_id, audience, key_id) DO UPDATE SET
                    key_epoch = excluded.key_epoch,
                    public_key_hex = excluded.public_key_hex
                """,
                (issuer_id, audience, key_id, key_epoch, public_key_bytes.hex()),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO authorization_trusted_key_epochs (
                    issuer_id, audience, current_key_epoch
                ) VALUES (?, ?, ?)
                """,
                (issuer_id, audience, key_epoch),
            )

    def rotate_key(
        self,
        *,
        issuer_id: str,
        audience: str,
        key_id: str,
        key_epoch: int,
        public_key_bytes: bytes,
    ) -> None:
        if key_epoch < 1 or len(public_key_bytes) != 32:
            raise ValueError("invalid Ed25519 trust key")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._current_epoch_locked(
                connection,
                issuer_id=issuer_id,
                audience=audience,
            )
            if current is None:
                raise KeyError("authorization issuer trust not initialized")
            if key_epoch <= current:
                raise ValueError("authorization signing key epochs are monotonic")
            connection.execute(
                """
                INSERT INTO authorization_trusted_keys (
                    issuer_id, audience, key_id, key_epoch, public_key_hex
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(issuer_id, audience, key_id) DO UPDATE SET
                    key_epoch = excluded.key_epoch,
                    public_key_hex = excluded.public_key_hex
                """,
                (issuer_id, audience, key_id, key_epoch, public_key_bytes.hex()),
            )
            connection.execute(
                """
                UPDATE authorization_trusted_key_epochs
                SET current_key_epoch = ?
                WHERE issuer_id = ? AND audience = ?
                """,
                (key_epoch, issuer_id, audience),
            )

    def current_epoch(self, *, issuer_id: str, audience: str) -> int:
        with self._connect() as connection:
            current = self._current_epoch_locked(
                connection,
                issuer_id=issuer_id,
                audience=audience,
            )
        if current is None:
            raise KeyError("authorization issuer trust not initialized")
        return current


class ProvenanceFencedSyntheticEffectService(SyntheticIdempotentEffectService):
    """Verifies signed authorization provenance and freshness before the first effect."""

    def __init__(
        self,
        database_path: Path,
        *,
        authoritative_versions: AuthorizationVersionStore,
        trusted_keys: TrustedAuthorizationKeyStore,
        expected_issuer_id: str,
        expected_audience: str,
        clock=None,
    ) -> None:
        database_path = Path(database_path)
        if authoritative_versions.database_path != database_path:
            raise ValueError("authoritative versions and effect ledger must share one SQLite database")
        if trusted_keys.database_path != database_path:
            raise ValueError("trusted keys and effect ledger must share one SQLite database")
        self.authoritative_versions = authoritative_versions
        self.trusted_keys = trusted_keys
        self.expected_issuer_id = expected_issuer_id
        self.expected_audience = expected_audience
        if clock is None:
            super().__init__(database_path)
        else:
            super().__init__(database_path, clock=clock)
        self.authoritative_versions._setup()
        self.trusted_keys._setup()

    def _decision_failure(
        self,
        connection: sqlite3.Connection,
        *,
        record: EffectOutboxRecord,
        decision: SignedAuthorizationDecision,
    ) -> AuthorizationProvenanceReason | None:
        claims = decision.claims
        if claims.issuer_id != self.expected_issuer_id:
            return AuthorizationProvenanceReason.ISSUER_MISMATCH
        if claims.audience != self.expected_audience:
            return AuthorizationProvenanceReason.AUDIENCE_MISMATCH

        key_row = TrustedAuthorizationKeyStore._key_locked(
            connection,
            issuer_id=claims.issuer_id,
            audience=claims.audience,
            key_id=claims.key_id,
        )
        if key_row is None:
            return AuthorizationProvenanceReason.UNTRUSTED_SIGNING_KEY
        current_key_epoch = TrustedAuthorizationKeyStore._current_epoch_locked(
            connection,
            issuer_id=claims.issuer_id,
            audience=claims.audience,
        )
        if current_key_epoch is None:
            return AuthorizationProvenanceReason.UNTRUSTED_SIGNING_KEY
        if claims.key_epoch != int(key_row["key_epoch"]) or claims.key_epoch != current_key_epoch:
            return AuthorizationProvenanceReason.KEY_EPOCH_MISMATCH

        try:
            signature = _b64url_decode(decision.signature_b64url)
            if len(signature) != 64:
                raise ValueError("invalid Ed25519 signature length")
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(key_row["public_key_hex"])))
            public_key.verify(signature, canonical_authorization_claims(claims))
        except (InvalidSignature, ValueError):
            return AuthorizationProvenanceReason.SIGNATURE_INVALID

        now = int(self._clock().timestamp())
        if claims.issued_at > now:
            return AuthorizationProvenanceReason.DECISION_NOT_YET_VALID
        if claims.expires_at <= now:
            return AuthorizationProvenanceReason.DECISION_EXPIRED
        if claims.tenant_id != record.tenant_id:
            return AuthorizationProvenanceReason.TENANT_BINDING_MISMATCH
        if claims.record_binding_hash != authorization_record_binding(record):
            return AuthorizationProvenanceReason.DECISION_BINDING_MISMATCH

        authoritative = AuthorizationVersionStore._read_locked(connection, record.tenant_id)
        if authoritative is None:
            return AuthorizationProvenanceReason.AUTHORITATIVE_VERSION_NOT_FOUND
        if claims.revocation_epoch != authoritative.revocation_epoch:
            return AuthorizationProvenanceReason.REVOCATION_EPOCH_MISMATCH
        if claims.policy_version != authoritative.policy_version:
            return AuthorizationProvenanceReason.POLICY_VERSION_MISMATCH
        if claims.reason is not ExecutionAuthorizationReason.ALLOWED:
            return AuthorizationProvenanceReason.CACHED_AUTHORIZATION_DENIED
        return None

    def execute_with_decision(
        self,
        record: EffectOutboxRecord,
        decision: SignedAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        denial_reason: AuthorizationProvenanceReason | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")

            existing = connection.execute(
                "SELECT * FROM synthetic_effect_ledger WHERE idempotency_key = ?",
                (record.idempotency_key,),
            ).fetchone()
            if existing is not None:
                self._validate_existing(existing, record=record)
                return SyntheticEffectExecution(
                    effect_ref=str(existing["effect_ref"]),
                    approval_id=record.approval_id,
                    action=record.action,
                    duplicate_suppressed=True,
                )

            conflicting = connection.execute(
                "SELECT * FROM synthetic_effect_ledger WHERE approval_id = ?",
                (record.approval_id,),
            ).fetchone()
            if conflicting is not None:
                raise EffectBindingError("approval already mapped to another idempotency key")

            durable_denial = connection.execute(
                """
                SELECT idempotency_key, reason
                FROM authorization_provenance_denials
                WHERE approval_id = ?
                """,
                (record.approval_id,),
            ).fetchone()
            if durable_denial is not None:
                if str(durable_denial["idempotency_key"]) != record.idempotency_key:
                    raise EffectBindingError("authorization provenance denial binding mismatch")
                denial_reason = AuthorizationProvenanceReason(str(durable_denial["reason"]))
            else:
                denial_reason = self._decision_failure(
                    connection,
                    record=record,
                    decision=decision,
                )
                if denial_reason is not None:
                    connection.execute(
                        """
                        INSERT INTO authorization_provenance_denials (
                            approval_id, idempotency_key, reason, denied_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            record.approval_id,
                            record.idempotency_key,
                            denial_reason.value,
                            self._clock().isoformat(),
                        ),
                    )
                else:
                    effect_ref = f"synthetic-effect-{record.idempotency_key[:20]}"
                    connection.execute(
                        """
                        INSERT INTO synthetic_effect_ledger (
                            idempotency_key, approval_id, requester_user_id, tenant_id,
                            action, normalized_arguments_json, effect_ref, executed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.idempotency_key,
                            record.approval_id,
                            record.requester_user_id,
                            record.tenant_id,
                            record.action.value,
                            record.normalized_arguments_json,
                            effect_ref,
                            self._clock().isoformat(),
                        ),
                    )
                    return SyntheticEffectExecution(
                        effect_ref=effect_ref,
                        approval_id=record.approval_id,
                        action=record.action,
                        duplicate_suppressed=False,
                    )

        assert denial_reason is not None
        raise AuthorizationProvenanceError(denial_reason)


class ProvenanceFencedDurableEffectWorker:
    """At-least-once worker consuming only authenticated authorization evidence."""

    def __init__(
        self,
        *,
        outbox_store: RevalidatingEffectOutboxStore,
        effect_service: ProvenanceFencedSyntheticEffectService,
        authorization_replica: SignedAuthorizationReplica,
        crash_after_effect_once: bool = False,
    ) -> None:
        self._outbox_store = outbox_store
        self._effect_service = effect_service
        self._authorization_replica = authorization_replica
        self._crash_after_effect_once = crash_after_effect_once

    def deliver(self, approval_id: str) -> SyntheticEffectExecution:
        current = self._outbox_store.get(approval_id)
        if current.status == "cancelled":
            raise AuthorizationProvenanceError(AuthorizationProvenanceReason.OUTBOX_CANCELLED)

        record = self._outbox_store.begin_delivery(approval_id)
        decision = self._authorization_replica.evaluate(record)
        try:
            execution = self._effect_service.execute_with_decision(record, decision)
        except AuthorizationProvenanceError:
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
