from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import ContextManager, Iterator, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis.effects.control_plane_recovery import (
    ControlPlaneConvergenceError,
    ControlPlaneMutation,
    CrashSafeControlPlaneCoordinator,
)
from aegis.effects.durable import EffectOutboxRecord, SyntheticEffectExecution, SyntheticWorkerCrash
from aegis.effects.revalidation import RevalidatingEffectOutboxStore
from aegis.effects.rollback_anchor import (
    AnchoredAuthorizationDecision,
    AnchoredAuthorizationSigner,
    ControlPlaneGenerationStore,
    RollbackAnchorError,
    RollbackAnchorReason,
    RollbackResistantSyntheticEffectService,
)
from aegis.effects.signed_authorization import (
    AuthorizationProvenanceError,
    ProvenanceFencedSyntheticEffectService,
    TrustedAuthorizationKeyStore,
)
from aegis.effects.versioned_revalidation import CachedAuthorizationReplica


PROTECTED_CHECKPOINT_SCHEMA = "aegis.protected-control-plane-checkpoint.v1"
PROTECTED_JOURNAL_LINK_SCHEMA = "aegis.protected-control-plane-journal-link.v1"
PROTECTED_CHECKPOINT_POLICY_VERSION = "protected-monotonic-generation-journal-head-v1"


class ProtectedCheckpointReason(StrEnum):
    NOT_INITIALIZED = "protected_checkpoint_not_initialized"
    LOCAL_GENERATION_ROLLBACK = "protected_checkpoint_ahead_of_local_generation"
    CHECKPOINT_BEHIND = "protected_checkpoint_behind_local_generation"
    JOURNAL_HEAD_MISMATCH = "protected_checkpoint_journal_head_mismatch"
    JOURNAL_CHAIN_INVALID = "local_control_plane_journal_chain_invalid"
    CHECKPOINT_CONFLICT = "protected_checkpoint_compare_and_swap_failed"


class ProtectedCheckpointError(RuntimeError):
    def __init__(self, reason: ProtectedCheckpointReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class ProtectedCheckpointCrashPoint(StrEnum):
    AFTER_LOCAL_ACTIVATION = "after_local_activation_before_protected_checkpoint"


class SyntheticProtectedCheckpointCrash(RuntimeError):
    def __init__(self, point: ProtectedCheckpointCrashPoint) -> None:
        self.point = point
        super().__init__(point.value)


class ProtectedControlPlaneCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.protected-control-plane-checkpoint.v1"] = PROTECTED_CHECKPOINT_SCHEMA
    authority_id: str = Field(min_length=1, max_length=256)
    generation: int = Field(ge=1)
    journal_head_sha256: str = Field(min_length=64, max_length=64)

    @field_validator("journal_head_sha256")
    @classmethod
    def _validate_journal_head(cls, value: str) -> str:
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("journal head must be lowercase SHA-256 hex") from exc
        if len(decoded) != 32 or value != value.lower():
            raise ValueError("journal head must be lowercase SHA-256 hex")
        return value


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def genesis_journal_head(authority_id: str) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "schema_version": PROTECTED_JOURNAL_LINK_SCHEMA,
                "authority_id": authority_id,
                "generation": 1,
                "previous_head_sha256": "0" * 64,
                "change_id": "genesis",
                "mutation_sha256": "0" * 64,
            }
        )
    ).hexdigest()


def _extend_journal_head(
    *,
    authority_id: str,
    previous_head_sha256: str,
    from_generation: int,
    target_generation: int,
    change_id: str,
    mutation_sha256: str,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "schema_version": PROTECTED_JOURNAL_LINK_SCHEMA,
                "authority_id": authority_id,
                "from_generation": from_generation,
                "generation": target_generation,
                "previous_head_sha256": previous_head_sha256,
                "change_id": change_id,
                "mutation_sha256": mutation_sha256,
            }
        )
    ).hexdigest()


def active_journal_heads(
    *,
    generation_store: ControlPlaneGenerationStore,
    authority_id: str,
    current_generation: int,
) -> dict[int, str]:
    if current_generation < 1:
        raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID)
    heads: dict[int, str] = {1: genesis_journal_head(authority_id)}
    if current_generation == 1:
        return heads

    with generation_store._connect() as connection:
        rows = connection.execute(
            """
            SELECT change_id, from_generation, target_generation, mutation_sha256, mutation_json
            FROM control_plane_changes
            WHERE authority_id = ? AND status = 'active' AND target_generation <= ?
            ORDER BY target_generation
            """,
            (authority_id, current_generation),
        ).fetchall()

    expected_generation = 1
    previous_head = heads[1]
    for row in rows:
        from_generation = int(row["from_generation"])
        target_generation = int(row["target_generation"])
        if from_generation != expected_generation or target_generation != expected_generation + 1:
            raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID)
        try:
            mutation = ControlPlaneMutation.model_validate_json(str(row["mutation_json"]))
        except Exception as exc:
            raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID) from exc
        canonical_mutation = json.dumps(
            mutation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        mutation_sha256 = hashlib.sha256(canonical_mutation).hexdigest()
        if mutation_sha256 != str(row["mutation_sha256"]):
            raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID)
        previous_head = _extend_journal_head(
            authority_id=authority_id,
            previous_head_sha256=previous_head,
            from_generation=from_generation,
            target_generation=target_generation,
            change_id=str(row["change_id"]),
            mutation_sha256=mutation_sha256,
        )
        heads[target_generation] = previous_head
        expected_generation = target_generation

    if expected_generation != current_generation:
        raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID)
    return heads


class SyntheticProtectedCheckpointAuthority:
    """Synthetic trust-domain stand-in excluded from the P2-R dual-local rollback set."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS protected_control_plane_checkpoints (
                    authority_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    journal_head_sha256 TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _read_locked(
        connection: sqlite3.Connection,
        authority_id: str,
    ) -> ProtectedControlPlaneCheckpoint | None:
        row = connection.execute(
            """
            SELECT authority_id, generation, journal_head_sha256
            FROM protected_control_plane_checkpoints
            WHERE authority_id = ?
            """,
            (authority_id,),
        ).fetchone()
        if row is None:
            return None
        return ProtectedControlPlaneCheckpoint(
            authority_id=str(row["authority_id"]),
            generation=int(row["generation"]),
            journal_head_sha256=str(row["journal_head_sha256"]),
        )

    def initialize(
        self,
        *,
        authority_id: str,
        generation: int,
        journal_head_sha256: str,
    ) -> ProtectedControlPlaneCheckpoint:
        candidate = ProtectedControlPlaneCheckpoint(
            authority_id=authority_id,
            generation=generation,
            journal_head_sha256=journal_head_sha256,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, authority_id)
            if current is not None and current != candidate:
                raise ProtectedCheckpointError(ProtectedCheckpointReason.CHECKPOINT_CONFLICT)
            connection.execute(
                """
                INSERT OR IGNORE INTO protected_control_plane_checkpoints (
                    authority_id, generation, journal_head_sha256
                ) VALUES (?, ?, ?)
                """,
                (authority_id, generation, journal_head_sha256),
            )
        return self.current(authority_id)

    def current(self, authority_id: str) -> ProtectedControlPlaneCheckpoint:
        with self._connect() as connection:
            current = self._read_locked(connection, authority_id)
        if current is None:
            raise ProtectedCheckpointError(ProtectedCheckpointReason.NOT_INITIALIZED)
        return current

    def advance(
        self,
        *,
        authority_id: str,
        expected_generation: int,
        expected_journal_head_sha256: str,
        target_generation: int,
        target_journal_head_sha256: str,
    ) -> ProtectedControlPlaneCheckpoint:
        if target_generation != expected_generation + 1:
            raise ValueError("protected checkpoint generations advance exactly one step")
        ProtectedControlPlaneCheckpoint(
            authority_id=authority_id,
            generation=target_generation,
            journal_head_sha256=target_journal_head_sha256,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, authority_id)
            if current is None:
                raise ProtectedCheckpointError(ProtectedCheckpointReason.NOT_INITIALIZED)
            if (
                current.generation != expected_generation
                or current.journal_head_sha256 != expected_journal_head_sha256
            ):
                raise ProtectedCheckpointError(ProtectedCheckpointReason.CHECKPOINT_CONFLICT)
            connection.execute(
                """
                UPDATE protected_control_plane_checkpoints
                SET generation = ?, journal_head_sha256 = ?
                WHERE authority_id = ?
                """,
                (target_generation, target_journal_head_sha256, authority_id),
            )
        return self.current(authority_id)

    @contextmanager
    def locked_current(self, authority_id: str) -> Iterator[ProtectedControlPlaneCheckpoint]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, authority_id)
            if current is None:
                raise ProtectedCheckpointError(ProtectedCheckpointReason.NOT_INITIALIZED)
            yield current
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


class ActiveGenerationFence(Protocol):
    def locked_active_generation(self) -> ContextManager[int]: ...

    def current_active_generation(self) -> int: ...


class ExternallyCheckpointedControlPlaneCoordinator:
    """P2-Q convergence plus protected monotonic generation/journal-head fencing."""

    policy_version = PROTECTED_CHECKPOINT_POLICY_VERSION

    def __init__(
        self,
        *,
        local_coordinator: CrashSafeControlPlaneCoordinator,
        checkpoint_authority: SyntheticProtectedCheckpointAuthority,
    ) -> None:
        self.local_coordinator = local_coordinator
        self.checkpoint_authority = checkpoint_authority
        self.authority_id = local_coordinator.authority_id
        paths = {
            local_coordinator.execution_database_path.resolve(),
            local_coordinator.generation_store.database_path.resolve(),
            checkpoint_authority.database_path.resolve(),
        }
        if len(paths) != 3:
            raise ValueError("protected checkpoint, anchor journal, and execution state must be independent")

    def initialize(self, *, generation: int = 1) -> ProtectedControlPlaneCheckpoint:
        if generation != 1:
            raise ValueError("P2-R protected checkpoint initialization requires genesis generation 1")
        self.local_coordinator.initialize(generation=generation)
        return self.checkpoint_authority.initialize(
            authority_id=self.authority_id,
            generation=generation,
            journal_head_sha256=genesis_journal_head(self.authority_id),
        )

    def _heads(self, local_generation: int) -> dict[int, str]:
        heads = active_journal_heads(
            generation_store=self.local_coordinator.generation_store,
            authority_id=self.authority_id,
            current_generation=local_generation,
        )
        state = self.local_coordinator.execution_state()
        if state.applied_generation != local_generation:
            raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID)
        if local_generation > 1:
            with self.local_coordinator.generation_store._connect() as connection:
                row = connection.execute(
                    """
                    SELECT change_id, mutation_sha256
                    FROM control_plane_changes
                    WHERE authority_id = ? AND status = 'active' AND target_generation = ?
                    """,
                    (self.authority_id, local_generation),
                ).fetchone()
            if row is None or state.last_change_id != str(row["change_id"]) or state.last_mutation_sha256 != str(row["mutation_sha256"]):
                raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID)
        return heads

    def synchronize_checkpoint(self) -> ProtectedControlPlaneCheckpoint:
        with self.local_coordinator.locked_active_generation() as local_generation:
            checkpoint = self.checkpoint_authority.current(self.authority_id)
            if local_generation < checkpoint.generation:
                raise ProtectedCheckpointError(ProtectedCheckpointReason.LOCAL_GENERATION_ROLLBACK)
            heads = self._heads(local_generation)
            if heads.get(checkpoint.generation) != checkpoint.journal_head_sha256:
                raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_HEAD_MISMATCH)
            while checkpoint.generation < local_generation:
                target = checkpoint.generation + 1
                checkpoint = self.checkpoint_authority.advance(
                    authority_id=self.authority_id,
                    expected_generation=checkpoint.generation,
                    expected_journal_head_sha256=checkpoint.journal_head_sha256,
                    target_generation=target,
                    target_journal_head_sha256=heads[target],
                )
            return checkpoint

    def commit(
        self,
        *,
        change_id: str,
        mutation: ControlPlaneMutation,
        crash_at: ProtectedCheckpointCrashPoint | None = None,
    ):
        change = self.local_coordinator.commit(change_id=change_id, mutation=mutation)
        if crash_at is ProtectedCheckpointCrashPoint.AFTER_LOCAL_ACTIVATION:
            raise SyntheticProtectedCheckpointCrash(crash_at)
        self.synchronize_checkpoint()
        return change

    def recover(self):
        recovered = self.local_coordinator.recover()
        self.synchronize_checkpoint()
        return recovered

    @contextmanager
    def locked_active_generation(self) -> Iterator[int]:
        with self.local_coordinator.locked_active_generation() as local_generation:
            heads = self._heads(local_generation)
            with self.checkpoint_authority.locked_current(self.authority_id) as checkpoint:
                if local_generation < checkpoint.generation:
                    raise ProtectedCheckpointError(ProtectedCheckpointReason.LOCAL_GENERATION_ROLLBACK)
                if local_generation > checkpoint.generation:
                    raise ProtectedCheckpointError(ProtectedCheckpointReason.CHECKPOINT_BEHIND)
                if heads[local_generation] != checkpoint.journal_head_sha256:
                    raise ProtectedCheckpointError(ProtectedCheckpointReason.JOURNAL_HEAD_MISMATCH)
                yield local_generation

    def current_active_generation(self) -> int:
        with self.locked_active_generation() as generation:
            return generation


class CheckpointBoundAuthorizationReplica:
    def __init__(
        self,
        *,
        authorization_replica: CachedAuthorizationReplica,
        signer: AnchoredAuthorizationSigner,
        generation_fence: ActiveGenerationFence,
    ) -> None:
        self.authorization_replica = authorization_replica
        self.signer = signer
        self.generation_fence = generation_fence

    def evaluate(self, record: EffectOutboxRecord) -> AnchoredAuthorizationDecision:
        generation = self.generation_fence.current_active_generation()
        decision = self.authorization_replica.evaluate(record)
        return self.signer.issue(decision, control_plane_generation=generation)


class CheckpointBoundSyntheticEffectService(RollbackResistantSyntheticEffectService):
    def __init__(
        self,
        database_path: Path,
        *,
        authoritative_versions,
        trusted_keys: TrustedAuthorizationKeyStore,
        generation_store: ControlPlaneGenerationStore,
        authority_id: str,
        generation_fence: ActiveGenerationFence,
        expected_issuer_id: str,
        expected_audience: str,
        clock=None,
    ) -> None:
        self.generation_fence = generation_fence
        super().__init__(
            database_path,
            authoritative_versions=authoritative_versions,
            trusted_keys=trusted_keys,
            generation_store=generation_store,
            authority_id=authority_id,
            expected_issuer_id=expected_issuer_id,
            expected_audience=expected_audience,
            clock=clock,
        )

    def execute_with_anchored_decision(
        self,
        record: EffectOutboxRecord,
        envelope: AnchoredAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        with self.generation_fence.locked_active_generation() as current_generation:
            if envelope.payload.control_plane_generation != current_generation:
                raise RollbackAnchorError(RollbackAnchorReason.CONTROL_PLANE_GENERATION_MISMATCH)
            self._verify_envelope_signature(envelope)
            return ProvenanceFencedSyntheticEffectService.execute_with_decision(
                self,
                record,
                envelope.payload.decision,
            )


class ProtectedCheckpointDurableEffectWorker:
    def __init__(
        self,
        *,
        outbox_store: RevalidatingEffectOutboxStore,
        effect_service: CheckpointBoundSyntheticEffectService,
        authorization_replica: CheckpointBoundAuthorizationReplica,
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
        try:
            envelope = self._authorization_replica.evaluate(record)
            execution = self._effect_service.execute_with_anchored_decision(record, envelope)
        except (ControlPlaneConvergenceError, ProtectedCheckpointError):
            raise
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
