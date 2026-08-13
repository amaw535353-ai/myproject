from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Iterator, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


CONTROL_PLANE_CHANGE_SCHEMA = "aegis.control-plane-change.v1"
EXECUTION_CONTROL_PLANE_SCHEMA = "aegis.execution-control-plane-state.v1"


class ControlPlaneMutationKind(StrEnum):
    SUBJECT_ACTIVE = "subject_active"
    PASSWORD_RESET_ENABLED = "password_reset_enabled"
    SIGNING_KEY_ROTATION = "signing_key_rotation"


class ControlPlaneChangeStatus(StrEnum):
    PREPARED = "prepared"
    APPLIED = "applied"
    ACTIVE = "active"


class ControlPlaneCrashPoint(StrEnum):
    AFTER_PREPARE = "after_prepare"
    AFTER_EXECUTION_APPLY = "after_execution_apply"
    AFTER_MARK_APPLIED = "after_mark_applied"


class ControlPlaneConvergenceReason(StrEnum):
    CHANGE_PENDING = "control_plane_change_pending"
    EXECUTION_STATE_NOT_INITIALIZED = "execution_control_plane_state_not_initialized"
    EXECUTION_GENERATION_MISMATCH = "execution_control_plane_generation_mismatch"
    CHANGE_CONFLICT = "control_plane_change_conflict"


class ControlPlaneConvergenceError(RuntimeError):
    """Fail-closed cross-database control-plane convergence failure."""

    def __init__(self, reason: ControlPlaneConvergenceReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class SyntheticControlPlaneCrash(RuntimeError):
    """Deterministic process-crash injection used only by the local P2-Q lab."""

    def __init__(self, point: ControlPlaneCrashPoint) -> None:
        self.point = point
        super().__init__(point.value)


class ControlPlaneMutation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.control-plane-change.v1"] = CONTROL_PLANE_CHANGE_SCHEMA
    kind: ControlPlaneMutationKind
    tenant_id: str | None = Field(default=None, min_length=1, max_length=256)
    user_id: str | None = Field(default=None, min_length=1, max_length=256)
    active: bool | None = None
    password_reset_enabled: bool | None = None
    issuer_id: str | None = Field(default=None, min_length=1, max_length=128)
    audience: str | None = Field(default=None, min_length=1, max_length=128)
    key_id: str | None = Field(default=None, min_length=1, max_length=128)
    key_epoch: int | None = Field(default=None, ge=1)
    public_key_hex: str | None = Field(default=None, min_length=64, max_length=64)

    @model_validator(mode="after")
    def _validate_kind_fields(self) -> "ControlPlaneMutation":
        if self.kind is ControlPlaneMutationKind.SUBJECT_ACTIVE:
            if self.tenant_id is None or self.user_id is None or self.active is None:
                raise ValueError("subject-active mutation requires tenant, user, and active state")
            if any(
                value is not None
                for value in (
                    self.password_reset_enabled,
                    self.issuer_id,
                    self.audience,
                    self.key_id,
                    self.key_epoch,
                    self.public_key_hex,
                )
            ):
                raise ValueError("subject-active mutation contains unrelated fields")
        elif self.kind is ControlPlaneMutationKind.PASSWORD_RESET_ENABLED:
            if self.tenant_id is None or self.password_reset_enabled is None:
                raise ValueError("password-reset mutation requires tenant and enabled state")
            if any(
                value is not None
                for value in (
                    self.user_id,
                    self.active,
                    self.issuer_id,
                    self.audience,
                    self.key_id,
                    self.key_epoch,
                    self.public_key_hex,
                )
            ):
                raise ValueError("password-reset mutation contains unrelated fields")
        else:
            if any(
                value is None
                for value in (
                    self.issuer_id,
                    self.audience,
                    self.key_id,
                    self.key_epoch,
                    self.public_key_hex,
                )
            ):
                raise ValueError("signing-key rotation requires complete key metadata")
            if any(
                value is not None
                for value in (
                    self.tenant_id,
                    self.user_id,
                    self.active,
                    self.password_reset_enabled,
                )
            ):
                raise ValueError("signing-key rotation contains unrelated fields")
            try:
                public_key = bytes.fromhex(str(self.public_key_hex))
            except ValueError as exc:
                raise ValueError("invalid Ed25519 public key encoding") from exc
            if len(public_key) != 32:
                raise ValueError("invalid Ed25519 public key length")
        return self


class ControlPlaneChange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_id: str
    change_id: str
    from_generation: int = Field(ge=1)
    target_generation: int = Field(ge=2)
    mutation_sha256: str = Field(min_length=64, max_length=64)
    mutation: ControlPlaneMutation
    status: ControlPlaneChangeStatus


class ExecutionControlPlaneState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.execution-control-plane-state.v1"] = EXECUTION_CONTROL_PLANE_SCHEMA
    authority_id: str
    applied_generation: int = Field(ge=1)
    last_change_id: str | None = None
    last_mutation_sha256: str | None = Field(default=None, min_length=64, max_length=64)


def canonical_control_plane_mutation(mutation: ControlPlaneMutation) -> bytes:
    return json.dumps(
        mutation.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def control_plane_mutation_hash(mutation: ControlPlaneMutation) -> str:
    return hashlib.sha256(canonical_control_plane_mutation(mutation)).hexdigest()


class CrashSafeControlPlaneCoordinator:
    """Recoverable prepared/applied/active protocol across anchor and execution SQLite files."""

    def __init__(
        self,
        *,
        execution_database_path: Path,
        generation_store: ControlPlaneGenerationStore,
        authority_id: str,
    ) -> None:
        self.execution_database_path = Path(execution_database_path)
        self.generation_store = generation_store
        self.authority_id = authority_id
        if self.execution_database_path.resolve() == generation_store.database_path.resolve():
            raise ValueError("control-plane journal must be independent of execution state")
        self.execution_database_path.parent.mkdir(parents=True, exist_ok=True)
        self._setup()

    def _execution_connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.execution_database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _setup(self) -> None:
        with self.generation_store._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS control_plane_changes (
                    authority_id TEXT NOT NULL,
                    change_id TEXT NOT NULL,
                    from_generation INTEGER NOT NULL CHECK (from_generation >= 1),
                    target_generation INTEGER NOT NULL CHECK (target_generation >= 2),
                    mutation_sha256 TEXT NOT NULL,
                    mutation_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('prepared', 'applied', 'active')),
                    PRIMARY KEY (authority_id, change_id),
                    UNIQUE (authority_id, target_generation)
                )
                """
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS one_pending_control_plane_change
                ON control_plane_changes(authority_id)
                WHERE status != 'active'
                """
            )
        with self._execution_connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_control_plane_state (
                    authority_id TEXT PRIMARY KEY,
                    applied_generation INTEGER NOT NULL CHECK (applied_generation >= 1),
                    last_change_id TEXT,
                    last_mutation_sha256 TEXT
                )
                """
            )

    @staticmethod
    def _row_to_change(row: sqlite3.Row) -> ControlPlaneChange:
        return ControlPlaneChange(
            authority_id=str(row["authority_id"]),
            change_id=str(row["change_id"]),
            from_generation=int(row["from_generation"]),
            target_generation=int(row["target_generation"]),
            mutation_sha256=str(row["mutation_sha256"]),
            mutation=ControlPlaneMutation.model_validate_json(str(row["mutation_json"])),
            status=ControlPlaneChangeStatus(str(row["status"])),
        )

    @staticmethod
    def _execution_row_to_state(row: sqlite3.Row) -> ExecutionControlPlaneState:
        return ExecutionControlPlaneState(
            authority_id=str(row["authority_id"]),
            applied_generation=int(row["applied_generation"]),
            last_change_id=(None if row["last_change_id"] is None else str(row["last_change_id"])),
            last_mutation_sha256=(
                None if row["last_mutation_sha256"] is None else str(row["last_mutation_sha256"])
            ),
        )

    @staticmethod
    def _execution_state_locked(
        connection: sqlite3.Connection,
        authority_id: str,
    ) -> ExecutionControlPlaneState | None:
        row = connection.execute(
            """
            SELECT authority_id, applied_generation, last_change_id, last_mutation_sha256
            FROM execution_control_plane_state
            WHERE authority_id = ?
            """,
            (authority_id,),
        ).fetchone()
        return None if row is None else CrashSafeControlPlaneCoordinator._execution_row_to_state(row)

    def initialize(self, *, generation: int = 1) -> ExecutionControlPlaneState:
        anchor_generation = self.generation_store.initialize(
            authority_id=self.authority_id,
            generation=generation,
        )
        if anchor_generation != generation:
            raise ValueError("control-plane initialization generation mismatch")
        with self._execution_connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._execution_state_locked(connection, self.authority_id)
            if current is not None and current.applied_generation != generation:
                raise ValueError("execution control-plane state already initialized")
            connection.execute(
                """
                INSERT OR IGNORE INTO execution_control_plane_state (
                    authority_id, applied_generation, last_change_id, last_mutation_sha256
                ) VALUES (?, ?, NULL, NULL)
                """,
                (self.authority_id, generation),
            )
        return self.execution_state()

    def execution_state(self) -> ExecutionControlPlaneState:
        with self._execution_connect() as connection:
            state = self._execution_state_locked(connection, self.authority_id)
        if state is None:
            raise ControlPlaneConvergenceError(
                ControlPlaneConvergenceReason.EXECUTION_STATE_NOT_INITIALIZED
            )
        return state

    def get_change(self, change_id: str) -> ControlPlaneChange:
        with self.generation_store._connect() as connection:
            row = connection.execute(
                """
                SELECT authority_id, change_id, from_generation, target_generation,
                       mutation_sha256, mutation_json, status
                FROM control_plane_changes
                WHERE authority_id = ? AND change_id = ?
                """,
                (self.authority_id, change_id),
            ).fetchone()
        if row is None:
            raise KeyError("control-plane change not found")
        return self._row_to_change(row)

    def pending_change(self) -> ControlPlaneChange | None:
        with self.generation_store._connect() as connection:
            row = connection.execute(
                """
                SELECT authority_id, change_id, from_generation, target_generation,
                       mutation_sha256, mutation_json, status
                FROM control_plane_changes
                WHERE authority_id = ? AND status != 'active'
                ORDER BY target_generation
                LIMIT 1
                """,
                (self.authority_id,),
            ).fetchone()
        return None if row is None else self._row_to_change(row)

    def prepare(self, *, change_id: str, mutation: ControlPlaneMutation) -> ControlPlaneChange:
        mutation_sha256 = control_plane_mutation_hash(mutation)
        mutation_json = canonical_control_plane_mutation(mutation).decode("utf-8")
        with self.generation_store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT authority_id, change_id, from_generation, target_generation,
                       mutation_sha256, mutation_json, status
                FROM control_plane_changes
                WHERE authority_id = ? AND change_id = ?
                """,
                (self.authority_id, change_id),
            ).fetchone()
            if existing is not None:
                change = self._row_to_change(existing)
                if change.mutation_sha256 != mutation_sha256:
                    raise ControlPlaneConvergenceError(ControlPlaneConvergenceReason.CHANGE_CONFLICT)
                return change
            pending = connection.execute(
                """
                SELECT 1 FROM control_plane_changes
                WHERE authority_id = ? AND status != 'active'
                LIMIT 1
                """,
                (self.authority_id,),
            ).fetchone()
            if pending is not None:
                raise ControlPlaneConvergenceError(ControlPlaneConvergenceReason.CHANGE_PENDING)
            current = ControlPlaneGenerationStore._read_locked(connection, self.authority_id)
            if current is None:
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_STATE_NOT_INITIALIZED
                )
            target = current + 1
            connection.execute(
                """
                INSERT INTO control_plane_changes (
                    authority_id, change_id, from_generation, target_generation,
                    mutation_sha256, mutation_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, 'prepared')
                """,
                (
                    self.authority_id,
                    change_id,
                    current,
                    target,
                    mutation_sha256,
                    mutation_json,
                ),
            )
        return self.get_change(change_id)

    def _apply_mutation_locked(
        self,
        connection: sqlite3.Connection,
        mutation: ControlPlaneMutation,
    ) -> None:
        if mutation.kind is ControlPlaneMutationKind.SUBJECT_ACTIVE:
            row = connection.execute(
                "SELECT tenant_id FROM current_subject_authorization WHERE user_id = ?",
                (mutation.user_id,),
            ).fetchone()
            if row is None or str(row["tenant_id"]) != mutation.tenant_id:
                raise KeyError("synthetic subject mutation target not found")
            version = connection.execute(
                "SELECT 1 FROM authorization_versions WHERE tenant_id = ?",
                (mutation.tenant_id,),
            ).fetchone()
            if version is None:
                raise KeyError("synthetic authorization version not found")
            connection.execute(
                "UPDATE current_subject_authorization SET active = ? WHERE user_id = ?",
                (int(bool(mutation.active)), mutation.user_id),
            )
            connection.execute(
                """
                UPDATE authorization_versions
                SET revocation_epoch = revocation_epoch + 1
                WHERE tenant_id = ?
                """,
                (mutation.tenant_id,),
            )
            return

        if mutation.kind is ControlPlaneMutationKind.PASSWORD_RESET_ENABLED:
            version = connection.execute(
                "SELECT 1 FROM authorization_versions WHERE tenant_id = ?",
                (mutation.tenant_id,),
            ).fetchone()
            if version is None:
                raise KeyError("synthetic authorization version not found")
            connection.execute(
                """
                INSERT INTO current_tenant_policy (tenant_id, password_reset_enabled)
                VALUES (?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    password_reset_enabled = excluded.password_reset_enabled
                """,
                (mutation.tenant_id, int(bool(mutation.password_reset_enabled))),
            )
            connection.execute(
                """
                UPDATE authorization_versions
                SET policy_version = policy_version + 1
                WHERE tenant_id = ?
                """,
                (mutation.tenant_id,),
            )
            return

        assert mutation.issuer_id is not None
        assert mutation.audience is not None
        assert mutation.key_id is not None
        assert mutation.key_epoch is not None
        assert mutation.public_key_hex is not None
        current_epoch = TrustedAuthorizationKeyStore._current_epoch_locked(
            connection,
            issuer_id=mutation.issuer_id,
            audience=mutation.audience,
        )
        if current_epoch is None:
            raise KeyError("authorization issuer trust not initialized")
        if mutation.key_epoch <= current_epoch:
            raise ValueError("authorization signing key epochs are monotonic")
        connection.execute(
            """
            INSERT INTO authorization_trusted_keys (
                issuer_id, audience, key_id, key_epoch, public_key_hex
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(issuer_id, audience,key_id) DO UPDATE SET
                key_epoch = excluded.key_epoch,
                public_key_hex = excluded.public_key_hex
            """,
            (
                mutation.issuer_id,
                mutation.audience,
                mutation.key_id,
                mutation.key_epoch,
                mutation.public_key_hex,
            ),
        )
        connection.execute(
            """
            UPDATE authorization_trusted_key_epochs
            SET current_key_epoch = ?
            WHERE issuer_id = ? AND audience = ?
            """,
            (mutation.key_epoch, mutation.issuer_id, mutation.audience),
        )

    def _apply_execution(self, change: ControlPlaneChange) -> ExecutionControlPlaneState:
        with self._execution_connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = self._execution_state_locked(connection, self.authority_id)
            if state is None:
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_STATE_NOT_INITIALIZED
                )
            if state.applied_generation == change.target_generation:
                if (
                    state.last_change_id != change.change_id
                    or state.last_mutation_sha256 != change.mutation_sha256
                ):
                    raise ControlPlaneConvergenceError(
                        ControlPlaneConvergenceReason.CHANGE_CONFLICT
                    )
                return state
            if state.applied_generation != change.from_generation:
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_GENERATION_MISMATCH
                )
            self._apply_mutation_locked(connection, change.mutation)
            connection.execute(
                """
                UPDATE execution_control_plane_state
                SET applied_generation = ?, last_change_id = ?, last_mutation_sha256 = ?
                WHERE authority_id = ?
                """,
                (
                    change.target_generation,
                    change.change_id,
                    change.mutation_sha256,
                    self.authority_id,
                ),
            )
        return self.execution_state()

    def _mark_applied(self, change_id: str) -> ControlPlaneChange:
        with self.generation_store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT authority_id, change_id, from_generation, target_generation,
                       mutation_sha256, mutation_json, status
                FROM control_plane_changes
                WHERE authority_id = ? AND change_id = ?
                """,
                (self.authority_id, change_id),
            ).fetchone()
            if row is None:
                raise KeyError("control-plane change not found")
            change = self._row_to_change(row)
            if change.status is ControlPlaneChangeStatus.ACTIVE:
                return change
            state = self.execution_state()
            if (
                state.applied_generation != change.target_generation
                or state.last_change_id != change.change_id
                or state.last_mutation_sha256 != change.mutation_sha256
            ):
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_GENERATION_MISMATCH
                )
            if change.status is ControlPlaneChangeStatus.PREPARED:
                connection.execute(
                    """
                    UPDATE control_plane_changes
                    SET status = 'applied'
                    WHERE authority_id = ? AND change_id = ? AND status = 'prepared'
                    """,
                    (self.authority_id, change_id),
                )
        return self.get_change(change_id)

    def apply(self, change_id: str) -> ControlPlaneChange:
        change = self.get_change(change_id)
        self._apply_execution(change)
        return self._mark_applied(change_id)

    def activate(self, change_id: str) -> ControlPlaneChange:
        with self.generation_store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT authority_id, change_id, from_generation, target_generation,
                       mutation_sha256, mutation_json, status
                FROM control_plane_changes
                WHERE authority_id = ? AND change_id = ?
                """,
                (self.authority_id, change_id),
            ).fetchone()
            if row is None:
                raise KeyError("control-plane change not found")
            change = self._row_to_change(row)
            current = ControlPlaneGenerationStore._read_locked(connection, self.authority_id)
            if change.status is ControlPlaneChangeStatus.ACTIVE:
                if current != change.target_generation:
                    raise ControlPlaneConvergenceError(
                        ControlPlaneConvergenceReason.EXECUTION_GENERATION_MISMATCH
                    )
                return change
            if change.status is not ControlPlaneChangeStatus.APPLIED:
                raise ControlPlaneConvergenceError(ControlPlaneConvergenceReason.CHANGE_PENDING)
            state = self.execution_state()
            if (
                state.applied_generation != change.target_generation
                or state.last_change_id != change.change_id
                or state.last_mutation_sha256 != change.mutation_sha256
            ):
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_GENERATION_MISMATCH
                )
            if current != change.from_generation:
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_GENERATION_MISMATCH
                )
            connection.execute(
                """
                UPDATE control_plane_generations
                SET current_generation = ?
                WHERE authority_id = ?
                """,
                (change.target_generation, self.authority_id),
            )
            connection.execute(
                """
                UPDATE control_plane_changes
                SET status = 'active'
                WHERE authority_id = ? AND change_id = ? AND status = 'applied'
                """,
                (self.authority_id, change_id),
            )
        return self.get_change(change_id)

    def commit(
        self,
        *,
        change_id: str,
        mutation: ControlPlaneMutation,
        crash_at: ControlPlaneCrashPoint | None = None,
    ) -> ControlPlaneChange:
        change = self.prepare(change_id=change_id, mutation=mutation)
        if crash_at is ControlPlaneCrashPoint.AFTER_PREPARE:
            raise SyntheticControlPlaneCrash(crash_at)
        self._apply_execution(change)
        if crash_at is ControlPlaneCrashPoint.AFTER_EXECUTION_APPLY:
            raise SyntheticControlPlaneCrash(crash_at)
        self._mark_applied(change_id)
        if crash_at is ControlPlaneCrashPoint.AFTER_MARK_APPLIED:
            raise SyntheticControlPlaneCrash(crash_at)
        return self.activate(change_id)

    def recover(self) -> ControlPlaneChange | None:
        change = self.pending_change()
        if change is None:
            self.current_active_generation()
            return None
        state = self.execution_state()
        if state.applied_generation == change.from_generation:
            self._apply_execution(change)
        elif state.applied_generation == change.target_generation:
            if (
                state.last_change_id != change.change_id
                or state.last_mutation_sha256 != change.mutation_sha256
            ):
                raise ControlPlaneConvergenceError(ControlPlaneConvergenceReason.CHANGE_CONFLICT)
        else:
            raise ControlPlaneConvergenceError(
                ControlPlaneConvergenceReason.EXECUTION_GENERATION_MISMATCH
            )
        self._mark_applied(change.change_id)
        return self.activate(change.change_id)

    @contextmanager
    def locked_active_generation(self) -> Iterator[int]:
        connection = self.generation_store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            pending = connection.execute(
                """
                SELECT 1 FROM control_plane_changes
                WHERE authority_id = ? AND status != 'active'
                LIMIT 1
                """,
                (self.authority_id,),
            ).fetchone()
            if pending is not None:
                raise ControlPlaneConvergenceError(ControlPlaneConvergenceReason.CHANGE_PENDING)
            current = ControlPlaneGenerationStore._read_locked(connection, self.authority_id)
            if current is None:
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_STATE_NOT_INITIALIZED
                )
            state = self.execution_state()
            if state.applied_generation != current:
                raise ControlPlaneConvergenceError(
                    ControlPlaneConvergenceReason.EXECUTION_GENERATION_MISMATCH
                )
            yield current
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def current_active_generation(self) -> int:
        with self.locked_active_generation() as generation:
            return generation


class RecoverableAnchoredAuthorizationReplica:
    """Issues evidence only from a converged active control-plane generation."""

    def __init__(
        self,
        *,
        authorization_replica: CachedAuthorizationReplica,
        signer: AnchoredAuthorizationSigner,
        coordinator: CrashSafeControlPlaneCoordinator,
    ) -> None:
        self.authorization_replica = authorization_replica
        self.signer = signer
        self.coordinator = coordinator

    def evaluate(self, record: EffectOutboxRecord) -> AnchoredAuthorizationDecision:
        generation = self.coordinator.current_active_generation()
        decision = self.authorization_replica.evaluate(record)
        return self.signer.issue(decision, control_plane_generation=generation)


class CrashSafeRollbackResistantSyntheticEffectService(RollbackResistantSyntheticEffectService):
    """P2-P provenance plus P2-Q journal/execution-generation convergence fencing."""

    def __init__(
        self,
        database_path: Path,
        *,
        authoritative_versions,
        trusted_keys: TrustedAuthorizationKeyStore,
        coordinator: CrashSafeControlPlaneCoordinator,
        expected_issuer_id: str,
        expected_audience: str,
        clock=None,
    ) -> None:
        database_path = Path(database_path)
        if database_path.resolve() != coordinator.execution_database_path.resolve():
            raise ValueError("control-plane execution marker must share the effect database")
        self.coordinator = coordinator
        super().__init__(
            database_path,
            authoritative_versions=authoritative_versions,
            trusted_keys=trusted_keys,
            generation_store=coordinator.generation_store,
            authority_id=coordinator.authority_id,
            expected_issuer_id=expected_issuer_id,
            expected_audience=expected_audience,
            clock=clock,
        )

    def execute_with_anchored_decision(
        self,
        record: EffectOutboxRecord,
        envelope: AnchoredAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        with self.coordinator.locked_active_generation() as current_generation:
            if envelope.payload.control_plane_generation != current_generation:
                raise RollbackAnchorError(
                    RollbackAnchorReason.CONTROL_PLANE_GENERATION_MISMATCH
                )
            self._verify_envelope_signature(envelope)
            return ProvenanceFencedSyntheticEffectService.execute_with_decision(
                self,
                record,
                envelope.payload.decision,
            )


class CrashSafeControlPlaneDurableEffectWorker:
    """At-least-once worker that retries transient P2-Q convergence failures."""

    def __init__(
        self,
        *,
        outbox_store: RevalidatingEffectOutboxStore,
        effect_service: CrashSafeRollbackResistantSyntheticEffectService,
        authorization_replica: RecoverableAnchoredAuthorizationReplica,
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
        except ControlPlaneConvergenceError:
            # A pending/recoverable control-plane transition is fail-closed but not
            # a permanent authorization denial. Keep the bound outbox retryable.
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
