from __future__ import annotations

import hashlib
import sqlite3
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aegis.effects.durable import (
    EffectBindingError,
    EffectOutboxRecord,
    SyntheticEffectExecution,
    SyntheticIdempotentEffectService,
    SyntheticWorkerCrash,
)
from aegis.effects.revalidation import (
    ExecutionAuthorizationReason,
    RevalidatingEffectOutboxStore,
    SyntheticAuthorizationStateStore,
)


class AuthorizationFreshnessReason(StrEnum):
    OUTBOX_CANCELLED = "outbox_cancelled"
    DECISION_BINDING_MISMATCH = "decision_binding_mismatch"
    TENANT_BINDING_MISMATCH = "tenant_binding_mismatch"
    AUTHORITATIVE_VERSION_NOT_FOUND = "authoritative_version_not_found"
    REVOCATION_EPOCH_MISMATCH = "revocation_epoch_mismatch"
    POLICY_VERSION_MISMATCH = "policy_version_mismatch"
    CACHED_AUTHORIZATION_DENIED = "cached_authorization_denied"


class AuthorizationFreshnessError(RuntimeError):
    """Fail-closed stale-authorization failure with a non-sensitive reason code."""

    def __init__(self, reason: AuthorizationFreshnessReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class AuthorizationVersionState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    policy_version: int = Field(ge=1)
    revocation_epoch: int = Field(ge=1)


class CachedAuthorizationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    record_binding_hash: str
    policy_version: int = Field(ge=1)
    revocation_epoch: int = Field(ge=1)
    reason: ExecutionAuthorizationReason


def authorization_record_binding(record: EffectOutboxRecord) -> str:
    material = "\x1f".join(
        (
            "aegisdesk-p2n-authorization-evidence-v1",
            record.approval_id,
            record.idempotency_key,
            record.requester_user_id,
            record.tenant_id,
            record.action.value,
            record.normalized_arguments_json,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuthorizationVersionStore:
    """Server-owned monotonic authorization versions for one local synthetic node."""

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
                CREATE TABLE IF NOT EXISTS authorization_versions (
                    tenant_id TEXT PRIMARY KEY,
                    policy_version INTEGER NOT NULL CHECK (policy_version >= 1),
                    revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 1)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authorization_freshness_denials (
                    approval_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    denied_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _row_to_state(row: sqlite3.Row) -> AuthorizationVersionState:
        return AuthorizationVersionState(
            tenant_id=str(row["tenant_id"]),
            policy_version=int(row["policy_version"]),
            revocation_epoch=int(row["revocation_epoch"]),
        )

    @classmethod
    def _read_locked(
        cls,
        connection: sqlite3.Connection,
        tenant_id: str,
    ) -> AuthorizationVersionState | None:
        row = connection.execute(
            """
            SELECT tenant_id, policy_version, revocation_epoch
            FROM authorization_versions
            WHERE tenant_id = ?
            """,
            (tenant_id,),
        ).fetchone()
        return None if row is None else cls._row_to_state(row)

    def get(self, tenant_id: str) -> AuthorizationVersionState:
        with self._connect() as connection:
            state = self._read_locked(connection, tenant_id)
        if state is None:
            raise KeyError("synthetic authorization version not found")
        return state

    def ensure(
        self,
        *,
        tenant_id: str,
        policy_version: int,
        revocation_epoch: int,
    ) -> AuthorizationVersionState:
        desired = AuthorizationVersionState(
            tenant_id=tenant_id,
            policy_version=policy_version,
            revocation_epoch=revocation_epoch,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO authorization_versions (
                    tenant_id, policy_version, revocation_epoch
                ) VALUES (?, ?, ?)
                """,
                (tenant_id, policy_version, revocation_epoch),
            )
        return self.get(desired.tenant_id)

    def set_version(
        self,
        *,
        tenant_id: str,
        policy_version: int,
        revocation_epoch: int,
    ) -> AuthorizationVersionState:
        desired = AuthorizationVersionState(
            tenant_id=tenant_id,
            policy_version=policy_version,
            revocation_epoch=revocation_epoch,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, tenant_id)
            if current is not None and (
                desired.policy_version < current.policy_version
                or desired.revocation_epoch < current.revocation_epoch
            ):
                raise ValueError("authorization versions are monotonic")
            connection.execute(
                """
                INSERT INTO authorization_versions (
                    tenant_id, policy_version, revocation_epoch
                ) VALUES (?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    policy_version = excluded.policy_version,
                    revocation_epoch = excluded.revocation_epoch
                """,
                (tenant_id, policy_version, revocation_epoch),
            )
        return self.get(tenant_id)

    def advance_revocation_epoch(self, tenant_id: str) -> AuthorizationVersionState:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, tenant_id)
            if current is None:
                raise KeyError("synthetic authorization version not found")
            connection.execute(
                """
                UPDATE authorization_versions
                SET revocation_epoch = revocation_epoch + 1
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            )
        return self.get(tenant_id)

    def advance_policy_version(self, tenant_id: str) -> AuthorizationVersionState:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._read_locked(connection, tenant_id)
            if current is None:
                raise KeyError("synthetic authorization version not found")
            connection.execute(
                """
                UPDATE authorization_versions
                SET policy_version = policy_version + 1
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            )
        return self.get(tenant_id)


class VersionedAuthorizationController:
    """Applies authoritative synthetic security mutations with their version fence."""

    def __init__(
        self,
        *,
        authorization_store: SyntheticAuthorizationStateStore,
        version_store: AuthorizationVersionStore,
    ) -> None:
        if authorization_store.database_path != version_store.database_path:
            raise ValueError("authorization state and version store must share one SQLite database")
        self.authorization_store = authorization_store
        self.version_store = version_store

    def set_subject_active(self, user_id: str, active: bool) -> AuthorizationVersionState:
        with self.version_store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT tenant_id
                FROM current_subject_authorization
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            if row is None:
                raise KeyError("synthetic subject not found")
            tenant_id = str(row["tenant_id"])
            current = self.version_store._read_locked(connection, tenant_id)
            if current is None:
                raise KeyError("synthetic authorization version not found")
            connection.execute(
                """
                UPDATE current_subject_authorization
                SET active = ?
                WHERE user_id = ?
                """,
                (int(active), user_id),
            )
            connection.execute(
                """
                UPDATE authorization_versions
                SET revocation_epoch = revocation_epoch + 1
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            )
        return self.version_store.get(tenant_id)

    def set_resource_owner(
        self,
        *,
        tenant_id: str,
        resource: str,
        owner_user_id: str | None,
    ) -> AuthorizationVersionState:
        with self.version_store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self.version_store._read_locked(connection, tenant_id)
            if current is None:
                raise KeyError("synthetic authorization version not found")
            cursor = connection.execute(
                """
                UPDATE current_resource_authorization
                SET owner_user_id = ?
                WHERE tenant_id = ? AND resource = ?
                """,
                (owner_user_id, tenant_id, resource),
            )
            if cursor.rowcount != 1:
                raise KeyError("synthetic resource not found")
            connection.execute(
                """
                UPDATE authorization_versions
                SET revocation_epoch = revocation_epoch + 1
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            )
        return self.version_store.get(tenant_id)

    def set_password_reset_enabled(
        self,
        tenant_id: str,
        enabled: bool,
    ) -> AuthorizationVersionState:
        with self.version_store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self.version_store._read_locked(connection, tenant_id)
            if current is None:
                raise KeyError("synthetic authorization version not found")
            connection.execute(
                """
                INSERT INTO current_tenant_policy (
                    tenant_id, password_reset_enabled
                ) VALUES (?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    password_reset_enabled = excluded.password_reset_enabled
                """,
                (tenant_id, int(enabled)),
            )
            connection.execute(
                """
                UPDATE authorization_versions
                SET policy_version = policy_version + 1
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            )
        return self.version_store.get(tenant_id)


class CachedAuthorizationReplica:
    """A separate local replica that may intentionally lag the authoritative node."""

    def __init__(
        self,
        *,
        authorization_store: SyntheticAuthorizationStateStore,
        version_store: AuthorizationVersionStore,
    ) -> None:
        if authorization_store.database_path != version_store.database_path:
            raise ValueError("replica authorization state and versions must share one SQLite database")
        self.authorization_store = authorization_store
        self.version_store = version_store

    def evaluate(self, record: EffectOutboxRecord) -> CachedAuthorizationDecision:
        version = self.version_store.get(record.tenant_id)
        return CachedAuthorizationDecision(
            tenant_id=record.tenant_id,
            record_binding_hash=authorization_record_binding(record),
            policy_version=version.policy_version,
            revocation_epoch=version.revocation_epoch,
            reason=self.authorization_store.evaluate(record),
        )


class VersionFencedSyntheticEffectService(SyntheticIdempotentEffectService):
    """Consumes cached authorization only when its version matches authoritative state."""

    def __init__(
        self,
        database_path: Path,
        *,
        authoritative_versions: AuthorizationVersionStore,
        clock=None,
    ) -> None:
        database_path = Path(database_path)
        if authoritative_versions.database_path != database_path:
            raise ValueError("authoritative versions and effect ledger must share one SQLite database")
        self.authoritative_versions = authoritative_versions
        if clock is None:
            super().__init__(database_path)
        else:
            super().__init__(database_path, clock=clock)
        self.authoritative_versions._setup()

    @staticmethod
    def _decision_failure(
        connection: sqlite3.Connection,
        *,
        record: EffectOutboxRecord,
        decision: CachedAuthorizationDecision,
    ) -> AuthorizationFreshnessReason | None:
        if decision.tenant_id != record.tenant_id:
            return AuthorizationFreshnessReason.TENANT_BINDING_MISMATCH
        if decision.record_binding_hash != authorization_record_binding(record):
            return AuthorizationFreshnessReason.DECISION_BINDING_MISMATCH

        authoritative = AuthorizationVersionStore._read_locked(
            connection,
            record.tenant_id,
        )
        if authoritative is None:
            return AuthorizationFreshnessReason.AUTHORITATIVE_VERSION_NOT_FOUND
        if decision.revocation_epoch != authoritative.revocation_epoch:
            return AuthorizationFreshnessReason.REVOCATION_EPOCH_MISMATCH
        if decision.policy_version != authoritative.policy_version:
            return AuthorizationFreshnessReason.POLICY_VERSION_MISMATCH
        if decision.reason is not ExecutionAuthorizationReason.ALLOWED:
            return AuthorizationFreshnessReason.CACHED_AUTHORIZATION_DENIED
        return None

    def execute_with_decision(
        self,
        record: EffectOutboxRecord,
        decision: CachedAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        denial_reason: AuthorizationFreshnessReason | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")

            existing = connection.execute(
                """
                SELECT * FROM synthetic_effect_ledger
                WHERE idempotency_key = ?
                """,
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
                """
                SELECT * FROM synthetic_effect_ledger
                WHERE approval_id = ?
                """,
                (record.approval_id,),
            ).fetchone()
            if conflicting is not None:
                raise EffectBindingError("approval already mapped to another idempotency key")

            durable_denial = connection.execute(
                """
                SELECT idempotency_key, reason
                FROM authorization_freshness_denials
                WHERE approval_id = ?
                """,
                (record.approval_id,),
            ).fetchone()
            if durable_denial is not None:
                if str(durable_denial["idempotency_key"]) != record.idempotency_key:
                    raise EffectBindingError("authorization freshness denial binding mismatch")
                denial_reason = AuthorizationFreshnessReason(str(durable_denial["reason"]))
            else:
                denial_reason = self._decision_failure(
                    connection,
                    record=record,
                    decision=decision,
                )
                if denial_reason is not None:
                    connection.execute(
                        """
                        INSERT INTO authorization_freshness_denials (
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
        raise AuthorizationFreshnessError(denial_reason)


class VersionFencedDurableEffectWorker:
    """At-least-once worker that fences stale cached authorization evidence."""

    def __init__(
        self,
        *,
        outbox_store: RevalidatingEffectOutboxStore,
        effect_service: VersionFencedSyntheticEffectService,
        authorization_replica: CachedAuthorizationReplica,
        crash_after_effect_once: bool = False,
    ) -> None:
        self._outbox_store = outbox_store
        self._effect_service = effect_service
        self._authorization_replica = authorization_replica
        self._crash_after_effect_once = crash_after_effect_once

    def deliver(self, approval_id: str) -> SyntheticEffectExecution:
        current = self._outbox_store.get(approval_id)
        if current.status == "cancelled":
            raise AuthorizationFreshnessError(AuthorizationFreshnessReason.OUTBOX_CANCELLED)

        record = self._outbox_store.begin_delivery(approval_id)
        decision = self._authorization_replica.evaluate(record)
        try:
            execution = self._effect_service.execute_with_decision(record, decision)
        except AuthorizationFreshnessError:
            self._outbox_store.cancel(
                approval_id=approval_id,
                idempotency_key=record.idempotency_key,
            )
            raise

        if self._crash_after_effect_once:
            self._crash_after_effect_once = False
            raise SyntheticWorkerCrash(
                "synthetic crash after effect before outbox acknowledgement"
            )

        self._outbox_store.complete(
            approval_id=approval_id,
            idempotency_key=record.idempotency_key,
        )
        return execution
