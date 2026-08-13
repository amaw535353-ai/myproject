from __future__ import annotations

import json
import sqlite3
from enum import StrEnum
from pathlib import Path

from aegis.approvals.models import ApprovalAction
from aegis.approvals.store import ApprovalAuthorizationError, ApprovalStateError
from aegis.effects.durable import (
    DurableEffectOutboxStore,
    DurableEffectWorker,
    EffectBindingError,
    EffectOutboxRecord,
    SyntheticEffectExecution,
    SyntheticIdempotentEffectService,
)
from aegis.identity.models import Role


class ExecutionAuthorizationReason(StrEnum):
    ALLOWED = "allowed"
    SUBJECT_NOT_FOUND = "subject_not_found"
    SUBJECT_INACTIVE = "subject_inactive"
    TENANT_MEMBERSHIP_CHANGED = "tenant_membership_changed"
    REQUIRED_ROLE_MISSING = "required_role_missing"
    RESOURCE_NOT_FOUND = "resource_not_found"
    RESOURCE_DISABLED = "resource_disabled"
    RESOURCE_OWNER_MISMATCH = "resource_owner_mismatch"
    PASSWORD_RESET_DISABLED = "password_reset_disabled"
    INVALID_BOUND_ARGUMENTS = "invalid_bound_arguments"
    OUTBOX_CANCELLED = "outbox_cancelled"


class ExecutionAuthorizationError(ApprovalAuthorizationError):
    """Fail-closed execution-time authorization failure with a non-sensitive reason code."""

    def __init__(self, reason: ExecutionAuthorizationReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def _roles_json(roles: frozenset[Role] | set[Role]) -> str:
    return json.dumps(sorted(role.value for role in roles), separators=(",", ":"))


class SyntheticAuthorizationStateStore:
    """Current server-owned authorization state for the local synthetic P2-M lab."""

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
                CREATE TABLE IF NOT EXISTS current_subject_authorization (
                    user_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    roles_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS current_resource_authorization (
                    tenant_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    owner_user_id TEXT,
                    required_role TEXT,
                    PRIMARY KEY (tenant_id, resource)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS current_tenant_policy (
                    tenant_id TEXT PRIMARY KEY,
                    password_reset_enabled INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_authorization_denials (
                    approval_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    denied_at TEXT NOT NULL
                )
                """
            )

    def ensure_subject(
        self,
        *,
        user_id: str,
        tenant_id: str,
        active: bool,
        roles: frozenset[Role] | set[Role],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO current_subject_authorization (
                    user_id, tenant_id, active, roles_json
                ) VALUES (?, ?, ?, ?)
                """,
                (user_id, tenant_id, int(active), _roles_json(roles)),
            )

    def set_subject(
        self,
        *,
        user_id: str,
        tenant_id: str,
        active: bool,
        roles: frozenset[Role] | set[Role],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO current_subject_authorization (
                    user_id, tenant_id, active, roles_json
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    active = excluded.active,
                    roles_json = excluded.roles_json
                """,
                (user_id, tenant_id, int(active), _roles_json(roles)),
            )

    def set_subject_active(self, user_id: str, active: bool) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE current_subject_authorization SET active = ? WHERE user_id = ?",
                (int(active), user_id),
            )
            if cursor.rowcount != 1:
                raise KeyError("synthetic subject not found")

    def set_subject_tenant(self, user_id: str, tenant_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE current_subject_authorization SET tenant_id = ? WHERE user_id = ?",
                (tenant_id, user_id),
            )
            if cursor.rowcount != 1:
                raise KeyError("synthetic subject not found")

    def set_subject_roles(
        self,
        user_id: str,
        roles: frozenset[Role] | set[Role],
    ) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE current_subject_authorization SET roles_json = ? WHERE user_id = ?",
                (_roles_json(roles), user_id),
            )
            if cursor.rowcount != 1:
                raise KeyError("synthetic subject not found")

    def ensure_resource(
        self,
        *,
        tenant_id: str,
        resource: str,
        enabled: bool,
        owner_user_id: str | None,
        required_role: Role | None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO current_resource_authorization (
                    tenant_id, resource, enabled, owner_user_id, required_role
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    resource,
                    int(enabled),
                    owner_user_id,
                    None if required_role is None else required_role.value,
                ),
            )

    def set_resource(
        self,
        *,
        tenant_id: str,
        resource: str,
        enabled: bool,
        owner_user_id: str | None,
        required_role: Role | None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO current_resource_authorization (
                    tenant_id, resource, enabled, owner_user_id, required_role
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, resource) DO UPDATE SET
                    enabled = excluded.enabled,
                    owner_user_id = excluded.owner_user_id,
                    required_role = excluded.required_role
                """,
                (
                    tenant_id,
                    resource,
                    int(enabled),
                    owner_user_id,
                    None if required_role is None else required_role.value,
                ),
            )

    def set_resource_enabled(self, tenant_id: str, resource: str, enabled: bool) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE current_resource_authorization
                SET enabled = ?
                WHERE tenant_id = ? AND resource = ?
                """,
                (int(enabled), tenant_id, resource),
            )
            if cursor.rowcount != 1:
                raise KeyError("synthetic resource not found")

    def set_resource_owner(
        self,
        tenant_id: str,
        resource: str,
        owner_user_id: str | None,
    ) -> None:
        with self._connect() as connection:
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

    def set_resource_required_role(
        self,
        tenant_id: str,
        resource: str,
        required_role: Role | None,
    ) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE current_resource_authorization
                SET required_role = ?
                WHERE tenant_id = ? AND resource = ?
                """,
                (
                    None if required_role is None else required_role.value,
                    tenant_id,
                    resource,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError("synthetic resource not found")

    def ensure_password_reset_policy(
        self,
        *,
        tenant_id: str,
        enabled: bool,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO current_tenant_policy (
                    tenant_id, password_reset_enabled
                ) VALUES (?, ?)
                """,
                (tenant_id, int(enabled)),
            )

    def set_password_reset_enabled(self, tenant_id: str, enabled: bool) -> None:
        with self._connect() as connection:
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

    @staticmethod
    def _decode_roles(raw: str) -> set[str]:
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return set()
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            return set()
        return set(value)

    @staticmethod
    def _bound_arguments(record: EffectOutboxRecord) -> dict[str, object] | None:
        try:
            value = json.loads(record.normalized_arguments_json)
        except (json.JSONDecodeError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    @classmethod
    def _authorization_reason(
        cls,
        connection: sqlite3.Connection,
        record: EffectOutboxRecord,
    ) -> ExecutionAuthorizationReason:
        subject = connection.execute(
            """
            SELECT tenant_id, active, roles_json
            FROM current_subject_authorization
            WHERE user_id = ?
            """,
            (record.requester_user_id,),
        ).fetchone()
        if subject is None:
            return ExecutionAuthorizationReason.SUBJECT_NOT_FOUND
        if int(subject["active"]) != 1:
            return ExecutionAuthorizationReason.SUBJECT_INACTIVE
        if str(subject["tenant_id"]) != record.tenant_id:
            return ExecutionAuthorizationReason.TENANT_MEMBERSHIP_CHANGED

        roles = cls._decode_roles(str(subject["roles_json"]))
        arguments = cls._bound_arguments(record)
        if arguments is None:
            return ExecutionAuthorizationReason.INVALID_BOUND_ARGUMENTS

        if record.action is ApprovalAction.REQUEST_ACCESS:
            resource = arguments.get("resource")
            if not isinstance(resource, str) or not resource:
                return ExecutionAuthorizationReason.INVALID_BOUND_ARGUMENTS
            resource_row = connection.execute(
                """
                SELECT enabled, owner_user_id, required_role
                FROM current_resource_authorization
                WHERE tenant_id = ? AND resource = ?
                """,
                (record.tenant_id, resource),
            ).fetchone()
            if resource_row is None:
                return ExecutionAuthorizationReason.RESOURCE_NOT_FOUND
            if int(resource_row["enabled"]) != 1:
                return ExecutionAuthorizationReason.RESOURCE_DISABLED

            owner_user_id = resource_row["owner_user_id"]
            if owner_user_id is not None and str(owner_user_id) != record.requester_user_id:
                return ExecutionAuthorizationReason.RESOURCE_OWNER_MISMATCH

            required_role = resource_row["required_role"]
            if required_role is not None and str(required_role) not in roles:
                return ExecutionAuthorizationReason.REQUIRED_ROLE_MISSING
            return ExecutionAuthorizationReason.ALLOWED

        if record.action is ApprovalAction.REQUEST_PASSWORD_RESET:
            policy = connection.execute(
                """
                SELECT password_reset_enabled
                FROM current_tenant_policy
                WHERE tenant_id = ?
                """,
                (record.tenant_id,),
            ).fetchone()
            if policy is None or int(policy["password_reset_enabled"]) != 1:
                return ExecutionAuthorizationReason.PASSWORD_RESET_DISABLED
            return ExecutionAuthorizationReason.ALLOWED

        return ExecutionAuthorizationReason.INVALID_BOUND_ARGUMENTS

    def evaluate(self, record: EffectOutboxRecord) -> ExecutionAuthorizationReason:
        with self._connect() as connection:
            return self._authorization_reason(connection, record)


class SyntheticRevalidatingEffectService(SyntheticIdempotentEffectService):
    """Idempotent synthetic downstream with atomic execution-time authorization."""

    def __init__(
        self,
        database_path: Path,
        *,
        authorization_store: SyntheticAuthorizationStateStore,
        clock=None,
    ) -> None:
        database_path = Path(database_path)
        if authorization_store.database_path != database_path:
            raise ValueError("authorization state and effect ledger must share one SQLite database")
        self.authorization_store = authorization_store
        if clock is None:
            super().__init__(database_path)
        else:
            super().__init__(database_path, clock=clock)
        self.authorization_store._setup()

    def execute(self, record: EffectOutboxRecord) -> SyntheticEffectExecution:
        denial_reason: ExecutionAuthorizationReason | None = None
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
                FROM execution_authorization_denials
                WHERE approval_id = ?
                """,
                (record.approval_id,),
            ).fetchone()
            if durable_denial is not None:
                if str(durable_denial["idempotency_key"]) != record.idempotency_key:
                    raise EffectBindingError("authorization denial binding mismatch")
                denial_reason = ExecutionAuthorizationReason(str(durable_denial["reason"]))
            else:
                reason = self.authorization_store._authorization_reason(connection, record)
                if reason is not ExecutionAuthorizationReason.ALLOWED:
                    connection.execute(
                        """
                        INSERT INTO execution_authorization_denials (
                            approval_id, idempotency_key, reason, denied_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            record.approval_id,
                            record.idempotency_key,
                            reason.value,
                            self._clock().isoformat(),
                        ),
                    )
                    denial_reason = reason
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
        raise ExecutionAuthorizationError(denial_reason)


class RevalidatingEffectOutboxStore(DurableEffectOutboxStore):
    """Adds a terminal cancelled state for execution-time authorization denial."""

    def cancel(
        self,
        *,
        approval_id: str,
        idempotency_key: str,
    ) -> EffectOutboxRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM effect_outbox WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise ApprovalStateError("no effect outbox row for approval")
            current = EffectOutboxRecord(
                approval_id=str(row["approval_id"]),
                idempotency_key=str(row["idempotency_key"]),
                requester_user_id=str(row["requester_user_id"]),
                tenant_id=str(row["tenant_id"]),
                action=ApprovalAction(str(row["action"])),
                normalized_arguments_json=str(row["normalized_arguments_json"]),
                status=str(row["status"]),
                delivery_attempts=int(row["delivery_attempts"]),
                created_at=row["created_at"],
                completed_at=row["completed_at"],
            )
            if current.idempotency_key != idempotency_key:
                raise EffectBindingError("effect outbox idempotency key mismatch")
            if current.status == "completed":
                return current
            if current.status != "cancelled":
                connection.execute(
                    """
                    UPDATE effect_outbox
                    SET status = 'cancelled', completed_at = ?
                    WHERE approval_id = ? AND status != 'completed'
                    """,
                    (self._clock().isoformat(), approval_id),
                )
        return self.get(approval_id)


class RevalidatingDurableEffectWorker(DurableEffectWorker):
    """At-least-once worker that revalidates current authority before first effect."""

    def __init__(
        self,
        *,
        outbox_store: RevalidatingEffectOutboxStore,
        effect_service: SyntheticRevalidatingEffectService,
        crash_after_effect_once: bool = False,
    ) -> None:
        super().__init__(
            outbox_store=outbox_store,
            effect_service=effect_service,
            crash_after_effect_once=crash_after_effect_once,
        )
        self._outbox_store = outbox_store
        self._effect_service = effect_service

    def deliver(self, approval_id: str) -> SyntheticEffectExecution:
        current = self._outbox_store.get(approval_id)
        if current.status == "cancelled":
            raise ExecutionAuthorizationError(ExecutionAuthorizationReason.OUTBOX_CANCELLED)

        record = self._outbox_store.begin_delivery(approval_id)
        try:
            execution = self._effect_service.execute(record)
        except ExecutionAuthorizationError:
            self._outbox_store.cancel(
                approval_id=approval_id,
                idempotency_key=record.idempotency_key,
            )
            raise

        if self._crash_after_effect_once:
            self._crash_after_effect_once = False
            from aegis.effects.durable import SyntheticWorkerCrash

            raise SyntheticWorkerCrash(
                "synthetic crash after effect before outbox acknowledgement"
            )

        self._outbox_store.complete(
            approval_id=approval_id,
            idempotency_key=record.idempotency_key,
        )
        return execution
