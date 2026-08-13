from __future__ import annotations

import json
import sqlite3
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.approvals.models import (
    ApprovalAction,
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStatus,
)
from aegis.approvals.store import (
    ApprovalAuthorizationError,
    ApprovalNotFoundError,
    ApprovalStateError,
    ApprovalStore,
    _binding_hash,
    _canonicalize,
    _utc_now,
)
from aegis.identity.models import Principal, Role


class WorkflowStatus(str):
    PENDING = "pending"
    COMPLETED = "completed"


@dataclass(frozen=True)
class ApprovalWorkflowContext:
    thread_id: str
    trace_id: str
    tool_calls: int


_WORKFLOW_CONTEXT: ContextVar[ApprovalWorkflowContext | None] = ContextVar(
    "aegis_approval_workflow_context", default=None
)


def bind_approval_workflow_context(
    context: ApprovalWorkflowContext,
) -> Token[ApprovalWorkflowContext | None]:
    return _WORKFLOW_CONTEXT.set(context)


def reset_approval_workflow_context(
    token: Token[ApprovalWorkflowContext | None],
) -> None:
    _WORKFLOW_CONTEXT.reset(token)


class DurableWorkflowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str
    thread_id: str
    trace_id: str
    requester_user_id: str
    tenant_id: str
    requester_roles: frozenset[Role]
    action: ApprovalAction
    arguments: dict[str, Any]
    tool_calls: int
    status: str
    final_outcome: str | None = None
    created_at: datetime
    completed_at: datetime | None = None

    @property
    def requester(self) -> Principal:
        return Principal(
            user_id=self.requester_user_id,
            tenant_id=self.tenant_id,
            roles=self.requester_roles,
        )


class DurableApprovalStore(ApprovalStore):
    """SQLite-backed approval ledger with atomic, restart-safe state transitions.

    The approval binding remains requester/tenant/action/argument/nonce-specific. If an
    agent workflow context is bound, the pending workflow journal row is inserted in the
    same SQLite transaction as the approval record.
    """

    def __init__(
        self,
        database_path: Path,
        *,
        ttl: timedelta = timedelta(minutes=10),
        clock=_utc_now,
    ) -> None:
        super().__init__(ttl=ttl, clock=clock)
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._setup()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _setup(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_records (
                    approval_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    requester_user_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    normalized_arguments_json TEXT NOT NULL,
                    binding_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approver_user_id TEXT,
                    decided_at TEXT,
                    consumed_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_workflows (
                    approval_id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL UNIQUE,
                    trace_id TEXT NOT NULL,
                    requester_user_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    requester_roles_json TEXT NOT NULL,
                    action TEXT NOT NULL,
                    normalized_arguments_json TEXT NOT NULL,
                    tool_calls INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    final_outcome TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY (approval_id) REFERENCES approval_records(approval_id)
                )
                """
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=str(row["approval_id"]),
            nonce=str(row["nonce"]),
            requester_user_id=str(row["requester_user_id"]),
            tenant_id=str(row["tenant_id"]),
            action=ApprovalAction(str(row["action"])),
            normalized_arguments_json=str(row["normalized_arguments_json"]),
            binding_hash=str(row["binding_hash"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            expires_at=datetime.fromisoformat(str(row["expires_at"])),
            status=ApprovalStatus(str(row["status"])),
            approver_user_id=(
                str(row["approver_user_id"])
                if row["approver_user_id"] is not None
                else None
            ),
            decided_at=(
                datetime.fromisoformat(str(row["decided_at"]))
                if row["decided_at"] is not None
                else None
            ),
            consumed_at=(
                datetime.fromisoformat(str(row["consumed_at"]))
                if row["consumed_at"] is not None
                else None
            ),
        )

    def _load_locked(
        self, connection: sqlite3.Connection, approval_id: str
    ) -> ApprovalRecord:
        row = connection.execute(
            "SELECT * FROM approval_records WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            raise ApprovalNotFoundError("approval not found")
        record = self._row_to_record(row)
        if record.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            if self._clock() >= record.expires_at:
                connection.execute(
                    "UPDATE approval_records SET status = ? WHERE approval_id = ?",
                    (ApprovalStatus.EXPIRED.value, approval_id),
                )
                record = record.model_copy(update={"status": ApprovalStatus.EXPIRED})
        return record

    def create(
        self,
        *,
        requester: Principal,
        action: ApprovalAction,
        arguments: dict[str, Any],
    ) -> ApprovalRecord:
        import secrets

        now = self._clock()
        approval_id = f"apr_{secrets.token_urlsafe(18)}"
        nonce = secrets.token_urlsafe(24)
        normalized = _canonicalize(arguments)
        record = ApprovalRecord(
            approval_id=approval_id,
            nonce=nonce,
            requester_user_id=requester.user_id,
            tenant_id=requester.tenant_id,
            action=action,
            normalized_arguments_json=normalized,
            binding_hash=_binding_hash(
                nonce=nonce,
                requester_user_id=requester.user_id,
                tenant_id=requester.tenant_id,
                action=action,
                normalized_arguments_json=normalized,
            ),
            created_at=now,
            expires_at=now + self._ttl,
            status=ApprovalStatus.PENDING,
        )
        workflow = _WORKFLOW_CONTEXT.get()

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO approval_records (
                    approval_id, nonce, requester_user_id, tenant_id, action,
                    normalized_arguments_json, binding_hash, created_at, expires_at,
                    status, approver_user_id, decided_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (
                    record.approval_id,
                    record.nonce,
                    record.requester_user_id,
                    record.tenant_id,
                    record.action.value,
                    record.normalized_arguments_json,
                    record.binding_hash,
                    record.created_at.isoformat(),
                    record.expires_at.isoformat(),
                    record.status.value,
                ),
            )
            if workflow is not None:
                connection.execute(
                    """
                    INSERT INTO approval_workflows (
                        approval_id, thread_id, trace_id, requester_user_id, tenant_id,
                        requester_roles_json, action, normalized_arguments_json,
                        tool_calls, status, final_outcome, created_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)
                    """,
                    (
                        record.approval_id,
                        workflow.thread_id,
                        workflow.trace_id,
                        requester.user_id,
                        requester.tenant_id,
                        json.dumps(sorted(role.value for role in requester.roles)),
                        action.value,
                        normalized,
                        workflow.tool_calls,
                        WorkflowStatus.PENDING,
                        now.isoformat(),
                    ),
                )
        return record

    def get(self, approval_id: str) -> ApprovalRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._load_locked(connection, approval_id)

    def decide(
        self,
        *,
        approval_id: str,
        approver: Principal,
        decision: ApprovalDecision,
    ) -> ApprovalRecord:
        desired_status = (
            ApprovalStatus.APPROVED
            if decision is ApprovalDecision.APPROVE
            else ApprovalStatus.REJECTED
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._load_locked(connection, approval_id)
            if Role.ADMIN_APPROVER not in approver.roles:
                raise ApprovalAuthorizationError("principal is not an approver")
            if approver.tenant_id != record.tenant_id:
                raise ApprovalAuthorizationError("cross-tenant approval is forbidden")
            if approver.user_id == record.requester_user_id:
                raise ApprovalAuthorizationError("self-approval is forbidden")

            if record.status is ApprovalStatus.PENDING:
                now = self._clock()
                connection.execute(
                    """
                    UPDATE approval_records
                    SET status = ?, approver_user_id = ?, decided_at = ?
                    WHERE approval_id = ? AND status = ?
                    """,
                    (
                        desired_status.value,
                        approver.user_id,
                        now.isoformat(),
                        approval_id,
                        ApprovalStatus.PENDING.value,
                    ),
                )
                return record.model_copy(
                    update={
                        "status": desired_status,
                        "approver_user_id": approver.user_id,
                        "decided_at": now,
                    }
                )

            same_recovery_decision = (
                record.approver_user_id == approver.user_id
                and (
                    record.status is desired_status
                    or (
                        record.status is ApprovalStatus.CONSUMED
                        and desired_status is ApprovalStatus.APPROVED
                    )
                )
            )
            if same_recovery_decision:
                return record
            raise ApprovalStateError("approval is not pending")

    def resolve_after_review(
        self,
        *,
        approval_id: str,
        requester: Principal,
        action: ApprovalAction,
        arguments: dict[str, Any],
    ) -> ApprovalRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._load_locked(connection, approval_id)
            self._verify_binding(
                record=record,
                requester=requester,
                action=action,
                arguments=arguments,
            )
            if record.status is ApprovalStatus.REJECTED:
                return record
            if record.status is ApprovalStatus.CONSUMED:
                return record
            if record.status is not ApprovalStatus.APPROVED:
                raise ApprovalStateError("approval is not ready for consumption")

            now = self._clock()
            connection.execute(
                """
                UPDATE approval_records
                SET status = ?, consumed_at = ?
                WHERE approval_id = ? AND status = ?
                """,
                (
                    ApprovalStatus.CONSUMED.value,
                    now.isoformat(),
                    approval_id,
                    ApprovalStatus.APPROVED.value,
                ),
            )
            return record.model_copy(
                update={"status": ApprovalStatus.CONSUMED, "consumed_at": now}
            )

    def consume(
        self,
        *,
        approval_id: str,
        requester: Principal,
        action: ApprovalAction,
        arguments: dict[str, Any],
    ) -> ApprovalRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._load_locked(connection, approval_id)
            self._verify_binding(
                record=record,
                requester=requester,
                action=action,
                arguments=arguments,
            )
            if record.status is ApprovalStatus.CONSUMED:
                return record
            if record.status is not ApprovalStatus.APPROVED:
                raise ApprovalStateError("approval is not approved")
            now = self._clock()
            connection.execute(
                """
                UPDATE approval_records
                SET status = ?, consumed_at = ?
                WHERE approval_id = ? AND status = ?
                """,
                (
                    ApprovalStatus.CONSUMED.value,
                    now.isoformat(),
                    approval_id,
                    ApprovalStatus.APPROVED.value,
                ),
            )
            return record.model_copy(
                update={"status": ApprovalStatus.CONSUMED, "consumed_at": now}
            )


class DurableWorkflowStore:
    """SQLite workflow journal used as the restart-safe source of resume context."""

    def __init__(self, database_path: Path, *, clock=_utc_now) -> None:
        self.database_path = Path(database_path)
        self._clock = clock
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        # DurableApprovalStore owns schema creation. Constructing it is cheap and keeps
        # the workflow store safe when tests instantiate this class first.
        DurableApprovalStore(self.database_path, clock=clock)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> DurableWorkflowRecord:
        return DurableWorkflowRecord(
            approval_id=str(row["approval_id"]),
            thread_id=str(row["thread_id"]),
            trace_id=str(row["trace_id"]),
            requester_user_id=str(row["requester_user_id"]),
            tenant_id=str(row["tenant_id"]),
            requester_roles=frozenset(
                Role(value) for value in json.loads(str(row["requester_roles_json"]))
            ),
            action=ApprovalAction(str(row["action"])),
            arguments=json.loads(str(row["normalized_arguments_json"])),
            tool_calls=int(row["tool_calls"]),
            status=str(row["status"]),
            final_outcome=(
                str(row["final_outcome"])
                if row["final_outcome"] is not None
                else None
            ),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            completed_at=(
                datetime.fromisoformat(str(row["completed_at"]))
                if row["completed_at"] is not None
                else None
            ),
        )

    def get(self, approval_id: str) -> DurableWorkflowRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM approval_workflows WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise ApprovalStateError("no durable workflow for approval")
        return self._row_to_record(row)

    def require_pending(self, approval_id: str) -> DurableWorkflowRecord:
        record = self.get(approval_id)
        if record.status != WorkflowStatus.PENDING:
            raise ApprovalStateError("approval workflow is already completed")
        return record

    def complete(self, *, approval_id: str, outcome: str) -> DurableWorkflowRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM approval_workflows WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise ApprovalStateError("no durable workflow for approval")
            record = self._row_to_record(row)
            if record.status != WorkflowStatus.PENDING:
                raise ApprovalStateError("approval workflow is already completed")
            completed_at = self._clock()
            connection.execute(
                """
                UPDATE approval_workflows
                SET status = ?, final_outcome = ?, completed_at = ?
                WHERE approval_id = ? AND status = ?
                """,
                (
                    WorkflowStatus.COMPLETED,
                    outcome,
                    completed_at.isoformat(),
                    approval_id,
                    WorkflowStatus.PENDING,
                ),
            )
            return record.model_copy(
                update={
                    "status": WorkflowStatus.COMPLETED,
                    "final_outcome": outcome,
                    "completed_at": completed_at,
                }
            )
