from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.approvals.durable import DurableApprovalStore
from aegis.approvals.models import ApprovalAction, ApprovalRecord, ApprovalStatus
from aegis.approvals.store import ApprovalStateError
from aegis.identity.models import Principal


class EffectBindingError(RuntimeError):
    """Raised when a duplicate effect delivery disagrees with the bound payload."""


class SyntheticWorkerCrash(RuntimeError):
    """Synthetic fault used only by local tests/evaluations."""


class EffectOutboxRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str
    idempotency_key: str
    requester_user_id: str
    tenant_id: str
    action: ApprovalAction
    normalized_arguments_json: str
    status: str
    delivery_attempts: int
    created_at: datetime
    completed_at: datetime | None = None


class SyntheticEffectExecution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    effect_ref: str
    approval_id: str
    action: ApprovalAction
    duplicate_suppressed: bool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _idempotency_key(record: ApprovalRecord) -> str:
    material = "\x1f".join(
        (
            "aegisdesk-p2l-v1",
            record.approval_id,
            record.binding_hash,
            record.requester_user_id,
            record.tenant_id,
            record.action.value,
            record.normalized_arguments_json,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _setup_outbox(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(database_path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS effect_outbox (
                approval_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                requester_user_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                normalized_arguments_json TEXT NOT NULL,
                status TEXT NOT NULL,
                delivery_attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (approval_id) REFERENCES approval_records(approval_id)
            )
            """
        )


def _row_to_outbox(row: sqlite3.Row) -> EffectOutboxRecord:
    return EffectOutboxRecord(
        approval_id=str(row["approval_id"]),
        idempotency_key=str(row["idempotency_key"]),
        requester_user_id=str(row["requester_user_id"]),
        tenant_id=str(row["tenant_id"]),
        action=ApprovalAction(str(row["action"])),
        normalized_arguments_json=str(row["normalized_arguments_json"]),
        status=str(row["status"]),
        delivery_attempts=int(row["delivery_attempts"]),
        created_at=datetime.fromisoformat(str(row["created_at"])),
        completed_at=(
            datetime.fromisoformat(str(row["completed_at"]))
            if row["completed_at"] is not None
            else None
        ),
    )


def _insert_or_validate_outbox(
    connection: sqlite3.Connection,
    *,
    record: ApprovalRecord,
    created_at: datetime,
) -> EffectOutboxRecord:
    key = _idempotency_key(record)
    connection.execute(
        """
        INSERT OR IGNORE INTO effect_outbox (
            approval_id, idempotency_key, requester_user_id, tenant_id, action,
            normalized_arguments_json, status, delivery_attempts, created_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, NULL)
        """,
        (
            record.approval_id,
            key,
            record.requester_user_id,
            record.tenant_id,
            record.action.value,
            record.normalized_arguments_json,
            created_at.isoformat(),
        ),
    )
    row = connection.execute(
        "SELECT * FROM effect_outbox WHERE approval_id = ?",
        (record.approval_id,),
    ).fetchone()
    if row is None:
        raise ApprovalStateError("effect outbox row was not created")
    outbox = _row_to_outbox(row)
    expected = (
        key,
        record.requester_user_id,
        record.tenant_id,
        record.action,
        record.normalized_arguments_json,
    )
    actual = (
        outbox.idempotency_key,
        outbox.requester_user_id,
        outbox.tenant_id,
        outbox.action,
        outbox.normalized_arguments_json,
    )
    if actual != expected:
        raise EffectBindingError("existing effect outbox binding mismatch")
    return outbox


class TransactionalEffectCoordinator:
    """Consumes an approved record and creates its outbox row in one SQLite transaction."""

    def __init__(self, approval_store: DurableApprovalStore) -> None:
        self._approval_store = approval_store
        self.database_path = approval_store.database_path
        _setup_outbox(self.database_path)

    def resolve_after_review_and_enqueue(
        self,
        *,
        approval_id: str,
        requester: Principal,
        action: ApprovalAction,
        arguments: dict[str, Any],
    ) -> ApprovalRecord:
        with self._approval_store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._approval_store._load_locked(connection, approval_id)
            self._approval_store._verify_binding(
                record=record,
                requester=requester,
                action=action,
                arguments=arguments,
            )

            if record.status is ApprovalStatus.REJECTED:
                return record

            if record.status is ApprovalStatus.CONSUMED:
                consumed = record
                created_at = record.consumed_at or self._approval_store._clock()
            elif record.status is ApprovalStatus.APPROVED:
                now = self._approval_store._clock()
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
                consumed = record.model_copy(
                    update={"status": ApprovalStatus.CONSUMED, "consumed_at": now}
                )
                created_at = now
            else:
                raise ApprovalStateError("approval is not ready for effect enqueue")

            _insert_or_validate_outbox(
                connection,
                record=consumed,
                created_at=created_at,
            )
            return consumed


class DurableEffectOutboxStore:
    def __init__(self, database_path: Path, *, clock=_utc_now) -> None:
        self.database_path = Path(database_path)
        self._clock = clock
        _setup_outbox(self.database_path)

    def _connect(self) -> sqlite3.Connection:
        return _connect(self.database_path)

    def get(self, approval_id: str) -> EffectOutboxRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM effect_outbox WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise ApprovalStateError("no effect outbox row for approval")
        return _row_to_outbox(row)

    def begin_delivery(self, approval_id: str) -> EffectOutboxRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM effect_outbox WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise ApprovalStateError("no effect outbox row for approval")
            connection.execute(
                """
                UPDATE effect_outbox
                SET delivery_attempts = delivery_attempts + 1
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            refreshed = connection.execute(
                "SELECT * FROM effect_outbox WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        assert refreshed is not None
        return _row_to_outbox(refreshed)

    def complete(
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
            current = _row_to_outbox(row)
            if current.idempotency_key != idempotency_key:
                raise EffectBindingError("effect outbox idempotency key mismatch")
            if current.status == "completed":
                return current
            completed_at = self._clock()
            connection.execute(
                """
                UPDATE effect_outbox
                SET status = 'completed', completed_at = ?
                WHERE approval_id = ? AND status = 'pending'
                """,
                (completed_at.isoformat(), approval_id),
            )
            refreshed = connection.execute(
                "SELECT * FROM effect_outbox WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        assert refreshed is not None
        return _row_to_outbox(refreshed)


class SyntheticIdempotentEffectService:
    """A local synthetic downstream that records intent only; it performs no real grant/reset."""

    def __init__(self, database_path: Path, *, clock=_utc_now) -> None:
        self.database_path = Path(database_path)
        self._clock = clock
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
                CREATE TABLE IF NOT EXISTS synthetic_effect_ledger (
                    idempotency_key TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL UNIQUE,
                    requester_user_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    normalized_arguments_json TEXT NOT NULL,
                    effect_ref TEXT NOT NULL UNIQUE,
                    executed_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _validate_existing(
        row: sqlite3.Row,
        *,
        record: EffectOutboxRecord,
    ) -> None:
        expected = (
            record.approval_id,
            record.requester_user_id,
            record.tenant_id,
            record.action.value,
            record.normalized_arguments_json,
        )
        actual = (
            str(row["approval_id"]),
            str(row["requester_user_id"]),
            str(row["tenant_id"]),
            str(row["action"]),
            str(row["normalized_arguments_json"]),
        )
        if actual != expected:
            raise EffectBindingError("idempotency key reused with a different effect payload")

    def execute(self, record: EffectOutboxRecord) -> SyntheticEffectExecution:
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

            effect_ref = f"synthetic-effect-{record.idempotency_key[:20]}"
            connection.execute(
                """
                INSERT INTO synthetic_effect_ledger (
                    idempotency_key, approval_id, requester_user_id, tenant_id, action,
                    normalized_arguments_json, effect_ref, executed_at
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

    def count_effects(self, approval_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM synthetic_effect_ledger
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
        assert row is not None
        return int(row["count"])


class DurableEffectWorker:
    def __init__(
        self,
        *,
        outbox_store: DurableEffectOutboxStore,
        effect_service: SyntheticIdempotentEffectService,
        crash_after_effect_once: bool = False,
    ) -> None:
        self._outbox_store = outbox_store
        self._effect_service = effect_service
        self._crash_after_effect_once = crash_after_effect_once

    def deliver(self, approval_id: str) -> SyntheticEffectExecution:
        record = self._outbox_store.begin_delivery(approval_id)
        execution = self._effect_service.execute(record)
        if self._crash_after_effect_once:
            self._crash_after_effect_once = False
            raise SyntheticWorkerCrash("synthetic crash after effect before outbox acknowledgement")
        self._outbox_store.complete(
            approval_id=approval_id,
            idempotency_key=record.idempotency_key,
        )
        return execution


class DurableApprovedEffectPipeline:
    """Approval-to-effect boundary used by the durable agent resume path."""

    def __init__(
        self,
        *,
        coordinator: TransactionalEffectCoordinator,
        worker: DurableEffectWorker,
    ) -> None:
        self._coordinator = coordinator
        self._worker = worker

    def resolve_and_deliver(
        self,
        *,
        approval_id: str,
        requester: Principal,
        action: ApprovalAction,
        arguments: dict[str, Any],
    ) -> tuple[ApprovalRecord, SyntheticEffectExecution | None]:
        record = self._coordinator.resolve_after_review_and_enqueue(
            approval_id=approval_id,
            requester=requester,
            action=action,
            arguments=arguments,
        )
        if record.status is ApprovalStatus.REJECTED:
            return record, None
        if record.status is not ApprovalStatus.CONSUMED:
            raise ApprovalStateError("unexpected approval status before effect delivery")
        return record, self._worker.deliver(approval_id)
