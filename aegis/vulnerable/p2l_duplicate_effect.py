from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.approvals.models import ApprovalAction


class VulnerableSyntheticWorkerCrash(RuntimeError):
    pass


@dataclass(frozen=True)
class VulnerableEffectSnapshot:
    approval_id: str
    action: ApprovalAction
    normalized_arguments_json: str


class VulnerableNonIdempotentEffectPipeline:
    """Intentionally vulnerable P2-L baseline.

    A worker reads a pending outbox row, performs a local synthetic effect, then marks the
    outbox complete. The downstream effect log has no idempotency key, so a crash after
    the effect or two workers holding the same stale snapshot can create duplicates.
    """

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
                CREATE TABLE IF NOT EXISTS vulnerable_effect_outbox (
                    approval_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    normalized_arguments_json TEXT NOT NULL,
                    status TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerable_effect_log (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    approval_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    normalized_arguments_json TEXT NOT NULL
                )
                """
            )

    def enqueue(
        self,
        *,
        approval_id: str,
        action: ApprovalAction,
        arguments: dict[str, Any],
    ) -> None:
        normalized = json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO vulnerable_effect_outbox (
                    approval_id, action, normalized_arguments_json, status
                ) VALUES (?, ?, ?, 'pending')
                """,
                (approval_id, action.value, normalized),
            )

    def read_pending_snapshot(self, approval_id: str) -> VulnerableEffectSnapshot | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT approval_id, action, normalized_arguments_json
                FROM vulnerable_effect_outbox
                WHERE approval_id = ? AND status = 'pending'
                """,
                (approval_id,),
            ).fetchone()
        if row is None:
            return None
        return VulnerableEffectSnapshot(
            approval_id=str(row["approval_id"]),
            action=ApprovalAction(str(row["action"])),
            normalized_arguments_json=str(row["normalized_arguments_json"]),
        )

    def deliver_snapshot(
        self,
        snapshot: VulnerableEffectSnapshot,
        *,
        crash_after_effect: bool = False,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO vulnerable_effect_log (
                    approval_id, action, normalized_arguments_json
                ) VALUES (?, ?, ?)
                """,
                (
                    snapshot.approval_id,
                    snapshot.action.value,
                    snapshot.normalized_arguments_json,
                ),
            )
        if crash_after_effect:
            raise VulnerableSyntheticWorkerCrash(
                "synthetic crash after non-idempotent effect before outbox acknowledgement"
            )
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE vulnerable_effect_outbox
                SET status = 'completed'
                WHERE approval_id = ?
                """,
                (snapshot.approval_id,),
            )

    def count_effects(self, approval_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM vulnerable_effect_log
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
        assert row is not None
        return int(row["count"])

    def outbox_status(self, approval_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT status FROM vulnerable_effect_outbox WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
        return None if row is None else str(row["status"])
