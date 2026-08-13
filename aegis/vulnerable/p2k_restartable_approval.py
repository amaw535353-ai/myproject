from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.approvals.models import ApprovalAction
from aegis.identity.models import Principal


@dataclass(frozen=True)
class VulnerableResumeResult:
    approval_id: str
    requester_user_id: str
    tenant_id: str
    action: ApprovalAction
    arguments: dict[str, Any]


class VulnerableRestartableApprovalWorkflow:
    """Intentionally vulnerable local baseline for P2-K.

    It persists only a coarse approval status and trusts caller-supplied requester/action/
    arguments at resume time. Approved records are never consumed, so they remain
    replayable across process restarts. This module is for the synthetic lab only.
    """

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerable_approval_workflows (
                    approval_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    stored_action TEXT NOT NULL,
                    stored_arguments_json TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path, timeout=5.0)

    def create(self, *, action: ApprovalAction, arguments: dict[str, Any]) -> str:
        approval_id = f"vuln_apr_{secrets.token_urlsafe(12)}"
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO vulnerable_approval_workflows (
                    approval_id, status, stored_action, stored_arguments_json
                ) VALUES (?, 'pending', ?, ?)
                """,
                (
                    approval_id,
                    action.value,
                    json.dumps(arguments, sort_keys=True, separators=(",", ":")),
                ),
            )
        return approval_id

    def approve(self, approval_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE vulnerable_approval_workflows SET status = 'approved' WHERE approval_id = ?",
                (approval_id,),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("vulnerable approval not found")

    def reject(self, approval_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE vulnerable_approval_workflows SET status = 'rejected' WHERE approval_id = ?",
                (approval_id,),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("vulnerable approval not found")

    def resume(
        self,
        *,
        approval_id: str,
        requester: Principal,
        action: ApprovalAction,
        arguments: dict[str, Any],
    ) -> VulnerableResumeResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM vulnerable_approval_workflows WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("vulnerable approval not found")
        if str(row[0]) != "approved":
            return None
        # Deliberate flaw: caller-supplied authority replaces persisted request context,
        # and the approval remains approved after this resume.
        return VulnerableResumeResult(
            approval_id=approval_id,
            requester_user_id=requester.user_id,
            tenant_id=requester.tenant_id,
            action=action,
            arguments=dict(arguments),
        )
