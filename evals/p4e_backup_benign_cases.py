from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_backup import AuthenticatedCheckpointBackupManager
from aegis.agent.checkpoint_backup_storage import apply_restore
from evals.p4e_backup_common import config, marker, put, saver


FRESH_CASE_ID = "P4E-B1-fresh-target-recovery"
FORWARD_CASE_ID = "P4E-B2-forward-ancestor-recovery"


def fresh_recovery_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4e-b1-") as raw:
        root = Path(raw)
        source = saver(root / "source")
        saved = put(
            source,
            thread_id="p4e-b1",
            checkpoint_id="00000001",
            marker="fresh-recovery",
        )
        source.put_writes(
            saved,
            [("synthetic_pending", {"marker": "pending-recovery"})],
            task_id="p4e-task",
        )
        backup = root / "backup"
        artifact = AuthenticatedCheckpointBackupManager(saver=source).create_backup(backup)
        target = saver(root / "target")
        report = AuthenticatedCheckpointBackupManager(saver=target).restore_backup(backup)
        reopened = target.get_tuple(config("p4e-b1"))
        pending = [] if reopened is None else list(reopened.pending_writes)
        safe = bool(
            reopened
            and reopened.checkpoint["channel_values"].get("marker") == "fresh-recovery"
            and pending
            and pending[0][2].get("marker") == "pending-recovery"
            and report.backup_id == artifact.backup_id
        )
        return {
            "attempt_id": FRESH_CASE_ID,
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
            "pending_write_preserved": bool(pending),
        }


def forward_recovery_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4e-b2-") as raw:
        root = Path(raw)
        source = saver(root / "source")
        first = put(
            source,
            thread_id="p4e-b2",
            checkpoint_id="00000001",
            marker="ancestor",
        )
        target = saver(root / "target")
        apply_restore(
            target,
            backup_database_path=source.database_path,
            backup_anchor_path=source.anchor_database_path,
        )
        put(
            source,
            thread_id="p4e-b2",
            checkpoint_id="00000002",
            marker="recovered-forward",
            parent=first,
        )
        backup = root / "backup"
        AuthenticatedCheckpointBackupManager(saver=source).create_backup(backup)
        report = AuthenticatedCheckpointBackupManager(saver=target).restore_backup(backup)
        safe = marker(target, "p4e-b2") == "recovered-forward" and report.checkpoint_rows == 2
        return {
            "attempt_id": FORWARD_CASE_ID,
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
            "ancestor_boundary_preserved": safe,
        }
