from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_backup import (
    AuthenticatedCheckpointBackupManager,
    CheckpointBackupError,
)
from aegis.agent.checkpoint_backup_storage import apply_restore
from evals.p4e_backup_common import marker, put, saver


CASE_ID = "P4E-A2-stale-backup-rollback"


def _exercise(root: Path, hardened: bool) -> tuple[bool, str | None, str | None]:
    checkpointer = saver(root / "live")
    first = put(
        checkpointer,
        thread_id="p4e-a2",
        checkpoint_id="00000001",
        marker="generation-one",
    )
    backup = root / "backup"
    AuthenticatedCheckpointBackupManager(saver=checkpointer).create_backup(backup)
    put(
        checkpointer,
        thread_id="p4e-a2",
        checkpoint_id="00000002",
        marker="generation-two",
        parent=first,
    )
    rejection: str | None = None
    if hardened:
        try:
            AuthenticatedCheckpointBackupManager(saver=checkpointer).restore_backup(backup)
        except CheckpointBackupError as exc:
            rejection = exc.reason.value
    else:
        apply_restore(
            checkpointer,
            backup_database_path=backup / "checkpoints.sqlite3",
            backup_anchor_path=backup / "anchors.sqlite3",
        )
    observed = marker(checkpointer, "p4e-a2")
    return observed == "generation-one", rejection, observed


def run_case() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4e-a2-") as raw:
        root = Path(raw)
        baseline_success, _, baseline_marker = _exercise(root / "baseline", False)
        hardened_success, rejection, hardened_marker = _exercise(root / "hardened", True)
        return (
            {
                "attempt_id": CASE_ID,
                "success": baseline_success,
                "observed_generation": baseline_marker,
            },
            {
                "attempt_id": CASE_ID,
                "success": hardened_success,
                "rejection": rejection,
                "current_generation_preserved": hardened_marker == "generation-two",
            },
        )
