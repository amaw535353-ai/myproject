from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_backup import (
    AuthenticatedCheckpointBackupManager,
    CheckpointBackupError,
)
from aegis.agent.checkpoint_backup_storage import apply_restore
from evals.p4e_backup_common import marker, put, saver


CASE_ID = "P4E-A1-backup-file-substitution"


def run_case() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4e-a1-") as raw:
        root = Path(raw)
        trusted = saver(root / "trusted")
        alternate = saver(root / "alternate")
        put(
            trusted,
            thread_id="p4e-a1",
            checkpoint_id="00000001",
            marker="trusted-state",
        )
        put(
            alternate,
            thread_id="p4e-a1",
            checkpoint_id="00000001",
            marker="alternate-state",
        )
        trusted_backup = root / "trusted-backup"
        alternate_backup = root / "alternate-backup"
        AuthenticatedCheckpointBackupManager(saver=trusted).create_backup(trusted_backup)
        AuthenticatedCheckpointBackupManager(saver=alternate).create_backup(alternate_backup)

        baseline_target = saver(root / "baseline-target")
        apply_restore(
            baseline_target,
            backup_database_path=alternate_backup / "checkpoints.sqlite3",
            backup_anchor_path=alternate_backup / "anchors.sqlite3",
        )
        baseline_success = marker(baseline_target, "p4e-a1") == "alternate-state"

        substituted = root / "substituted"
        shutil.copytree(trusted_backup, substituted)
        shutil.copyfile(
            alternate_backup / "checkpoints.sqlite3",
            substituted / "checkpoints.sqlite3",
        )
        shutil.copyfile(
            alternate_backup / "anchors.sqlite3",
            substituted / "anchors.sqlite3",
        )
        hardened_target = saver(root / "hardened-target")
        rejection: str | None = None
        try:
            AuthenticatedCheckpointBackupManager(saver=hardened_target).restore_backup(
                substituted
            )
        except CheckpointBackupError as exc:
            rejection = exc.reason.value
        hardened_success = marker(hardened_target, "p4e-a1") is not None
        return (
            {"attempt_id": CASE_ID, "success": baseline_success},
            {
                "attempt_id": CASE_ID,
                "success": hardened_success,
                "rejection": rejection,
                "target_state_installed": hardened_success,
            },
        )
