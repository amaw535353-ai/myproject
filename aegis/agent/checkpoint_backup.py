from __future__ import annotations

from pathlib import Path

from aegis.agent.checkpoint_backup_create_v2 import (
    CheckpointBackupArtifact,
    create_checkpoint_backup,
)
from aegis.agent.checkpoint_backup_format import (
    P4E_BACKUP_SCHEMA,
    P4E_CHECKPOINT_BACKUP_POLICY_VERSION,
    P4E_LOCAL_BACKUP_KEY,
    P4E_LOCAL_BACKUP_KEY_ID,
    CheckpointBackupError,
    CheckpointBackupReason,
)
from aegis.agent.checkpoint_backup_restore import (
    CheckpointRestoreReport,
    restore_checkpoint_backup,
)
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer


class AuthenticatedCheckpointBackupManager:
    policy_version = P4E_CHECKPOINT_BACKUP_POLICY_VERSION

    def __init__(
        self,
        *,
        saver: KeyLifecycleConfidentialCheckpointer,
        backup_key: bytes = P4E_LOCAL_BACKUP_KEY,
        backup_key_id: str = P4E_LOCAL_BACKUP_KEY_ID,
    ) -> None:
        self.saver = saver
        self.backup_key = bytes(backup_key)
        self.backup_key_id = backup_key_id

    def create_backup(self, backup_directory: Path) -> CheckpointBackupArtifact:
        return create_checkpoint_backup(
            self.saver,
            backup_directory,
            backup_key=self.backup_key,
            backup_key_id=self.backup_key_id,
        )

    def restore_backup(self, backup_directory: Path) -> CheckpointRestoreReport:
        return restore_checkpoint_backup(
            self.saver,
            backup_directory,
            backup_key=self.backup_key,
            backup_key_id=self.backup_key_id,
        )


__all__ = [
    "AuthenticatedCheckpointBackupManager",
    "CheckpointBackupArtifact",
    "CheckpointBackupError",
    "CheckpointBackupReason",
    "CheckpointRestoreReport",
    "P4E_BACKUP_SCHEMA",
    "P4E_CHECKPOINT_BACKUP_POLICY_VERSION",
    "P4E_LOCAL_BACKUP_KEY_ID",
]
