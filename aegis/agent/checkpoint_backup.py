from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer


P4E_CHECKPOINT_BACKUP_POLICY_VERSION = "authenticated-checkpoint-backup-restore-v1"
P4E_LOCAL_BACKUP_KEY_ID = "local-synthetic-agent-checkpoint-backup-hmac-v1"
P4E_LOCAL_BACKUP_KEY = hashlib.sha256(
    b"aegisdesk-local-checkpoint-backup-key-v1-2026"
).digest()


class CheckpointBackupReason(StrEnum):
    PACKAGE_INVALID = "checkpoint_backup_package_invalid"
    AUTHENTICATION_FAILED = "checkpoint_backup_authentication_failed"
    ROLLBACK_DETECTED = "checkpoint_backup_rollback_detected"
    VALIDATION_FAILED = "checkpoint_backup_validation_failed"


class CheckpointBackupError(RuntimeError):
    def __init__(self, reason: CheckpointBackupReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True)
class CheckpointBackupArtifact:
    package: bytes
    backup_id: str
    checkpoint_heads: int


@dataclass(frozen=True)
class CheckpointRestoreReport:
    backup_id: str
    checkpoint_heads: int
    checkpoint_rows: int
    write_rows: int


class AuthenticatedCheckpointBackupManager:
    policy_version = P4E_CHECKPOINT_BACKUP_POLICY_VERSION

    def __init__(self, *, saver: KeyLifecycleConfidentialCheckpointer) -> None:
        self.saver = saver
