from __future__ import annotations

from pathlib import Path

from aegis.agent.checkpoint_backup_create import (
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
from aegis.agent.checkpoint_runtime_contracts import (
    CheckpointBackupAuthenticationOperationProvider,
    CheckpointRecoveryAuthorityOperationProvider,
)
from aegis.agent.checkpoint_runtime_providers import (
    LocalSyntheticCheckpointBackupAuthenticationProvider,
    LocalSyntheticCheckpointRecoveryAuthorityProvider,
)


class AuthenticatedCheckpointBackupManager:
    policy_version = P4E_CHECKPOINT_BACKUP_POLICY_VERSION

    def __init__(
        self,
        *,
        saver: KeyLifecycleConfidentialCheckpointer,
        backup_key: bytes = P4E_LOCAL_BACKUP_KEY,
        backup_key_id: str = P4E_LOCAL_BACKUP_KEY_ID,
        backup_authentication_provider: (
            CheckpointBackupAuthenticationOperationProvider | None
        ) = None,
        recovery_authority_provider: (
            CheckpointRecoveryAuthorityOperationProvider | None
        ) = None,
    ) -> None:
        self.saver = saver
        self.backup_authentication_provider = (
            backup_authentication_provider
            if backup_authentication_provider is not None
            else LocalSyntheticCheckpointBackupAuthenticationProvider(
                key=bytes(backup_key),
                provider_id=backup_key_id,
            )
        )
        self.recovery_authority_provider = (
            recovery_authority_provider
            if recovery_authority_provider is not None
            else LocalSyntheticCheckpointRecoveryAuthorityProvider()
        )
        self.backup_key_id = self.backup_authentication_provider.provider_id

    def create_backup(self, backup_directory: Path) -> CheckpointBackupArtifact:
        return create_checkpoint_backup(
            self.saver,
            backup_directory,
            backup_authentication_provider=self.backup_authentication_provider,
            backup_key_id=self.backup_key_id,
        )

    def restore_backup(
        self,
        backup_directory: Path,
        *,
        operator_id: str = "local-synthetic-recovery-operator",
    ) -> CheckpointRestoreReport:
        return restore_checkpoint_backup(
            self.saver,
            backup_directory,
            backup_authentication_provider=self.backup_authentication_provider,
            recovery_authority_provider=self.recovery_authority_provider,
            operator_id=operator_id,
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
