from __future__ import annotations

from pathlib import Path

from aegis.agent.checkpoint_backup_format import (
    P4E_LOCAL_BACKUP_KEY,
    P4E_LOCAL_BACKUP_KEY_ID,
)
from aegis.agent.checkpoint_durability import (
    P4B_LOCAL_SYNTHETIC_HMAC_KEY,
    P4B_LOCAL_SYNTHETIC_KEY_ID,
)
from aegis.agent.checkpoint_runtime_providers import (
    LocalSqliteCheckpointAnchorProvider,
    LocalSyntheticCheckpointBackupAuthenticationProvider,
    LocalSyntheticCheckpointIntegrityProvider,
    LocalSyntheticCheckpointRecoveryAuthorityProvider,
)
from aegis.agent.checkpoint_trust import LocalSyntheticCheckpointTrustProviderFactory


class LocalSyntheticCheckpointOperationProviderFactory(
    LocalSyntheticCheckpointTrustProviderFactory
):
    """Default local trust factory that exports operations instead of raw keys."""

    def integrity_provider(self) -> LocalSyntheticCheckpointIntegrityProvider:
        return LocalSyntheticCheckpointIntegrityProvider(
            key=P4B_LOCAL_SYNTHETIC_HMAC_KEY,
            provider_id=P4B_LOCAL_SYNTHETIC_KEY_ID,
        )

    def anchor_provider(self, database_path: Path) -> LocalSqliteCheckpointAnchorProvider:
        return LocalSqliteCheckpointAnchorProvider(database_path=database_path)

    def backup_authentication_provider(
        self,
    ) -> LocalSyntheticCheckpointBackupAuthenticationProvider:
        return LocalSyntheticCheckpointBackupAuthenticationProvider(
            key=P4E_LOCAL_BACKUP_KEY,
            provider_id=P4E_LOCAL_BACKUP_KEY_ID,
        )

    def recovery_authority_provider(
        self,
    ) -> LocalSyntheticCheckpointRecoveryAuthorityProvider:
        return LocalSyntheticCheckpointRecoveryAuthorityProvider()
