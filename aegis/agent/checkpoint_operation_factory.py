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
from aegis.agent.checkpoint_lifecycle_capabilities import (
    CheckpointLifecycleCapability,
    LocalSqliteCheckpointLifecycleProvider,
)
from aegis.agent.checkpoint_lifecycle_trust import (
    CheckpointLifecycleTrustProviderDescriptor,
)
from aegis.agent.checkpoint_runtime_providers import (
    LocalSqliteCheckpointAnchorProvider,
    LocalSyntheticCheckpointBackupAuthenticationProvider,
    LocalSyntheticCheckpointIntegrityProvider,
    LocalSyntheticCheckpointRecoveryAuthorityProvider,
)
from aegis.agent.checkpoint_trust import (
    CheckpointTrustSurface,
    LocalSyntheticCheckpointTrustProviderFactory,
)
from aegis.effects.trust_providers import TrustProviderKind


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

    def lifecycle_provider(
        self,
        anchor_provider: LocalSqliteCheckpointAnchorProvider,
    ) -> LocalSqliteCheckpointLifecycleProvider:
        return LocalSqliteCheckpointLifecycleProvider(anchor_provider=anchor_provider)

    def lifecycle_trust_descriptor(self) -> CheckpointLifecycleTrustProviderDescriptor:
        anchor_provider_id = next(
            provider.provider_id
            for provider in self.manifest.providers
            if provider.surface is CheckpointTrustSurface.MONOTONIC_ANCHOR
        )
        return CheckpointLifecycleTrustProviderDescriptor(
            provider_id=LocalSqliteCheckpointLifecycleProvider.provider_id,
            anchor_provider_id=anchor_provider_id,
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            capabilities=frozenset(CheckpointLifecycleCapability),
            synthetic_in_process=True,
            operationally_external=False,
            production_runtime_eligible=False,
        )

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
