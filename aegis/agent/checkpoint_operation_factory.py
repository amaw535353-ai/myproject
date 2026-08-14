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
    LifecycleAwareCheckpointTrustManifest,
)
from aegis.agent.checkpoint_runtime_providers import (
    LocalSqliteCheckpointAnchorProvider,
    LocalSyntheticCheckpointBackupAuthenticationProvider,
    LocalSyntheticCheckpointIntegrityProvider,
    LocalSyntheticCheckpointRecoveryAuthorityProvider,
)
from aegis.agent.checkpoint_trust import (
    LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST,
    CheckpointTrustSurface,
    LocalSyntheticCheckpointTrustProviderFactory,
)
from aegis.effects.trust_providers import TrustProviderKind


def _local_lifecycle_trust_descriptor() -> CheckpointLifecycleTrustProviderDescriptor:
    anchor_provider_id = next(
        provider.provider_id
        for provider in LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST.providers
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


class LocalSyntheticCheckpointOperationProviderFactory(
    LocalSyntheticCheckpointTrustProviderFactory
):
    """Default local trust factory that exports operations instead of raw keys."""

    manifest = LifecycleAwareCheckpointTrustManifest(
        checkpoint_manifest=LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST,
        lifecycle_descriptor=_local_lifecycle_trust_descriptor(),
    )

    def lifecycle_trust_descriptor(self) -> CheckpointLifecycleTrustProviderDescriptor:
        return self.manifest.lifecycle_descriptor

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
