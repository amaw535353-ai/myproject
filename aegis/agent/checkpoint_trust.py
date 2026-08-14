from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from aegis.agent.checkpoint_backup_format import (
    P4E_LOCAL_BACKUP_KEY,
    P4E_LOCAL_BACKUP_KEY_ID,
)
from aegis.agent.checkpoint_durability import (
    P4B_LOCAL_SYNTHETIC_HMAC_KEY,
    P4B_LOCAL_SYNTHETIC_KEY_ID,
)
from aegis.agent.checkpoint_keys import (
    CheckpointEncryptionKeyProvider,
    LocalSyntheticCheckpointKeyProvider,
    build_default_local_synthetic_checkpoint_key_provider,
)
from aegis.effects.trust_providers import TrustDeploymentProfile, TrustProviderKind


P4F_CHECKPOINT_TRUST_POLICY_VERSION = "checkpoint-deployment-trust-provider-boundary-v1"


class CheckpointTrustSurface(StrEnum):
    ENCRYPTION_KEY_CUSTODY = "checkpoint_encryption_key_custody"
    INTEGRITY_KEY_CUSTODY = "checkpoint_integrity_key_custody"
    MONOTONIC_ANCHOR = "checkpoint_monotonic_anchor"
    BACKUP_AUTHENTICATION = "checkpoint_backup_authentication"
    RECOVERY_AUTHORITY = "checkpoint_recovery_authority"


class CheckpointTrustReason(StrEnum):
    MISSING_SURFACE = "checkpoint_trust_provider_surface_missing"
    LOCAL_PROVIDER_IN_PRODUCTION = "local_checkpoint_trust_provider_forbidden_in_production"
    EXTERNAL_KEY_CUSTODY_REQUIRED = "checkpoint_external_key_custody_required"
    INDEPENDENT_FAILURE_DOMAIN_REQUIRED = "checkpoint_independent_failure_domain_required"
    ROLLBACK_RESISTANT_STATE_REQUIRED = "checkpoint_rollback_resistant_state_required"
    EXTERNAL_RECOVERY_AUTHORITY_REQUIRED = "checkpoint_external_recovery_authority_required"
    DUPLICATE_PROVIDER_ID = "duplicate_checkpoint_trust_provider_id"


class CheckpointTrustBoundaryError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointTrustReason,
        *,
        surface: CheckpointTrustSurface | None = None,
    ) -> None:
        self.reason = reason
        self.surface = surface
        detail = reason.value if surface is None else f"{reason.value}:{surface.value}"
        super().__init__(detail)


@dataclass(frozen=True)
class CheckpointTrustProviderDescriptor:
    surface: CheckpointTrustSurface
    provider_id: str
    kind: TrustProviderKind
    independent_failure_domain: bool
    external_key_custody: bool = False
    rollback_resistant_state: bool = False
    external_recovery_authority: bool = False

    def __post_init__(self) -> None:
        if not self.provider_id.strip():
            raise ValueError("checkpoint trust provider id must be non-empty")


@dataclass(frozen=True)
class CheckpointTrustProviderManifest:
    providers: tuple[CheckpointTrustProviderDescriptor, ...]
    policy_version: str = P4F_CHECKPOINT_TRUST_POLICY_VERSION

    def _by_surface(self) -> dict[CheckpointTrustSurface, CheckpointTrustProviderDescriptor]:
        mapped: dict[CheckpointTrustSurface, CheckpointTrustProviderDescriptor] = {}
        for provider in self.providers:
            if provider.surface in mapped:
                raise ValueError(f"duplicate checkpoint trust surface: {provider.surface.value}")
            mapped[provider.surface] = provider
        return mapped

    def assert_complete(self) -> None:
        mapped = self._by_surface()
        for surface in CheckpointTrustSurface:
            if surface not in mapped:
                raise CheckpointTrustBoundaryError(
                    CheckpointTrustReason.MISSING_SURFACE,
                    surface=surface,
                )

    def assert_allowed(self, profile: TrustDeploymentProfile) -> None:
        self.assert_complete()
        if profile is TrustDeploymentProfile.LOCAL_SYNTHETIC:
            return

        provider_ids = [provider.provider_id for provider in self.providers]
        if len(provider_ids) != len(set(provider_ids)):
            raise CheckpointTrustBoundaryError(CheckpointTrustReason.DUPLICATE_PROVIDER_ID)

        key_custody_surfaces = {
            CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY,
            CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY,
            CheckpointTrustSurface.BACKUP_AUTHENTICATION,
        }
        for provider in self.providers:
            if provider.kind is not TrustProviderKind.EXTERNAL:
                raise CheckpointTrustBoundaryError(
                    CheckpointTrustReason.LOCAL_PROVIDER_IN_PRODUCTION,
                    surface=provider.surface,
                )
            if not provider.independent_failure_domain:
                raise CheckpointTrustBoundaryError(
                    CheckpointTrustReason.INDEPENDENT_FAILURE_DOMAIN_REQUIRED,
                    surface=provider.surface,
                )
            if provider.surface in key_custody_surfaces and not provider.external_key_custody:
                raise CheckpointTrustBoundaryError(
                    CheckpointTrustReason.EXTERNAL_KEY_CUSTODY_REQUIRED,
                    surface=provider.surface,
                )
            if (
                provider.surface is CheckpointTrustSurface.MONOTONIC_ANCHOR
                and not provider.rollback_resistant_state
            ):
                raise CheckpointTrustBoundaryError(
                    CheckpointTrustReason.ROLLBACK_RESISTANT_STATE_REQUIRED,
                    surface=provider.surface,
                )
            if (
                provider.surface is CheckpointTrustSurface.RECOVERY_AUTHORITY
                and not provider.external_recovery_authority
            ):
                raise CheckpointTrustBoundaryError(
                    CheckpointTrustReason.EXTERNAL_RECOVERY_AUTHORITY_REQUIRED,
                    surface=provider.surface,
                )

    def production_trust_claim_allowed(self) -> bool:
        try:
            self.assert_allowed(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
        except CheckpointTrustBoundaryError:
            return False
        return True

    def public_posture(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "surface": provider.surface.value,
                "provider_id": provider.provider_id,
                "kind": provider.kind.value,
                "independent_failure_domain": provider.independent_failure_domain,
                "external_key_custody": provider.external_key_custody,
                "rollback_resistant_state": provider.rollback_resistant_state,
                "external_recovery_authority": provider.external_recovery_authority,
            }
            for provider in sorted(self.providers, key=lambda item: item.surface.value)
        )


@dataclass(frozen=True)
class CheckpointIntegrityKeyMaterial:
    key_id: str
    key: bytes


@dataclass(frozen=True)
class CheckpointBackupAuthenticationMaterial:
    key_id: str
    key: bytes


class CheckpointRuntimeTrustProviderFactory(Protocol):
    """Composition seam for checkpoint trust-bearing dependencies.

    Production implementations are expected to keep checkpoint encryption keys,
    integrity keys, monotonic state, backup authentication material, and recovery
    authority outside the AegisDesk process/local failure domain. The repository
    supplies only a local synthetic implementation.
    """

    manifest: CheckpointTrustProviderManifest

    def encryption_key_provider(self) -> CheckpointEncryptionKeyProvider: ...

    def integrity_key_material(self) -> CheckpointIntegrityKeyMaterial: ...

    def backup_authentication_material(self) -> CheckpointBackupAuthenticationMaterial: ...


LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST = CheckpointTrustProviderManifest(
    providers=(
        CheckpointTrustProviderDescriptor(
            surface=CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY,
            provider_id="local-synthetic-checkpoint-keyring",
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            external_key_custody=False,
        ),
        CheckpointTrustProviderDescriptor(
            surface=CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY,
            provider_id=P4B_LOCAL_SYNTHETIC_KEY_ID,
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            external_key_custody=False,
        ),
        CheckpointTrustProviderDescriptor(
            surface=CheckpointTrustSurface.MONOTONIC_ANCHOR,
            provider_id="local-sqlite-agent-checkpoint-anchor",
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            rollback_resistant_state=False,
        ),
        CheckpointTrustProviderDescriptor(
            surface=CheckpointTrustSurface.BACKUP_AUTHENTICATION,
            provider_id=P4E_LOCAL_BACKUP_KEY_ID,
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            external_key_custody=False,
        ),
        CheckpointTrustProviderDescriptor(
            surface=CheckpointTrustSurface.RECOVERY_AUTHORITY,
            provider_id="local-process-checkpoint-recovery-authority",
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            external_recovery_authority=False,
        ),
    )
)


class LocalSyntheticCheckpointTrustProviderFactory:
    """Local-only checkpoint trust bundle used by the default lab profile."""

    manifest = LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST

    def encryption_key_provider(self) -> LocalSyntheticCheckpointKeyProvider:
        return build_default_local_synthetic_checkpoint_key_provider()

    def integrity_key_material(self) -> CheckpointIntegrityKeyMaterial:
        return CheckpointIntegrityKeyMaterial(
            key_id=P4B_LOCAL_SYNTHETIC_KEY_ID,
            key=P4B_LOCAL_SYNTHETIC_HMAC_KEY,
        )

    def backup_authentication_material(self) -> CheckpointBackupAuthenticationMaterial:
        return CheckpointBackupAuthenticationMaterial(
            key_id=P4E_LOCAL_BACKUP_KEY_ID,
            key=P4E_LOCAL_BACKUP_KEY,
        )
