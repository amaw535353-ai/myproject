from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


P3F_TRUST_POLICY_VERSION = "explicit-production-trust-provider-boundary-v1"


class TrustDeploymentProfile(StrEnum):
    LOCAL_SYNTHETIC = "local_synthetic"
    PRODUCTION_EXTERNAL_REQUIRED = "production_external_required"


class TrustProviderKind(StrEnum):
    LOCAL_SYNTHETIC = "local_synthetic"
    EXTERNAL = "external"


class TrustSurface(StrEnum):
    AUTHORIZATION_SIGNING = "authorization_signing"
    PROTECTED_CHECKPOINT = "protected_checkpoint"
    CHECKPOINT_RECEIPT_SOURCE = "checkpoint_receipt_source"
    RECEIPT_WITNESS = "receipt_witness"


class TrustBoundaryReason(StrEnum):
    MISSING_SURFACE = "trust_provider_surface_missing"
    LOCAL_PROVIDER_IN_PRODUCTION = "local_trust_provider_forbidden_in_production"
    EXTERNAL_KEY_CUSTODY_REQUIRED = "external_key_custody_required"
    INDEPENDENT_FAILURE_DOMAIN_REQUIRED = "independent_failure_domain_required"
    DUPLICATE_PROVIDER_ID = "duplicate_trust_provider_id"


class TrustBoundaryError(RuntimeError):
    def __init__(self, reason: TrustBoundaryReason, *, surface: TrustSurface | None = None) -> None:
        self.reason = reason
        self.surface = surface
        detail = reason.value if surface is None else f"{reason.value}:{surface.value}"
        super().__init__(detail)


@dataclass(frozen=True)
class TrustProviderDescriptor:
    surface: TrustSurface
    provider_id: str
    kind: TrustProviderKind
    independent_failure_domain: bool
    external_key_custody: bool = False

    def __post_init__(self) -> None:
        if not self.provider_id.strip():
            raise ValueError("trust provider id must be non-empty")


@dataclass(frozen=True)
class TrustProviderManifest:
    providers: tuple[TrustProviderDescriptor, ...]
    policy_version: str = P3F_TRUST_POLICY_VERSION

    def _by_surface(self) -> dict[TrustSurface, TrustProviderDescriptor]:
        mapped: dict[TrustSurface, TrustProviderDescriptor] = {}
        for provider in self.providers:
            if provider.surface in mapped:
                raise ValueError(f"duplicate trust surface: {provider.surface.value}")
            mapped[provider.surface] = provider
        return mapped

    def assert_complete(self) -> None:
        mapped = self._by_surface()
        for surface in TrustSurface:
            if surface not in mapped:
                raise TrustBoundaryError(TrustBoundaryReason.MISSING_SURFACE, surface=surface)

    def assert_allowed(self, profile: TrustDeploymentProfile) -> None:
        self.assert_complete()
        if profile is TrustDeploymentProfile.LOCAL_SYNTHETIC:
            return

        provider_ids = [provider.provider_id for provider in self.providers]
        if len(provider_ids) != len(set(provider_ids)):
            raise TrustBoundaryError(TrustBoundaryReason.DUPLICATE_PROVIDER_ID)

        for provider in self.providers:
            if provider.kind is not TrustProviderKind.EXTERNAL:
                raise TrustBoundaryError(
                    TrustBoundaryReason.LOCAL_PROVIDER_IN_PRODUCTION,
                    surface=provider.surface,
                )
            if not provider.independent_failure_domain:
                raise TrustBoundaryError(
                    TrustBoundaryReason.INDEPENDENT_FAILURE_DOMAIN_REQUIRED,
                    surface=provider.surface,
                )
            if provider.surface in {
                TrustSurface.AUTHORIZATION_SIGNING,
                TrustSurface.CHECKPOINT_RECEIPT_SOURCE,
            } and not provider.external_key_custody:
                raise TrustBoundaryError(
                    TrustBoundaryReason.EXTERNAL_KEY_CUSTODY_REQUIRED,
                    surface=provider.surface,
                )

    def production_trust_claim_allowed(self) -> bool:
        try:
            self.assert_allowed(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
        except TrustBoundaryError:
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
            }
            for provider in sorted(self.providers, key=lambda item: item.surface.value)
        )


class HighImpactTrustProviderFactory(Protocol):
    """Composition seam for trust-bearing services used by the high-impact runtime.

    External implementations are expected to keep private signing material and
    rollback-resistant checkpoint/witness state outside the AegisDesk process.
    The default repository implementation remains deliberately local and synthetic.
    """

    manifest: TrustProviderManifest

    def authorization_signer(self, *, registry: Any, fixture: dict[str, Any]) -> Any: ...

    def protected_checkpoint_authority(self, *, database_path: Any) -> Any: ...

    def checkpoint_receipt_source(
        self,
        *,
        checkpoint_authority: Any,
        fixture: dict[str, Any],
    ) -> Any: ...

    def checkpoint_receipt_observer(
        self,
        *,
        receipt_source: Any,
        witness_database_path: Any,
    ) -> Any: ...


LOCAL_SYNTHETIC_TRUST_MANIFEST = TrustProviderManifest(
    providers=(
        TrustProviderDescriptor(
            surface=TrustSurface.AUTHORIZATION_SIGNING,
            provider_id="local-fixture-ed25519-authz-signer",
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            external_key_custody=False,
        ),
        TrustProviderDescriptor(
            surface=TrustSurface.PROTECTED_CHECKPOINT,
            provider_id="local-sqlite-protected-checkpoint",
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=True,
            external_key_custody=False,
        ),
        TrustProviderDescriptor(
            surface=TrustSurface.CHECKPOINT_RECEIPT_SOURCE,
            provider_id="local-fixture-ed25519-checkpoint-receipt-source",
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=False,
            external_key_custody=False,
        ),
        TrustProviderDescriptor(
            surface=TrustSurface.RECEIPT_WITNESS,
            provider_id="local-sqlite-receipt-witness",
            kind=TrustProviderKind.LOCAL_SYNTHETIC,
            independent_failure_domain=True,
            external_key_custody=False,
        ),
    )
)
