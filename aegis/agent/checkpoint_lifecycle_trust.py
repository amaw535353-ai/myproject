from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from aegis.agent.checkpoint_lifecycle_capabilities import (
    CheckpointLifecycleCapability,
    CheckpointLifecycleOperationProvider,
)
from aegis.agent.checkpoint_trust import (
    CheckpointTrustProviderManifest,
    CheckpointTrustSurface,
)
from aegis.effects.trust_providers import TrustDeploymentProfile, TrustProviderKind


P4K_CHECKPOINT_LIFECYCLE_TRUST_POLICY_VERSION = (
    "checkpoint-lifecycle-deployment-trust-boundary-v1"
)


class CheckpointLifecycleTrustReason(StrEnum):
    PROVIDER_ID_MISSING = "checkpoint_lifecycle_trust_provider_id_missing"
    ANCHOR_PROVIDER_ID_MISSING = "checkpoint_lifecycle_trust_anchor_provider_id_missing"
    ANCHOR_PROVIDER_MISMATCH = "checkpoint_lifecycle_trust_anchor_provider_mismatch"
    CAPABILITY_REQUIRED = "checkpoint_lifecycle_trust_capability_required"
    LOCAL_PROVIDER_IN_PRODUCTION = (
        "local_checkpoint_lifecycle_provider_forbidden_in_production"
    )
    INDEPENDENT_FAILURE_DOMAIN_REQUIRED = (
        "checkpoint_lifecycle_independent_failure_domain_required"
    )
    SYNTHETIC_PROVIDER_IN_PRODUCTION = (
        "synthetic_checkpoint_lifecycle_provider_forbidden_in_production"
    )
    OPERATIONALLY_EXTERNAL_REQUIRED = (
        "checkpoint_lifecycle_operationally_external_required"
    )
    PRODUCTION_RUNTIME_ELIGIBLE_REQUIRED = (
        "checkpoint_lifecycle_production_runtime_eligible_required"
    )


class CheckpointLifecycleTrustBoundaryError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointLifecycleTrustReason,
        *,
        capability: CheckpointLifecycleCapability | None = None,
    ) -> None:
        self.reason = reason
        self.capability = capability
        detail = reason.value
        if capability is not None:
            detail = f"{detail}:{capability.value}"
        super().__init__(detail)


@dataclass(frozen=True)
class CheckpointLifecycleTrustProviderDescriptor:
    """Deployment posture for the provider coordinating checkpoint lifecycle operations.

    P4-K deliberately keeps this descriptor separate from the five P4-F storage and
    recovery trust surfaces so the original P4-F policy/evaluation remains stable.
    Production composition must satisfy both the P4-F manifest and this lifecycle
    coordinator descriptor.
    """

    provider_id: str
    anchor_provider_id: str
    kind: TrustProviderKind
    independent_failure_domain: bool
    capabilities: frozenset[CheckpointLifecycleCapability]
    synthetic_in_process: bool
    operationally_external: bool
    production_runtime_eligible: bool
    policy_version: str = P4K_CHECKPOINT_LIFECYCLE_TRUST_POLICY_VERSION

    def __post_init__(self) -> None:
        if not self.provider_id.strip():
            raise CheckpointLifecycleTrustBoundaryError(
                CheckpointLifecycleTrustReason.PROVIDER_ID_MISSING
            )
        if not self.anchor_provider_id.strip():
            raise CheckpointLifecycleTrustBoundaryError(
                CheckpointLifecycleTrustReason.ANCHOR_PROVIDER_ID_MISSING
            )

    def public_posture(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "anchor_provider_id": self.anchor_provider_id,
            "kind": self.kind.value,
            "independent_failure_domain": self.independent_failure_domain,
            "capabilities": sorted(capability.value for capability in self.capabilities),
            "synthetic_in_process": self.synthetic_in_process,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "policy_version": self.policy_version,
        }


def describe_checkpoint_lifecycle_provider(
    provider: CheckpointLifecycleOperationProvider,
    *,
    kind: TrustProviderKind,
    independent_failure_domain: bool,
    production_runtime_eligible: bool | None = None,
) -> CheckpointLifecycleTrustProviderDescriptor:
    return CheckpointLifecycleTrustProviderDescriptor(
        provider_id=str(getattr(provider, "provider_id", "")),
        anchor_provider_id=str(getattr(provider, "anchor_provider_id", "")),
        kind=kind,
        independent_failure_domain=bool(independent_failure_domain),
        capabilities=frozenset(getattr(provider, "capabilities", frozenset())),
        synthetic_in_process=bool(getattr(provider, "synthetic_in_process", True)),
        operationally_external=bool(getattr(provider, "operationally_external", False)),
        production_runtime_eligible=(
            bool(getattr(provider, "production_runtime_eligible", False))
            if production_runtime_eligible is None
            else bool(production_runtime_eligible)
        ),
    )


def _anchor_provider_id(manifest: CheckpointTrustProviderManifest) -> str:
    manifest.assert_complete()
    for provider in manifest.providers:
        if provider.surface is CheckpointTrustSurface.MONOTONIC_ANCHOR:
            return provider.provider_id
    raise RuntimeError("complete checkpoint trust manifest has no monotonic anchor")


def assert_checkpoint_deployment_trust(
    *,
    checkpoint_manifest: CheckpointTrustProviderManifest,
    lifecycle_descriptor: CheckpointLifecycleTrustProviderDescriptor,
    profile: TrustDeploymentProfile,
) -> None:
    """Require both the P4-F trust manifest and P4-K lifecycle trust posture."""

    checkpoint_manifest.assert_allowed(profile)

    if lifecycle_descriptor.anchor_provider_id != _anchor_provider_id(checkpoint_manifest):
        raise CheckpointLifecycleTrustBoundaryError(
            CheckpointLifecycleTrustReason.ANCHOR_PROVIDER_MISMATCH
        )

    for capability in CheckpointLifecycleCapability:
        if capability not in lifecycle_descriptor.capabilities:
            raise CheckpointLifecycleTrustBoundaryError(
                CheckpointLifecycleTrustReason.CAPABILITY_REQUIRED,
                capability=capability,
            )

    if profile is TrustDeploymentProfile.LOCAL_SYNTHETIC:
        return

    if lifecycle_descriptor.kind is not TrustProviderKind.EXTERNAL:
        raise CheckpointLifecycleTrustBoundaryError(
            CheckpointLifecycleTrustReason.LOCAL_PROVIDER_IN_PRODUCTION
        )
    if not lifecycle_descriptor.independent_failure_domain:
        raise CheckpointLifecycleTrustBoundaryError(
            CheckpointLifecycleTrustReason.INDEPENDENT_FAILURE_DOMAIN_REQUIRED
        )
    if lifecycle_descriptor.synthetic_in_process:
        raise CheckpointLifecycleTrustBoundaryError(
            CheckpointLifecycleTrustReason.SYNTHETIC_PROVIDER_IN_PRODUCTION
        )
    if not lifecycle_descriptor.operationally_external:
        raise CheckpointLifecycleTrustBoundaryError(
            CheckpointLifecycleTrustReason.OPERATIONALLY_EXTERNAL_REQUIRED
        )
    if not lifecycle_descriptor.production_runtime_eligible:
        raise CheckpointLifecycleTrustBoundaryError(
            CheckpointLifecycleTrustReason.PRODUCTION_RUNTIME_ELIGIBLE_REQUIRED
        )


def production_lifecycle_descriptor_allowed(
    *,
    checkpoint_manifest: CheckpointTrustProviderManifest,
    lifecycle_descriptor: CheckpointLifecycleTrustProviderDescriptor,
) -> bool:
    """Return policy-shape acceptance only; this is not implementation evidence."""

    try:
        assert_checkpoint_deployment_trust(
            checkpoint_manifest=checkpoint_manifest,
            lifecycle_descriptor=lifecycle_descriptor,
            profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
        )
    except Exception:
        return False
    return True
