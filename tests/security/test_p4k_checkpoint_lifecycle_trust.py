from __future__ import annotations

import pytest

from aegis.agent.checkpoint_external_contracts import (
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_external_lifecycle import (
    SyntheticExternalStyleCheckpointLifecycleProvider,
)
from aegis.agent.checkpoint_external_runtime_bridge import (
    SyntheticExternalCheckpointAnchorRuntimeBridge,
)
from aegis.agent.checkpoint_lifecycle_capabilities import CheckpointLifecycleCapability
from aegis.agent.checkpoint_lifecycle_trust import (
    P4K_CHECKPOINT_LIFECYCLE_TRUST_POLICY_VERSION,
    CheckpointLifecycleTrustBoundaryError,
    CheckpointLifecycleTrustProviderDescriptor,
    CheckpointLifecycleTrustReason,
    LifecycleAwareCheckpointTrustManifest,
    assert_checkpoint_deployment_trust,
    describe_checkpoint_lifecycle_provider,
    production_lifecycle_descriptor_allowed,
)
from aegis.agent.checkpoint_operation_factory import (
    LocalSyntheticCheckpointOperationProviderFactory,
)
from aegis.agent.checkpoint_trust import (
    P4F_CHECKPOINT_TRUST_POLICY_VERSION,
    CheckpointTrustSurface,
)
from aegis.effects.trust_providers import TrustDeploymentProfile, TrustProviderKind
from evals.p4k_checkpoint_lifecycle_trust import build_report


def _anchor_provider_id(manifest) -> str:
    return next(
        provider.provider_id
        for provider in manifest.providers
        if provider.surface is CheckpointTrustSurface.MONOTONIC_ANCHOR
    )


def _production_descriptor(
    *,
    anchor_provider_id: str,
    provider_id: str = "external-checkpoint-lifecycle-coordinator-contract",
    kind: TrustProviderKind = TrustProviderKind.EXTERNAL,
    independent_failure_domain: bool = True,
    capabilities: frozenset[CheckpointLifecycleCapability] = frozenset(
        CheckpointLifecycleCapability
    ),
    synthetic_in_process: bool = False,
    operationally_external: bool = True,
    production_runtime_eligible: bool = True,
) -> CheckpointLifecycleTrustProviderDescriptor:
    return CheckpointLifecycleTrustProviderDescriptor(
        provider_id=provider_id,
        anchor_provider_id=anchor_provider_id,
        kind=kind,
        independent_failure_domain=independent_failure_domain,
        capabilities=capabilities,
        synthetic_in_process=synthetic_in_process,
        operationally_external=operationally_external,
        production_runtime_eligible=production_runtime_eligible,
    )


def test_default_factory_wraps_original_p4f_manifest_with_local_lifecycle_trust() -> None:
    factory = LocalSyntheticCheckpointOperationProviderFactory()
    manifest = factory.manifest
    descriptor = factory.lifecycle_trust_descriptor()

    assert isinstance(manifest, LifecycleAwareCheckpointTrustManifest)
    assert manifest.policy_version == P4F_CHECKPOINT_TRUST_POLICY_VERSION
    assert len(manifest.providers) == len(CheckpointTrustSurface) == 5
    assert descriptor.policy_version == P4K_CHECKPOINT_LIFECYCLE_TRUST_POLICY_VERSION
    assert descriptor.provider_id == "local-sqlite-agent-checkpoint-lifecycle"
    assert descriptor.anchor_provider_id == _anchor_provider_id(manifest)
    assert descriptor.capabilities == frozenset(CheckpointLifecycleCapability)
    assert descriptor.kind is TrustProviderKind.LOCAL_SYNTHETIC
    assert descriptor.independent_failure_domain is False
    assert descriptor.synthetic_in_process is True
    assert descriptor.operationally_external is False
    assert descriptor.production_runtime_eligible is False

    manifest.assert_allowed(TrustDeploymentProfile.LOCAL_SYNTHETIC)
    assert manifest.production_trust_claim_allowed() is False


def test_complete_external_lifecycle_descriptor_contract_passes_production_policy_shape() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    descriptor = _production_descriptor(
        anchor_provider_id=_anchor_provider_id(bundle.manifest)
    )

    assert_checkpoint_deployment_trust(
        checkpoint_manifest=bundle.manifest,
        lifecycle_descriptor=descriptor,
        profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
    )
    assert production_lifecycle_descriptor_allowed(
        checkpoint_manifest=bundle.manifest,
        lifecycle_descriptor=descriptor,
    ) is True


def test_local_lifecycle_provider_rejected_with_production_shaped_checkpoint_manifest() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    descriptor = _production_descriptor(
        anchor_provider_id=_anchor_provider_id(bundle.manifest),
        provider_id="local-sqlite-agent-checkpoint-lifecycle",
        kind=TrustProviderKind.LOCAL_SYNTHETIC,
        independent_failure_domain=False,
        synthetic_in_process=True,
        operationally_external=False,
        production_runtime_eligible=False,
    )

    with pytest.raises(CheckpointLifecycleTrustBoundaryError) as raised:
        assert_checkpoint_deployment_trust(
            checkpoint_manifest=bundle.manifest,
            lifecycle_descriptor=descriptor,
            profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
        )

    assert raised.value.reason is CheckpointLifecycleTrustReason.LOCAL_PROVIDER_IN_PRODUCTION


def test_synthetic_p4j_lifecycle_provider_cannot_satisfy_production_trust() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    provider = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    descriptor = describe_checkpoint_lifecycle_provider(
        provider,
        kind=TrustProviderKind.EXTERNAL,
        independent_failure_domain=True,
    )

    assert descriptor.anchor_provider_id == _anchor_provider_id(bundle.manifest)
    assert descriptor.synthetic_in_process is True
    assert descriptor.operationally_external is False
    assert descriptor.production_runtime_eligible is False

    with pytest.raises(CheckpointLifecycleTrustBoundaryError) as raised:
        assert_checkpoint_deployment_trust(
            checkpoint_manifest=bundle.manifest,
            lifecycle_descriptor=descriptor,
            profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
        )

    assert raised.value.reason is CheckpointLifecycleTrustReason.SYNTHETIC_PROVIDER_IN_PRODUCTION
    assert production_lifecycle_descriptor_allowed(
        checkpoint_manifest=bundle.manifest,
        lifecycle_descriptor=descriptor,
    ) is False


def test_lifecycle_anchor_and_capability_requirements_fail_closed() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    anchor_provider_id = _anchor_provider_id(bundle.manifest)

    with pytest.raises(CheckpointLifecycleTrustBoundaryError) as anchor_raised:
        assert_checkpoint_deployment_trust(
            checkpoint_manifest=bundle.manifest,
            lifecycle_descriptor=_production_descriptor(
                anchor_provider_id="wrong-external-anchor"
            ),
            profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
        )
    assert anchor_raised.value.reason is CheckpointLifecycleTrustReason.ANCHOR_PROVIDER_MISMATCH

    with pytest.raises(CheckpointLifecycleTrustBoundaryError) as capability_raised:
        assert_checkpoint_deployment_trust(
            checkpoint_manifest=bundle.manifest,
            lifecycle_descriptor=_production_descriptor(
                anchor_provider_id=anchor_provider_id,
                capabilities=frozenset(
                    {
                        CheckpointLifecycleCapability.MIGRATION,
                        CheckpointLifecycleCapability.SNAPSHOT,
                    }
                ),
            ),
            profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
        )
    assert capability_raised.value.reason is CheckpointLifecycleTrustReason.CAPABILITY_REQUIRED
    assert capability_raised.value.capability is CheckpointLifecycleCapability.RESTORE


def test_p4k_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    baseline = report["variants"]["implicit_lifecycle_trust_baseline"]["metrics"]
    hardened = report["variants"]["lifecycle_deployment_trust_boundary"]["metrics"]

    assert report["passed"] is True
    assert baseline["asr"] == [5, 5]
    assert hardened["asr"] == [0, 5]
    assert hardened["fpr"] == [0, 2]
    assert hardened["safe_task_rate"] == [2, 2]
    assert report["p4f_surface_count_unchanged"] == 5
    assert report["lifecycle_trust_extension_separate_from_p4f_v1"] is True
    assert report["external_descriptor_contract_accepted"] is True
    assert report["synthetic_p4j_production_trust_allowed"] is False
    assert report["production_external_lifecycle_provider_included"] is False
    assert report["production_checkpoint_lifecycle_claim"] is False
    assert report["real_external_trust_operations"] is False
    assert report["network_operations"] == 0
