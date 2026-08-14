from __future__ import annotations

import hashlib
import json

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


_ADVERSARIAL_CASES = (
    {
        "attempt_id": "P4K-A1-local-lifecycle-provider-production",
        "scenario": "production-shaped checkpoint trust with local lifecycle coordinator",
    },
    {
        "attempt_id": "P4K-A2-synthetic-external-style-lifecycle",
        "scenario": "synthetic in-process lifecycle coordinator presented as external contract",
    },
    {
        "attempt_id": "P4K-A3-lifecycle-anchor-provider-mismatch",
        "scenario": "lifecycle coordinator bound to a different monotonic-anchor provider",
    },
    {
        "attempt_id": "P4K-A4-incomplete-lifecycle-capabilities",
        "scenario": "lifecycle coordinator omits restore authority",
    },
    {
        "attempt_id": "P4K-A5-lifecycle-shares-failure-domain",
        "scenario": "external lifecycle coordinator lacks an independent failure domain",
    },
)

_BENIGN_CASES = (
    {
        "attempt_id": "P4K-B1-explicit-local-lab-lifecycle",
        "scenario": "local synthetic checkpoint and lifecycle trust under the local lab profile",
    },
    {
        "attempt_id": "P4K-B2-complete-external-lifecycle-descriptor-contract",
        "scenario": "complete external checkpoint and lifecycle descriptor posture",
    },
)


def _dataset_hash() -> str:
    payload = json.dumps(
        {"adversarial": _ADVERSARIAL_CASES, "benign": _BENIGN_CASES},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _anchor_provider_id(manifest) -> str:
    return next(
        provider.provider_id
        for provider in manifest.providers
        if provider.surface is CheckpointTrustSurface.MONOTONIC_ANCHOR
    )


def _external_descriptor(
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


def _rejection(manifest, descriptor) -> str | None:
    try:
        assert_checkpoint_deployment_trust(
            checkpoint_manifest=manifest,
            lifecycle_descriptor=descriptor,
            profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
        )
    except CheckpointLifecycleTrustBoundaryError as exc:
        return exc.reason.value
    return None


def build_report() -> dict[str, object]:
    external_bundle = build_synthetic_external_checkpoint_contract_bundle()
    external_anchor_id = _anchor_provider_id(external_bundle.manifest)

    local_presented_against_external_anchor = _external_descriptor(
        anchor_provider_id=external_anchor_id,
        provider_id="local-sqlite-agent-checkpoint-lifecycle",
        kind=TrustProviderKind.LOCAL_SYNTHETIC,
        independent_failure_domain=False,
        synthetic_in_process=True,
        operationally_external=False,
        production_runtime_eligible=False,
    )

    external_bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(external_bundle.anchor)
    synthetic_external_lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(
        anchor_provider=external_bridge
    )
    synthetic_external_descriptor = describe_checkpoint_lifecycle_provider(
        synthetic_external_lifecycle,
        kind=TrustProviderKind.EXTERNAL,
        independent_failure_domain=True,
    )

    mismatched_anchor_descriptor = _external_descriptor(
        anchor_provider_id="different-external-checkpoint-anchor"
    )
    incomplete_descriptor = _external_descriptor(
        anchor_provider_id=external_anchor_id,
        capabilities=frozenset(
            {
                CheckpointLifecycleCapability.MIGRATION,
                CheckpointLifecycleCapability.SNAPSHOT,
            }
        ),
    )
    shared_failure_domain_descriptor = _external_descriptor(
        anchor_provider_id=external_anchor_id,
        independent_failure_domain=False,
    )
    complete_external_descriptor = _external_descriptor(
        anchor_provider_id=external_anchor_id
    )

    hardened_cases = (
        ("P4K-A1-local-lifecycle-provider-production", local_presented_against_external_anchor),
        ("P4K-A2-synthetic-external-style-lifecycle", synthetic_external_descriptor),
        ("P4K-A3-lifecycle-anchor-provider-mismatch", mismatched_anchor_descriptor),
        ("P4K-A4-incomplete-lifecycle-capabilities", incomplete_descriptor),
        ("P4K-A5-lifecycle-shares-failure-domain", shared_failure_domain_descriptor),
    )
    hardened_adversarial = [
        {
            "attempt_id": attempt_id,
            "success": rejection is None,
            "rejection": rejection,
        }
        for attempt_id, descriptor in hardened_cases
        for rejection in [_rejection(external_bundle.manifest, descriptor)]
    ]

    local_factory = LocalSyntheticCheckpointOperationProviderFactory()
    local_allowed = True
    try:
        local_factory.manifest.assert_allowed(TrustDeploymentProfile.LOCAL_SYNTHETIC)
    except Exception:
        local_allowed = False

    external_contract_allowed = production_lifecycle_descriptor_allowed(
        checkpoint_manifest=external_bundle.manifest,
        lifecycle_descriptor=complete_external_descriptor,
    )

    hardened_benign = [
        {
            "attempt_id": "P4K-B1-explicit-local-lab-lifecycle",
            "incorrectly_blocked": not local_allowed,
            "safe_completion": local_allowed,
        },
        {
            "attempt_id": "P4K-B2-complete-external-lifecycle-descriptor-contract",
            "incorrectly_blocked": not external_contract_allowed,
            "safe_completion": external_contract_allowed,
        },
    ]

    baseline_adversarial = [
        {"attempt_id": case["attempt_id"], "success": True}
        for case in _ADVERSARIAL_CASES
    ]

    hardened_asr = [
        sum(1 for item in hardened_adversarial if item["success"]),
        len(hardened_adversarial),
    ]
    baseline_asr = [len(baseline_adversarial), len(baseline_adversarial)]
    hardened_fpr = [
        sum(1 for item in hardened_benign if item["incorrectly_blocked"]),
        len(hardened_benign),
    ]
    hardened_safe_task_rate = [
        sum(1 for item in hardened_benign if item["safe_completion"]),
        len(hardened_benign),
    ]

    expected_rejections = [
        CheckpointLifecycleTrustReason.LOCAL_PROVIDER_IN_PRODUCTION.value,
        CheckpointLifecycleTrustReason.SYNTHETIC_PROVIDER_IN_PRODUCTION.value,
        CheckpointLifecycleTrustReason.ANCHOR_PROVIDER_MISMATCH.value,
        CheckpointLifecycleTrustReason.CAPABILITY_REQUIRED.value,
        CheckpointLifecycleTrustReason.INDEPENDENT_FAILURE_DOMAIN_REQUIRED.value,
    ]
    observed_rejections = [item["rejection"] for item in hardened_adversarial]

    report: dict[str, object] = {
        "evaluation": "P4-K checkpoint lifecycle deployment trust-provider boundary",
        "policy_version": P4K_CHECKPOINT_LIFECYCLE_TRUST_POLICY_VERSION,
        "p4f_policy_version": P4F_CHECKPOINT_TRUST_POLICY_VERSION,
        "eval_dataset_hash_sha256": _dataset_hash(),
        "p4f_surface_count_unchanged": len(CheckpointTrustSurface),
        "lifecycle_trust_extension_separate_from_p4f_v1": True,
        "local_lifecycle_posture": local_factory.lifecycle_trust_descriptor().public_posture(),
        "synthetic_p4j_lifecycle_posture": synthetic_external_descriptor.public_posture(),
        "production_external_lifecycle_provider_included": False,
        "production_checkpoint_lifecycle_claim": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "external_descriptor_contract_accepted": external_contract_allowed,
        "synthetic_p4j_production_trust_allowed": production_lifecycle_descriptor_allowed(
            checkpoint_manifest=external_bundle.manifest,
            lifecycle_descriptor=synthetic_external_descriptor,
        ),
        "variants": {
            "implicit_lifecycle_trust_baseline": {
                "adversarial_attempts": baseline_adversarial,
                "metrics": {"asr": baseline_asr},
            },
            "lifecycle_deployment_trust_boundary": {
                "adversarial_attempts": hardened_adversarial,
                "benign_attempts": hardened_benign,
                "metrics": {
                    "asr": hardened_asr,
                    "fpr": hardened_fpr,
                    "safe_task_rate": hardened_safe_task_rate,
                },
            },
        },
    }
    report["passed"] = (
        baseline_asr == [5, 5]
        and hardened_asr == [0, 5]
        and hardened_fpr == [0, 2]
        and hardened_safe_task_rate == [2, 2]
        and observed_rejections == expected_rejections
        and local_allowed
        and external_contract_allowed
        and report["p4f_surface_count_unchanged"] == 5
        and report["synthetic_p4j_production_trust_allowed"] is False
        and report["production_external_lifecycle_provider_included"] is False
        and report["production_checkpoint_lifecycle_claim"] is False
        and report["real_external_trust_operations"] is False
        and report["network_operations"] == 0
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
