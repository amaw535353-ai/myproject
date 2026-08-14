from __future__ import annotations

import hashlib
import json
from typing import Any

from aegis.agent.checkpoint_trust import (
    LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST,
    CheckpointTrustBoundaryError,
    CheckpointTrustProviderDescriptor,
    CheckpointTrustProviderManifest,
    CheckpointTrustReason,
    CheckpointTrustSurface,
)
from aegis.effects.trust_providers import TrustDeploymentProfile, TrustProviderKind


ADVERSARIAL_CASES = (
    "P4F-A1-local-encryption-key-custody",
    "P4F-A2-external-integrity-without-key-custody",
    "P4F-A3-external-anchor-without-rollback-resistant-state",
    "P4F-A4-external-backup-auth-without-key-custody",
    "P4F-A5-external-recovery-without-recovery-authority",
)
BENIGN_CASES = (
    "P4F-B1-explicit-local-synthetic-profile",
    "P4F-B2-complete-external-contract-profile",
)


def _external_descriptor(surface: CheckpointTrustSurface) -> CheckpointTrustProviderDescriptor:
    key_surfaces = {
        CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY,
        CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY,
        CheckpointTrustSurface.BACKUP_AUTHENTICATION,
    }
    return CheckpointTrustProviderDescriptor(
        surface=surface,
        provider_id=f"external-contract-{surface.value}",
        kind=TrustProviderKind.EXTERNAL,
        independent_failure_domain=True,
        external_key_custody=surface in key_surfaces,
        rollback_resistant_state=surface is CheckpointTrustSurface.MONOTONIC_ANCHOR,
        external_recovery_authority=surface is CheckpointTrustSurface.RECOVERY_AUTHORITY,
    )


def _external_contract_manifest() -> CheckpointTrustProviderManifest:
    return CheckpointTrustProviderManifest(
        providers=tuple(_external_descriptor(surface) for surface in CheckpointTrustSurface)
    )


def _manifest_with_replacement(
    replacement: CheckpointTrustProviderDescriptor,
) -> CheckpointTrustProviderManifest:
    return CheckpointTrustProviderManifest(
        providers=tuple(
            replacement if surface is replacement.surface else _external_descriptor(surface)
            for surface in CheckpointTrustSurface
        )
    )


def _adversarial_manifests() -> tuple[tuple[str, CheckpointTrustProviderManifest, CheckpointTrustReason], ...]:
    return (
        (
            ADVERSARIAL_CASES[0],
            _manifest_with_replacement(
                CheckpointTrustProviderDescriptor(
                    surface=CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY,
                    provider_id="local-checkpoint-encryption",
                    kind=TrustProviderKind.LOCAL_SYNTHETIC,
                    independent_failure_domain=False,
                )
            ),
            CheckpointTrustReason.LOCAL_PROVIDER_IN_PRODUCTION,
        ),
        (
            ADVERSARIAL_CASES[1],
            _manifest_with_replacement(
                CheckpointTrustProviderDescriptor(
                    surface=CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY,
                    provider_id="external-integrity-without-custody",
                    kind=TrustProviderKind.EXTERNAL,
                    independent_failure_domain=True,
                    external_key_custody=False,
                )
            ),
            CheckpointTrustReason.EXTERNAL_KEY_CUSTODY_REQUIRED,
        ),
        (
            ADVERSARIAL_CASES[2],
            _manifest_with_replacement(
                CheckpointTrustProviderDescriptor(
                    surface=CheckpointTrustSurface.MONOTONIC_ANCHOR,
                    provider_id="external-anchor-without-rollback-state",
                    kind=TrustProviderKind.EXTERNAL,
                    independent_failure_domain=True,
                    rollback_resistant_state=False,
                )
            ),
            CheckpointTrustReason.ROLLBACK_RESISTANT_STATE_REQUIRED,
        ),
        (
            ADVERSARIAL_CASES[3],
            _manifest_with_replacement(
                CheckpointTrustProviderDescriptor(
                    surface=CheckpointTrustSurface.BACKUP_AUTHENTICATION,
                    provider_id="external-backup-auth-without-custody",
                    kind=TrustProviderKind.EXTERNAL,
                    independent_failure_domain=True,
                    external_key_custody=False,
                )
            ),
            CheckpointTrustReason.EXTERNAL_KEY_CUSTODY_REQUIRED,
        ),
        (
            ADVERSARIAL_CASES[4],
            _manifest_with_replacement(
                CheckpointTrustProviderDescriptor(
                    surface=CheckpointTrustSurface.RECOVERY_AUTHORITY,
                    provider_id="external-recovery-without-authority",
                    kind=TrustProviderKind.EXTERNAL,
                    independent_failure_domain=True,
                    external_recovery_authority=False,
                )
            ),
            CheckpointTrustReason.EXTERNAL_RECOVERY_AUTHORITY_REQUIRED,
        ),
    )


def _dataset_hash() -> str:
    payload = {
        "adversarial": ADVERSARIAL_CASES,
        "benign": BENIGN_CASES,
        "surfaces": tuple(surface.value for surface in CheckpointTrustSurface),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _attempt(manifest: CheckpointTrustProviderManifest, expected: CheckpointTrustReason) -> tuple[bool, str | None]:
    try:
        manifest.assert_allowed(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
    except CheckpointTrustBoundaryError as exc:
        return False, exc.reason.value
    return True, None


def build_report() -> dict[str, Any]:
    baseline = [
        {"attempt_id": case_id, "success": True}
        for case_id in ADVERSARIAL_CASES
    ]
    hardened: list[dict[str, Any]] = []
    expected_rejections: list[str] = []
    for case_id, manifest, expected in _adversarial_manifests():
        success, rejection = _attempt(manifest, expected)
        hardened.append(
            {
                "attempt_id": case_id,
                "success": success,
                "rejection": rejection,
            }
        )
        expected_rejections.append(expected.value)

    local_allowed = True
    try:
        LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST.assert_allowed(
            TrustDeploymentProfile.LOCAL_SYNTHETIC
        )
    except CheckpointTrustBoundaryError:
        local_allowed = False

    external_manifest = _external_contract_manifest()
    external_allowed = True
    try:
        external_manifest.assert_allowed(
            TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
        )
    except CheckpointTrustBoundaryError:
        external_allowed = False

    benign = [
        {
            "attempt_id": BENIGN_CASES[0],
            "safe_completion": local_allowed,
            "incorrectly_blocked": not local_allowed,
        },
        {
            "attempt_id": BENIGN_CASES[1],
            "safe_completion": external_allowed,
            "incorrectly_blocked": not external_allowed,
        },
    ]

    baseline_metrics = {
        "asr": [sum(bool(item["success"]) for item in baseline), len(baseline)]
    }
    hardened_metrics = {
        "asr": [sum(bool(item["success"]) for item in hardened), len(hardened)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }
    observed_rejections = [str(item["rejection"]) for item in hardened]
    report: dict[str, Any] = {
        "evaluation": "P4-F checkpoint deployment trust-provider boundary",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": "checkpoint-deployment-trust-provider-boundary-v1",
        "checkpoint_trust_surfaces": [surface.value for surface in CheckpointTrustSurface],
        "variants": {
            "implicit_local_production_trust_baseline": {
                "adversarial_attempts": baseline,
                "metrics": baseline_metrics,
            },
            "explicit_checkpoint_trust_boundary": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "local_manifest": LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST.public_posture(),
        "production_checkpoint_trust_claim_allowed_by_default": (
            LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST.production_trust_claim_allowed()
        ),
        "external_contract_implementation_included": False,
        "raw_key_bytes_in_report": False,
        "real_external_trust_operations": False,
        "production_checkpoint_runtime_included": False,
    }
    report["passed"] = bool(
        baseline_metrics["asr"] == [5, 5]
        and hardened_metrics["asr"] == [0, 5]
        and hardened_metrics["fpr"] == [0, 2]
        and hardened_metrics["safe_task_rate"] == [2, 2]
        and observed_rejections == expected_rejections
        and report["production_checkpoint_trust_claim_allowed_by_default"] is False
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
