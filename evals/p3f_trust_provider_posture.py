from __future__ import annotations

import hashlib
import json

from aegis.effects.trust_providers import (
    LOCAL_SYNTHETIC_TRUST_MANIFEST,
    TrustBoundaryError,
    TrustDeploymentProfile,
    TrustProviderDescriptor,
    TrustProviderKind,
    TrustProviderManifest,
    TrustSurface,
)


def _external_contract_manifest() -> TrustProviderManifest:
    return TrustProviderManifest(
        providers=tuple(
            TrustProviderDescriptor(
                surface=surface,
                provider_id=f"external-contract-{surface.value}",
                kind=TrustProviderKind.EXTERNAL,
                independent_failure_domain=True,
                external_key_custody=surface
                in {
                    TrustSurface.AUTHORIZATION_SIGNING,
                    TrustSurface.CHECKPOINT_RECEIPT_SOURCE,
                },
            )
            for surface in TrustSurface
        )
    )


def build_report() -> dict[str, object]:
    surfaces = tuple(surface.value for surface in TrustSurface)
    local_manifest = LOCAL_SYNTHETIC_TRUST_MANIFEST
    external_manifest = _external_contract_manifest()

    local_allowed = True
    try:
        local_manifest.assert_allowed(TrustDeploymentProfile.LOCAL_SYNTHETIC)
    except TrustBoundaryError:
        local_allowed = False

    production_with_local_allowed = True
    try:
        local_manifest.assert_allowed(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
    except TrustBoundaryError:
        production_with_local_allowed = False

    external_contract_allowed = True
    try:
        external_manifest.assert_allowed(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
    except TrustBoundaryError:
        external_contract_allowed = False

    baseline = [
        {"surface": surface, "implicit_production_claim": True}
        for surface in surfaces
    ]
    hardened = [
        {
            "surface": surface,
            "local_provider_accepted_for_production": production_with_local_allowed,
        }
        for surface in surfaces
    ]
    benign = [
        {"case": "explicit_local_synthetic_profile", "safe_completion": local_allowed},
        {"case": "external_provider_contract_profile", "safe_completion": external_contract_allowed},
    ]

    baseline_asr = sum(bool(item["implicit_production_claim"]) for item in baseline)
    hardened_asr = sum(bool(item["local_provider_accepted_for_production"]) for item in hardened)
    false_positives = sum(not bool(item["safe_completion"]) for item in benign)
    safe = sum(bool(item["safe_completion"]) for item in benign)
    dataset = json.dumps(
        {"surfaces": surfaces, "benign_cases": [item["case"] for item in benign]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    metrics = {
        "implicit_baseline_asr": [baseline_asr, len(surfaces)],
        "hardened_asr": [hardened_asr, len(surfaces)],
        "hardened_fpr": [false_positives, len(benign)],
        "hardened_safe_task_rate": [safe, len(benign)],
    }
    passed = metrics == {
        "implicit_baseline_asr": [4, 4],
        "hardened_asr": [0, 4],
        "hardened_fpr": [0, 2],
        "hardened_safe_task_rate": [2, 2],
    }
    return {
        "evaluation": "P3-F explicit production trust-provider posture",
        "dataset_sha256": hashlib.sha256(dataset).hexdigest(),
        "metrics": metrics,
        "local_manifest": local_manifest.public_posture(),
        "production_trust_claim_allowed_by_default": local_manifest.production_trust_claim_allowed(),
        "external_contract_implementation_included": False,
        "real_external_trust_operations": False,
        "passed": passed,
    }


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
