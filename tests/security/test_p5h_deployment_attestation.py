from dataclasses import replace

import pytest

from aegis.model_supply_chain.deployment_attestation import (
    DeploymentAttestationRejected,
    DeploymentAttestationVerifier,
    DeploymentAttestationRejectReason,
    privacy_policy_digest,
)
from evals.p5h_deployment_attestation import (
    P5H_DATASET_SHA256,
    P5H_FIXTURE_SHA256,
    attack_cases,
    attestation_policy,
    benign_cases,
    build_report,
    privacy_policy,
    safe_attestation,
    safe_request,
    verified_release,
    verified_runtime,
    verified_scan,
)


def test_p5h_deterministic_metrics() -> None:
    report = build_report()
    assert report["metrics"] == {
        "adversarial_cases": 16,
        "vulnerable_asr": "16/16",
        "hardened_asr": "0/16",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }
    assert len(P5H_DATASET_SHA256) == 64
    assert len(P5H_FIXTURE_SHA256) == 64


@pytest.mark.parametrize("case", attack_cases(), ids=lambda case: case["attempt"].attempt_id)
def test_attack_cases_fail_closed(case) -> None:
    verifier = DeploymentAttestationVerifier(attestation_policy())
    with pytest.raises(DeploymentAttestationRejected):
        verifier.verify(
            request=case["request"],
            release=case["release"],
            runtime=case["runtime"],
            scan=case["scan"],
            privacy_policy=case["privacy_policy"],
            attestation=case["attestation"],
        )


@pytest.mark.parametrize("case", benign_cases(), ids=lambda case: case["attempt"].attempt_id)
def test_benign_cases_verify_without_overclaim(case) -> None:
    handle = DeploymentAttestationVerifier(attestation_policy()).verify(
        request=case["request"],
        release=verified_release(),
        runtime=verified_runtime(),
        scan=verified_scan(),
        privacy_policy=privacy_policy(),
        attestation=case["attestation"],
    )
    assert handle.prior_release_verified
    assert handle.runtime_policy_verified
    assert handle.scan_evidence_verified
    assert handle.privacy_policy_verified
    assert handle.environment_policy_verified
    assert handle.attestor_signature_verified
    assert not handle.hardware_backed_attestation
    assert not handle.transparency_log_verified
    assert not handle.real_remote_attestation
    assert handle.network_operations == 0


def test_privacy_policy_digest_changes_when_policy_changes() -> None:
    baseline = privacy_policy()
    changed = replace(baseline, max_output_tokens=baseline.max_output_tokens + 1)
    assert privacy_policy_digest(baseline) != privacy_policy_digest(changed)


def test_signature_tamper_is_rejected() -> None:
    signed = safe_attestation()
    tampered = replace(signed, signature=b"\x00" * 64)
    with pytest.raises(DeploymentAttestationRejected) as excinfo:
        DeploymentAttestationVerifier(attestation_policy()).verify(
            request=safe_request(),
            release=verified_release(),
            runtime=verified_runtime(),
            scan=verified_scan(),
            privacy_policy=privacy_policy(),
            attestation=tampered,
        )
    assert excinfo.value.reason is DeploymentAttestationRejectReason.SIGNATURE_INVALID
