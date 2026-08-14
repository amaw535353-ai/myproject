from __future__ import annotations

import pytest

from aegis.assurance.waiver_governance import (
    SecurityInvariantWaiverGovernanceGate,
    WaiverGovernanceRejected,
)
from evals.p6b_waiver_governance import (
    adversarial_cases,
    benign_cases,
    dataset_digest,
    default_fixture,
    fixture_digest,
    run_evaluation,
)


@pytest.mark.parametrize("name,expected_reason,overrides", adversarial_cases())
def test_adversarial_cases_fail_closed(name, expected_reason, overrides):
    del name
    fixture = default_fixture()
    gate = SecurityInvariantWaiverGovernanceGate(
        corpus=overrides.get("corpus", fixture["corpus"]),
        registry=overrides.get("registry", fixture["registry"]),
        policy=overrides.get("policy", fixture["policy"]),
    )
    with pytest.raises(WaiverGovernanceRejected) as caught:
        gate.evaluate(
            request=overrides.get("request", fixture["request"]),
            candidate=overrides.get("candidate", fixture["candidate"]),
            waivers=overrides.get("waivers", ()),
        )
    assert caught.value.reason == expected_reason


@pytest.mark.parametrize("name,candidate,gov_request,waivers", benign_cases())
def test_benign_cases_remain_usable(name, candidate, gov_request, waivers):
    del name
    fixture = default_fixture()
    verified = SecurityInvariantWaiverGovernanceGate(
        corpus=fixture["corpus"],
        registry=fixture["registry"],
        policy=fixture["policy"],
    ).evaluate(request=gov_request, candidate=candidate, waivers=waivers)
    assert verified.candidate_commit_sha == candidate.commit_sha
    assert verified.critical_waiver_count == 0
    assert verified.production_change_management is False


def test_deterministic_metrics():
    result = run_evaluation()
    assert result["adversarial_cases"] == 25
    assert result["benign_cases"] == 3
    assert result["vulnerable_asr"] == "25/25"
    assert result["hardened_asr"] == "0/25"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert all(
        item["expected_reject_reason"] == item["actual_reject_reason"]
        for item in result["adversarial_results"]
    )


def test_deterministic_hashes_are_stable_within_process():
    assert dataset_digest() == dataset_digest()
    assert fixture_digest() == fixture_digest()
    assert len(dataset_digest()) == 64
    assert len(fixture_digest()) == 64


def test_verified_claim_boundary_is_explicit():
    fixture = default_fixture()
    verified = SecurityInvariantWaiverGovernanceGate(
        corpus=fixture["corpus"],
        registry=fixture["registry"],
        policy=fixture["policy"],
    ).evaluate(
        request=fixture["request"],
        candidate=fixture["candidate"],
        waivers=(),
    )
    assert verified.invariant_definitions_verified is True
    assert verified.invariant_ownership_verified is True
    assert verified.severity_downgrade_prevented is True
    assert verified.critical_waivers_permitted is False
    assert verified.cryptographic_approval_attestation is False
    assert verified.external_ticket_verification is False
    assert verified.network_operations == 0
