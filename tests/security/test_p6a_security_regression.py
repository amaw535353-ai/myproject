from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.assurance.regression import (
    AssuranceExpectation,
    AssuranceRejected,
    ContinuousSecurityAssuranceGate,
    VerifiedAssuranceEvidence,
    corpus_digest,
)
from evals.p6a_security_regression import (
    RUNNER_ID,
    adversarial_cases,
    benign_cases,
    dataset_digest,
    default_fixture,
    fixture_digest,
    run_evaluation,
)


@pytest.mark.parametrize("name,expected_reason,overrides", adversarial_cases())
def test_p6a_adversarial_cases_fail_closed(name, expected_reason, overrides):
    fixture = default_fixture()
    corpus = overrides.get("corpus", fixture["corpus"])
    policy = overrides.get("policy", fixture["policy"])
    baseline = overrides.get("baseline", fixture["baseline"])
    candidate = overrides.get("candidate", fixture["candidate"])
    request = overrides.get("request", fixture["request"])
    gate = ContinuousSecurityAssuranceGate(corpus=corpus, policy=policy)
    with pytest.raises(AssuranceRejected) as caught:
        gate.evaluate(request=request, baseline=baseline, candidate=candidate)
    assert caught.value.reason == expected_reason, name


@pytest.mark.parametrize("name,candidate", benign_cases())
def test_p6a_benign_cases_remain_usable(name, candidate):
    fixture = default_fixture()
    policy = replace(
        fixture["policy"],
        trusted_runner_ids=frozenset({RUNNER_ID, "aegis-secondary-assurance-runner-v1"}),
    )
    verified = ContinuousSecurityAssuranceGate(corpus=fixture["corpus"], policy=policy).evaluate(
        request=fixture["request"], baseline=fixture["baseline"], candidate=candidate
    )
    assert isinstance(verified, VerifiedAssuranceEvidence), name
    assert verified.regression_count == 0
    assert verified.safe_task_regression_count == 0


def test_p6a_deterministic_metrics():
    result = run_evaluation()
    assert result["adversarial_cases"] == 17
    assert result["vulnerable_asr"] == "17/17"
    assert result["hardened_asr"] == "0/17"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["corpus_case_count"] == 18
    assert result["corpus_boundary_count"] == 9


def test_p6a_deterministic_hashes():
    fixture = default_fixture()
    assert corpus_digest(fixture["corpus"]) == "8d4a161ae662246c2d49b5457f2b9a69684033a8494fb44b273e57b362e34738"
    assert dataset_digest() == "eefe9b1b9bab0332de4fbb0039644e02dabdc52fbd27a7407e100806aa7ce9a1"
    assert fixture_digest() == "90ff835b2d646937ed955c1a4a912f8e9003f47cf2890e0491c1f4ff334e3f42"


def test_p6a_verified_handle_has_explicit_nonclaims():
    fixture = default_fixture()
    verified = ContinuousSecurityAssuranceGate(
        corpus=fixture["corpus"], policy=fixture["policy"]
    ).evaluate(
        request=fixture["request"], baseline=fixture["baseline"], candidate=fixture["candidate"]
    )
    assert verified.exact_case_coverage_verified
    assert verified.case_definitions_verified
    assert verified.required_boundaries_verified
    assert verified.baseline_verified
    assert verified.candidate_verified
    assert not verified.aggregate_score_only
    assert not verified.formal_verification
    assert not verified.exhaustive_attack_coverage
    assert not verified.production_ci_attestation
    assert verified.network_operations == 0


def test_p6a_results_are_order_independent_but_definition_bound():
    fixture = default_fixture()
    first = ContinuousSecurityAssuranceGate(
        corpus=fixture["corpus"], policy=fixture["policy"]
    ).evaluate(
        request=fixture["request"], baseline=fixture["baseline"], candidate=fixture["candidate"]
    )
    reordered = replace(fixture["candidate"], results=tuple(reversed(fixture["candidate"].results)))
    second = ContinuousSecurityAssuranceGate(
        corpus=fixture["corpus"], policy=fixture["policy"]
    ).evaluate(request=fixture["request"], baseline=fixture["baseline"], candidate=reordered)
    assert first.evidence_sha256 == second.evidence_sha256
    assert all(
        case.expectation in {AssuranceExpectation.BLOCK, AssuranceExpectation.ALLOW}
        for case in fixture["corpus"].cases
    )
