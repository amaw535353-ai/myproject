from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.assurance.corpus_evolution import (
    AssuranceCorpusEvolutionGate,
    CorpusEvolutionRejected,
    change_manifest_digest,
)
from aegis.assurance.regression import corpus_digest
from evals.p6c_corpus_evolution import (
    adversarial_cases,
    benign_cases,
    default_fixture,
    dataset_digest,
    fixture_digest,
    manifest_for,
    request_for,
    run_evaluation,
)


@pytest.mark.parametrize("name,expected_reason,scenario", adversarial_cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_p6c_adversarial_cases_are_rejected(name, expected_reason, scenario):
    gate = AssuranceCorpusEvolutionGate(policy=scenario["policy"])
    with pytest.raises(CorpusEvolutionRejected) as exc:
        gate.evaluate(
            request=scenario["request"],
            baseline=scenario["baseline"],
            candidate=scenario["candidate"],
            manifest=scenario["manifest"],
        )
    assert exc.value.reason == expected_reason


@pytest.mark.parametrize("name,scenario", benign_cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_p6c_benign_corpus_evolution_is_accepted(name, scenario):
    gate = AssuranceCorpusEvolutionGate(policy=scenario["policy"])
    verified = gate.evaluate(
        request=scenario["request"],
        baseline=scenario["baseline"],
        candidate=scenario["candidate"],
        manifest=scenario["manifest"],
    )
    assert verified.corpus_id == scenario["candidate"].corpus_id
    assert verified.candidate_corpus_sha256 == corpus_digest(scenario["candidate"])
    assert verified.change_manifest_sha256 == change_manifest_digest(scenario["manifest"])
    assert verified.network_operations == 0


def test_p6c_deterministic_metrics_and_hashes():
    result = run_evaluation()
    assert result["metrics"] == {
        "adversarial_cases": 22,
        "vulnerable_asr": "22/22",
        "hardened_asr": "0/22",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }
    assert dataset_digest() == "623e5eaf40beaab1f0af141652319cab35cd1344d9526109605716a8360ff2c3"
    assert fixture_digest() == "6b1ff5de5ab5bd07d83de010509a08ae531cf5e8ee633fddff83c84124a838a3"
    assert result["baseline_corpus_sha256"] == "8d4a161ae662246c2d49b5457f2b9a69684033a8494fb44b273e57b362e34738"


def test_p6c_verified_evidence_preserves_claim_boundaries():
    fixture = default_fixture()
    verified = AssuranceCorpusEvolutionGate(policy=fixture["policy"]).evaluate(
        request=fixture["request"],
        baseline=fixture["baseline"],
        candidate=fixture["candidate"],
        manifest=fixture["manifest"],
    )
    assert verified.exact_change_coverage_verified is True
    assert verified.removal_tombstones_verified is True
    assert verified.coverage_floors_verified is True
    assert verified.weakening_prevented is True
    assert verified.silent_coverage_shrink_prevented is True
    assert verified.formal_verification is False
    assert verified.exhaustive_attack_coverage is False
    assert verified.production_change_management is False
    assert verified.network_operations == 0


def test_p6c_manifest_digest_is_order_independent():
    fixture = default_fixture()
    manifest = fixture["manifest"]
    reordered = replace(
        manifest,
        changes=tuple(reversed(manifest.changes)),
        tombstones=tuple(reversed(manifest.tombstones)),
    )
    assert change_manifest_digest(reordered) == change_manifest_digest(manifest)


def test_p6c_candidate_case_order_is_not_security_relevant():
    fixture = default_fixture()
    baseline = fixture["baseline"]
    candidate = replace(fixture["candidate"], cases=tuple(reversed(fixture["candidate"].cases)))
    manifest = manifest_for(baseline, candidate)
    request = request_for(candidate, manifest)
    verified = AssuranceCorpusEvolutionGate(policy=fixture["policy"]).evaluate(
        request=request,
        baseline=baseline,
        candidate=candidate,
        manifest=manifest,
    )
    assert verified.candidate_case_count == len(candidate.cases)
    assert verified.candidate_corpus_sha256 == corpus_digest(candidate)
