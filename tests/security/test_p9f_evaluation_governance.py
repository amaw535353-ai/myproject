from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.training.evaluation_governance_security import EvaluationBenchmarkGovernanceAnalyzer
from aegis.training.evaluation_governance_types import *
from evals.p9f_evaluation_governance import adversarial_cases, clean_cases
from evals.p9f_fixture import *


def evaluate(case):
    return EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).evaluate(
        case["request"], case["manifest"], case["p9e"]
    )


def test_clean_fixture_allows_and_sets_claim_boundaries():
    assessment = evaluate(build_fixture())
    assert assessment.decision == EvaluationDecision.ALLOW
    assert assessment.risks == ()
    assert assessment.upstream_p9e_bound
    assert assessment.benchmark_provenance_verified
    assert assessment.contamination_checks_clear
    assert assessment.protocol_verified
    assert assessment.result_evidence_bound
    assert assessment.performance_claim_admissible
    assert not assessment.caller_declared_safety_trusted
    assert not assessment.production_benchmark_registry_integrated
    assert not assessment.semantic_near_duplicate_detection_validated
    assert not assessment.score_recomputed_from_model_outputs
    assert not assessment.hidden_benchmark_secrecy_proven


def test_training_exposure_digest_is_order_independent():
    a = training_exposure_digest(P9E_ASSESSMENT_SHA, TRAINING_RECORD_IDS, TRAIN_CANON, TRAIN_TRANSFORM)
    b = training_exposure_digest(
        P9E_ASSESSMENT_SHA,
        tuple(reversed(TRAINING_RECORD_IDS)),
        tuple(reversed(TRAIN_CANON)),
        tuple(reversed(TRAIN_TRANSFORM)),
    )
    assert a == b == TRAINING_EXPOSURE_SHA


def test_snapshot_digest_changes_with_record_evidence():
    fixture = build_fixture()
    benchmark = fixture["manifest"].benchmark
    record = replace(benchmark.records[0], payload_sha256=h("changed"))
    changed = replace(benchmark, records=(record,) + benchmark.records[1:], snapshot_sha256="0"*64)
    assert benchmark_snapshot_digest(changed) != benchmark.snapshot_sha256


@pytest.mark.parametrize("case", clean_cases())
def test_clean_safe_cases(case):
    assert evaluate(case).decision == EvaluationDecision.ALLOW


def test_all_adversarial_cases_block_hardened():
    cases = adversarial_cases()
    assert len(cases) >= 80
    for name, case in cases:
        try:
            assessment = evaluate(case)
        except EvaluationSecurityRejected:
            continue
        assert assessment.decision == EvaluationDecision.DENY, name
        assert not assessment.performance_claim_admissible, name


def test_record_id_overlap_is_detected_when_policy_digest_rebound():
    fixture = build_fixture()
    records = list(fixture["manifest"].benchmark.records)
    records[0] = replace(records[0], record_id=TRAINING_RECORD_IDS[0])
    b0 = replace(fixture["manifest"].benchmark, records=tuple(records), snapshot_sha256="0"*64)
    b = replace(b0, snapshot_sha256=benchmark_snapshot_digest(b0))
    case = rebind(fixture, manifest=replace(fixture["manifest"], benchmark=b))
    risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
    assert EvaluationRisk.RECORD_ID_OVERLAP in risks


def test_canonical_fingerprint_overlap_is_detected():
    fixture = build_fixture()
    records = list(fixture["manifest"].benchmark.records)
    records[0] = replace(records[0], canonical_fingerprint_sha256=TRAIN_CANON[0])
    b0 = replace(fixture["manifest"].benchmark, records=tuple(records), snapshot_sha256="0"*64)
    b = replace(b0, snapshot_sha256=benchmark_snapshot_digest(b0))
    case = rebind(fixture, manifest=replace(fixture["manifest"], benchmark=b))
    risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
    assert EvaluationRisk.CANONICAL_FINGERPRINT_OVERLAP in risks


def test_transform_fingerprint_overlap_is_detected():
    fixture = build_fixture()
    records = list(fixture["manifest"].benchmark.records)
    records[0] = replace(records[0], transform_fingerprint_sha256=TRAIN_TRANSFORM[0])
    b0 = replace(fixture["manifest"].benchmark, records=tuple(records), snapshot_sha256="0"*64)
    b = replace(b0, snapshot_sha256=benchmark_snapshot_digest(b0))
    case = rebind(fixture, manifest=replace(fixture["manifest"], benchmark=b))
    risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
    assert EvaluationRisk.TRANSFORM_FINGERPRINT_OVERLAP in risks


def test_training_derivation_leak_is_detected():
    fixture = build_fixture()
    records = list(fixture["manifest"].benchmark.records)
    records[0] = replace(records[0], derived_from_training_record_id=TRAINING_RECORD_IDS[0])
    b0 = replace(fixture["manifest"].benchmark, records=tuple(records), snapshot_sha256="0"*64)
    b = replace(b0, snapshot_sha256=benchmark_snapshot_digest(b0))
    case = rebind(fixture, manifest=replace(fixture["manifest"], benchmark=b))
    risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
    assert EvaluationRisk.TRAINING_DERIVATION_LEAK in risks


def test_hidden_label_exposure_is_detected():
    fixture = build_fixture()
    b0 = replace(fixture["manifest"].benchmark, labels_exposed_to_training=True, snapshot_sha256="0"*64)
    b = replace(b0, snapshot_sha256=benchmark_snapshot_digest(b0))
    case = rebind(fixture, manifest=replace(fixture["manifest"], benchmark=b))
    risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
    assert EvaluationRisk.HIDDEN_LABEL_EXPOSURE in risks


def test_dynamic_or_external_data_is_detected():
    fixture = build_fixture()
    for field in ("dynamic_generation", "external_fetch"):
        b0 = replace(fixture["manifest"].benchmark, **{field: True}, snapshot_sha256="0"*64)
        b = replace(b0, snapshot_sha256=benchmark_snapshot_digest(b0))
        case = rebind(fixture, manifest=replace(fixture["manifest"], benchmark=b))
        risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
        assert EvaluationRisk.DYNAMIC_OR_EXTERNAL_DATA in risks


def test_test_record_cannot_be_fewshot_example():
    fixture = build_fixture()
    proto = replace(fixture["manifest"].protocol, fewshot_example_ids=(EVAL_RECORD_IDS[0],))
    case = rebind(fixture, manifest=replace(fixture["manifest"], protocol=proto))
    risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
    assert EvaluationRisk.FEWSHOT_CONFIG_MISMATCH in risks


def test_result_score_inflation_is_not_admissible():
    fixture = build_fixture()
    result = replace(fixture["manifest"].result, score_basis_points=9999)
    case = rebind(fixture, manifest=replace(fixture["manifest"], result=result))
    risks = EvaluationBenchmarkGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9e"])
    assert EvaluationRisk.RESULT_EVIDENCE_MISMATCH in risks


def test_request_cannot_override_contaminated_evidence():
    fixture = build_fixture()
    records = list(fixture["manifest"].benchmark.records)
    records[0] = replace(records[0], canonical_fingerprint_sha256=TRAIN_CANON[0])
    b0 = replace(fixture["manifest"].benchmark, records=tuple(records), snapshot_sha256="0"*64)
    b = replace(b0, snapshot_sha256=benchmark_snapshot_digest(b0))
    case = rebind(fixture, manifest=replace(fixture["manifest"], benchmark=b))
    with pytest.raises(EvaluationSecurityRejected) as exc:
        evaluate(case)
    assert exc.value.reason == EvaluationRejectReason.DECLARED_SUMMARY_MISMATCH


def test_stale_request_rejected():
    fixture = build_fixture()
    case = rebind(fixture, evaluated_at_epoch=NOW + 301)
    with pytest.raises(EvaluationSecurityRejected) as exc:
        evaluate(case)
    assert exc.value.reason == EvaluationRejectReason.REQUEST_INVALID


def test_policy_rejects_non_sha_pin():
    fixture = build_fixture()
    bad = replace(fixture["policy"], expected_manifest_sha256="bad")
    with pytest.raises(EvaluationSecurityRejected) as exc:
        EvaluationBenchmarkGovernanceAnalyzer(bad)
    assert exc.value.reason == EvaluationRejectReason.POLICY_INVALID


def test_manifest_schema_rejected():
    fixture = build_fixture()
    manifest = replace(fixture["manifest"], schema_version="wrong")
    policy = replace(fixture["policy"], expected_manifest_sha256=evaluation_benchmark_manifest_digest(manifest))
    with pytest.raises(EvaluationSecurityRejected) as exc:
        EvaluationBenchmarkGovernanceAnalyzer(policy).evaluate(
            replace(fixture["request"], manifest_sha256=evaluation_benchmark_manifest_digest(manifest)),
            manifest,
            fixture["p9e"],
        )
    assert exc.value.reason == EvaluationRejectReason.MANIFEST_INVALID


def test_assessment_digest_is_deterministic():
    fixture = build_fixture()
    first = evaluate(fixture)
    second = evaluate(fixture)
    assert first.assessment_evidence_sha256 == second.assessment_evidence_sha256
