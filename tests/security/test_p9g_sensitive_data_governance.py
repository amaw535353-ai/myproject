from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.training.evaluation_governance_types import EvaluationDecision
from aegis.training.sensitive_data_security import SensitiveDataGovernanceAnalyzer
from aegis.training.sensitive_data_types import *
from evals.p9g_fixture import NOW, build_fixture, finding, h, rebind
from evals.p9g_sensitive_data_governance import adversarial_cases, run_evaluation


def evaluate(case):
    return SensitiveDataGovernanceAnalyzer(case["policy"]).evaluate(
        case["request"], case["manifest"], case["p9f"]
    )


def derive(case):
    return SensitiveDataGovernanceAnalyzer(case["policy"]).derive(case["manifest"], case["p9f"])


def test_clean_fixture_allows():
    assessment = evaluate(build_fixture())
    assert assessment.decision == SensitiveDataDecision.ALLOW
    assert assessment.risks == ()
    assert assessment.input_governance_verified
    assert assessment.output_governance_verified
    assert assessment.canary_reproduction_clear


def test_clean_claim_boundary_is_explicit():
    assessment = evaluate(build_fixture())
    assert not assessment.caller_declared_safety_trusted
    assert not assessment.production_dlp_integrated
    assert not assessment.comprehensive_pii_detection_validated
    assert not assessment.legal_compliance_verified
    assert not assessment.differential_privacy_verified
    assert not assessment.memorization_absence_proven


def test_all_adversarial_cases_fail_closed():
    for name, case in adversarial_cases():
        try:
            assessment = evaluate(case)
        except SensitiveDataSecurityRejected:
            continue
        assert assessment.decision == SensitiveDataDecision.DENY, name


def test_evaluation_reports_zero_hardened_asr():
    result = run_evaluation()
    assert result["hardened_asr"] == f"0/{result['adversarial_cases']}"
    assert result["hardened_fpr"] == "0/4"
    assert result["safe_task_rate"] == "4/4"


def test_upstream_decision_must_allow():
    base = build_fixture()
    case = rebind(base, p9f=replace(base["p9f"], decision=EvaluationDecision.DENY))
    risks = derive(case)
    assert SensitiveDataRisk.UPSTREAM_P9F_INVALID in risks


def test_upstream_digest_is_bound():
    base = build_fixture()
    case = rebind(base, p9f=replace(base["p9f"], assessment_evidence_sha256=h("wrong")))
    risks = derive(case)
    assert SensitiveDataRisk.UPSTREAM_BINDING_MISMATCH in risks


def test_scanner_profile_is_pinned():
    base = build_fixture()
    manifest = replace(base["manifest"], scanner_profile_sha256=h("other-scanner"))
    risks = derive(rebind(base, manifest=manifest))
    assert SensitiveDataRisk.SCANNER_PROFILE_MISMATCH in risks


def test_canary_registry_is_pinned():
    base = build_fixture()
    manifest = replace(base["manifest"], canary_registry_sha256=h("other-registry"))
    risks = derive(rebind(base, manifest=manifest))
    assert SensitiveDataRisk.CANARY_REGISTRY_MISMATCH in risks


def test_pii_requires_redaction():
    base = build_fixture()
    records = tuple(
        replace(r, sanitized_content_sha256=r.content_sha256, disposition=DataDisposition.ALLOW)
        if r.record_id == "train-pii-01" else r
        for r in base["manifest"].records
    )
    risks = derive(rebind(base, manifest=replace(base["manifest"], records=records)))
    assert SensitiveDataRisk.REDACTION_POLICY_MISMATCH in risks


def test_secret_training_record_requires_quarantine():
    base = build_fixture()
    records = tuple(
        replace(r, included=True, disposition=DataDisposition.ALLOW)
        if r.record_id == "train-secret-01" else r
        for r in base["manifest"].records
    )
    manifest = replace(
        base["manifest"],
        records=records,
        included_training_record_ids=base["manifest"].included_training_record_ids + ("train-secret-01",),
    )
    risks = derive(rebind(base, manifest=manifest, preserve_declarations=False))
    assert SensitiveDataRisk.QUARANTINE_POLICY_MISMATCH in risks


def test_canary_training_record_requires_quarantine():
    base = build_fixture()
    records = tuple(
        replace(r, included=True, disposition=DataDisposition.ALLOW)
        if r.record_id == "train-canary-01" else r
        for r in base["manifest"].records
    )
    manifest = replace(
        base["manifest"],
        records=records,
        included_training_record_ids=base["manifest"].included_training_record_ids + ("train-canary-01",),
    )
    risks = derive(rebind(base, manifest=manifest, preserve_declarations=False))
    assert SensitiveDataRisk.QUARANTINE_POLICY_MISMATCH in risks


def test_output_canary_reproduction_is_denied():
    base = build_fixture()
    canary = finding("output-canary-test", SensitiveKind.CANARY_TOKEN, "AEGIS-CANARY-OUTPUT", 1, 9)
    records = tuple(
        replace(
            r,
            findings=(canary,),
            sensitivity=SensitivityClass.CANARY,
            disposition=DataDisposition.DENY,
        ) if r.record_id == "output-public-01" else r
        for r in base["manifest"].records
    )
    risks = derive(rebind(base, manifest=replace(base["manifest"], records=records)))
    assert SensitiveDataRisk.OUTPUT_SENSITIVE_REPRODUCTION in risks


def test_output_secret_reproduction_is_denied():
    base = build_fixture()
    secret = finding("output-secret-test", SensitiveKind.API_SECRET, "secret-output", 1, 9)
    records = tuple(
        replace(r, findings=(secret,), sensitivity=SensitivityClass.SECRET, disposition=DataDisposition.DENY)
        if r.record_id == "output-public-02" else r
        for r in base["manifest"].records
    )
    risks = derive(rebind(base, manifest=replace(base["manifest"], records=records)))
    assert SensitiveDataRisk.OUTPUT_SENSITIVE_REPRODUCTION in risks


def test_classification_is_derived_from_findings():
    base = build_fixture()
    records = tuple(
        replace(r, sensitivity=SensitivityClass.PUBLIC) if r.record_id == "train-secret-01" else r
        for r in base["manifest"].records
    )
    risks = derive(rebind(base, manifest=replace(base["manifest"], records=records)))
    assert SensitiveDataRisk.CLASSIFICATION_MISMATCH in risks


def test_finding_evidence_is_digest_bound():
    base = build_fixture()
    records = []
    for r in base["manifest"].records:
        if r.record_id == "train-pii-01":
            f = r.findings[0]
            r = replace(r, findings=(replace(f, token_fingerprint_sha256=h("other-token")),))
        records.append(r)
    risks = derive(rebind(base, manifest=replace(base["manifest"], records=tuple(records))))
    assert SensitiveDataRisk.FINDING_EVIDENCE_MISMATCH in risks


def test_record_coverage_is_ordered_and_exact():
    base = build_fixture()
    manifest = replace(base["manifest"], records=tuple(reversed(base["manifest"].records)))
    risks = derive(rebind(base, manifest=manifest, preserve_declarations=False))
    assert SensitiveDataRisk.RECORD_COVERAGE_MISMATCH in risks


def test_output_batch_digest_is_bound():
    base = build_fixture()
    manifest = replace(base["manifest"], output_batch_sha256=h("wrong-batch"))
    risks = derive(rebind(base, manifest=manifest))
    assert SensitiveDataRisk.OUTPUT_BATCH_MISMATCH in risks


def test_network_operations_must_be_zero():
    base = build_fixture()
    manifest = replace(base["manifest"], network_operations=1)
    risks = derive(rebind(base, manifest=manifest))
    assert SensitiveDataRisk.NETWORK_OPERATION_UNEXPECTED in risks


def test_stale_request_is_rejected():
    base = build_fixture()
    request = replace(base["request"], evaluated_at_epoch=NOW + 301)
    with pytest.raises(SensitiveDataSecurityRejected) as exc:
        evaluate({**base, "request": request})
    assert exc.value.reason == SensitiveDataRejectReason.REQUEST_INVALID


def test_declared_summary_mismatch_is_rejected():
    base = build_fixture()
    request = replace(base["request"], declared_output_record_ids=("output-public-01",))
    with pytest.raises(SensitiveDataSecurityRejected) as exc:
        evaluate({**base, "request": request})
    assert exc.value.reason == SensitiveDataRejectReason.DECLARED_SUMMARY_MISMATCH


def test_policy_record_maps_must_cover_exact_order():
    base = build_fixture()
    policy = replace(
        base["policy"],
        expected_content_sha256_by_record_id={
            k: v for k, v in base["policy"].expected_content_sha256_by_record_id.items()
            if k != "train-public-01"
        },
    )
    with pytest.raises(SensitiveDataSecurityRejected) as exc:
        SensitiveDataGovernanceAnalyzer(policy)
    assert exc.value.reason == SensitiveDataRejectReason.POLICY_INVALID
