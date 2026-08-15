from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.phase8_exit_security import Phase8IntegratedExitGate, machine_readable_phase8_exit
from aegis.agentic.phase8_exit_types import (
    MILESTONE_ORDER,
    P8L_ASSESSMENT_MODE,
    P8L_ASSESSMENT_SCHEMA_VERSION,
    P8L_EXIT_POLICY_VERSION,
    P8L_EXIT_SCHEMA_VERSION,
    ExitRisk,
    Phase8ExitDecision,
    Phase8ExitRejected,
    VerificationStatus,
    phase8_exit_manifest_digest,
)
from aegis.vulnerable.phase8_exit_security import VulnerableCallerDeclaredPhase8Exit
from evals.p8l_fixture import REMOTE_BLOCK_REASON, build_fixture
from evals.p8l_phase8_exit_gate import CASES, EXPECTED_ADVERSARIAL_CASES, run


def _attack(name: str):
    return dict(CASES)[name](build_fixture())


def _derive_attack(name: str):
    f = _attack(name)
    return Phase8IntegratedExitGate(f["policy"]).derive(
        f["manifest"], f["request"].evaluated_at_epoch
    )


def test_clean_blocked_ci_fixture_exits_with_explicit_external_limitation():
    f = build_fixture()
    assessment = Phase8IntegratedExitGate(f["policy"]).evaluate(f["request"], f["manifest"])
    assert assessment.decision == Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION
    assert assessment.milestone_count == 11
    assert assessment.all_milestones_evidence_bound
    assert assessment.local_security_validation_passed
    assert assessment.remote_ci_external_limitation
    assert not assessment.remote_ci_execution_verified


def test_clean_remote_ci_pass_requires_actual_runner_execution():
    f = build_fixture(VerificationStatus.REMOTE_CI_PASS)
    assessment = Phase8IntegratedExitGate(f["policy"]).evaluate(f["request"], f["manifest"])
    assert assessment.decision == Phase8ExitDecision.PASS
    assert assessment.remote_ci_execution_verified
    assert not assessment.remote_ci_external_limitation


def test_policy_schema_and_assessment_versions_are_pinned():
    assert P8L_EXIT_POLICY_VERSION == "phase8-integrated-agent-exit-policy-v1"
    assert P8L_EXIT_SCHEMA_VERSION == "aegis-phase8-integrated-exit-manifest-v1"
    assert P8L_ASSESSMENT_SCHEMA_VERSION == "aegis-phase8-integrated-exit-assessment-v1"
    assert P8L_ASSESSMENT_MODE == "deterministic-evidence-lineage-and-verification-aware-phase8-exit-v1"


def test_manifest_digest_is_exact_and_content_sensitive():
    f = build_fixture()
    original = phase8_exit_manifest_digest(f["manifest"])
    assert original == f["policy"].expected_manifest_sha256
    changed = replace(f["manifest"], created_at_epoch=f["manifest"].created_at_epoch + 1)
    assert phase8_exit_manifest_digest(changed) != original


def test_milestone_order_is_exact_p8a_through_p8k():
    f = build_fixture()
    assert tuple(m.milestone_id for m in f["manifest"].milestone_evidence) == MILESTONE_ORDER
    for index, milestone in enumerate(f["manifest"].milestone_evidence):
        expected_predecessor = (
            "0" * 64
            if index == 0
            else f["manifest"].milestone_evidence[index - 1].assessment_sha256
        )
        expected_input = (
            "0" * 64
            if index == 0
            else f["manifest"].milestone_evidence[index - 1].output_state_sha256
        )
        assert milestone.predecessor_assessment_sha256 == expected_predecessor
        assert milestone.input_state_sha256 == expected_input


def test_cross_milestone_state_lineage_tampering_fails_closed():
    risks, decision, _ = _derive_attack("p8-h-input-state")
    assert ExitRisk.LINEAGE_MISMATCH in risks
    assert decision == Phase8ExitDecision.FAIL


def test_upstream_unsafe_milestone_fails_phase8_exit():
    risks, decision, _ = _derive_attack("p8-c-unsafe")
    assert ExitRisk.UPSTREAM_SAFETY_FAILED in risks
    assert decision == Phase8ExitDecision.FAIL


def test_caller_declared_safety_trust_is_never_accepted():
    risks, decision, _ = _derive_attack("p8-g-caller-trust")
    assert ExitRisk.CALLER_DECLARED_SAFETY_TRUSTED in risks
    assert decision == Phase8ExitDecision.FAIL


def test_local_verification_must_have_actual_execution():
    risks, decision, _ = _derive_attack("p8-j-local-runner-not-started")
    assert ExitRisk.LOCAL_VERIFICATION_INCOMPLETE in risks
    assert decision == Phase8ExitDecision.FAIL


def test_blocked_hosted_ci_is_not_misreported_as_ci_pass():
    f = build_fixture()
    remote = [
        v
        for v in f["manifest"].verification_records
        if v.status == VerificationStatus.REMOTE_CI_BLOCKED
    ][0]
    assert remote.reason_code == REMOTE_BLOCK_REASON
    assert remote.runner_started is False
    assert remote.steps_executed == 0
    assessment = Phase8IntegratedExitGate(f["policy"]).evaluate(f["request"], f["manifest"])
    assert assessment.remote_ci_status == VerificationStatus.REMOTE_CI_BLOCKED.value
    assert not assessment.remote_ci_execution_verified


def test_blocked_ci_with_executed_steps_is_invalid_not_external_limitation():
    risks, decision, metadata = _derive_attack("remote-blocked-steps-executed")
    assert ExitRisk.REMOTE_CI_INVALID in risks
    assert decision == Phase8ExitDecision.FAIL
    assert not metadata["remote_external_limitation"]


def test_remote_ci_execution_failure_is_phase8_fail_not_billing_limitation():
    f = build_fixture(VerificationStatus.REMOTE_CI_FAIL)
    risks, decision, metadata = Phase8IntegratedExitGate(f["policy"]).derive(
        f["manifest"], f["request"].evaluated_at_epoch
    )
    assert ExitRisk.REMOTE_CI_EXECUTION_FAILED in risks
    assert decision == Phase8ExitDecision.FAIL
    assert not metadata["remote_external_limitation"]


def test_remote_ci_pass_with_zero_steps_is_rejected_as_invalid_evidence():
    risks, decision, _ = _derive_attack("remote-pass-zero-steps")
    assert ExitRisk.REMOTE_CI_INVALID in risks
    assert decision == Phase8ExitDecision.FAIL


def test_unsupported_production_claims_fail_closed():
    for name in (
        "unsupported-claim-production_runtime_validated",
        "unsupported-claim-production_distributed_system_validated",
        "unsupported-claim-production_siem_edr_integrated",
        "unsupported-claim-production_secret_rotation_executed",
        "unsupported-claim-cryptographic_attestation_verified",
    ):
        risks, decision, _ = _derive_attack(name)
        assert ExitRisk.UNSUPPORTED_PRODUCTION_CLAIM in risks
        assert decision == Phase8ExitDecision.FAIL


def test_synthetic_assumptions_are_machine_enforced():
    risks, decision, _ = _derive_attack("assumption-drop")
    assert ExitRisk.SYNTHETIC_ASSUMPTION_MISSING in risks
    assert decision == Phase8ExitDecision.FAIL


def test_request_cannot_upgrade_blocked_ci_to_pass():
    f = _attack("request-decision-lie")
    with pytest.raises(Phase8ExitRejected):
        Phase8IntegratedExitGate(f["policy"]).evaluate(f["request"], f["manifest"])


def test_request_cannot_replace_exact_milestone_evidence():
    f = _attack("request-evidence-lie")
    with pytest.raises(Phase8ExitRejected):
        Phase8IntegratedExitGate(f["policy"]).evaluate(f["request"], f["manifest"])


def test_vulnerable_baseline_trusts_caller_declared_phase8_exit():
    assert VulnerableCallerDeclaredPhase8Exit().accepts(Phase8ExitDecision.PASS)


def test_machine_readable_exit_preserves_verification_distinction():
    f = build_fixture()
    assessment = Phase8IntegratedExitGate(f["policy"]).evaluate(f["request"], f["manifest"])
    report = machine_readable_phase8_exit(assessment)
    assert report["phase"] == "P8"
    assert report["local_security_validation"] == "PASS"
    assert report["remote_ci"]["status"] == VerificationStatus.REMOTE_CI_BLOCKED.value
    assert report["remote_ci"]["execution_verified"] is False
    assert report["remote_ci"]["external_limitation"] is True
    assert report["exit_decision"] == Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION.value
    assert report["production_claims"] is False


def test_safe_evaluation_time_variants_remain_valid():
    for offset in (0, 1, 30, 300):
        f = build_fixture()
        request = replace(
            f["request"], evaluated_at_epoch=f["manifest"].created_at_epoch + offset
        )
        assessment = Phase8IntegratedExitGate(f["policy"]).evaluate(request, f["manifest"])
        assert assessment.decision == Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION


def test_evaluator_metrics_are_deterministic():
    result = run()
    assert EXPECTED_ADVERSARIAL_CASES == 198
    assert result["adversarial_cases"] == 198
    assert result["vulnerable_asr"] == "198/198"
    assert result["hardened_asr"] == "0/198"
    assert result["hardened_fpr"] == "0/4"
    assert result["safe_task_rate"] == "4/4"
    assert result["exit_decision"] == Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION.value
