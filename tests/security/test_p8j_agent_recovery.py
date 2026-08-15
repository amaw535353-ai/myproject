from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.recovery_security import (
    P8J_ASSESSMENT_MODE,
    P8J_ASSESSMENT_SCHEMA_VERSION,
    P8J_RECOVERY_POLICY_VERSION,
    P8J_RECOVERY_SCHEMA_VERSION,
    AgentRecoverySecurityRejected,
    AgentRollbackRecoverySecurityAnalyzer,
    RecoveryDecision,
    RecoveryRisk,
    agent_recovery_manifest_digest,
)
from aegis.vulnerable.recovery_security import VulnerableDeclaredRecoverySafety
from evals.p8j_agent_recovery import CASES, EXPECTED_ADVERSARIAL_CASES, run
from evals.p8j_fixture import build_fixture


def _attack(name: str):
    mutator = dict(CASES)[name]
    return mutator(build_fixture())


def _risks(name: str, recovery_id: str):
    f = _attack(name)
    facts = AgentRollbackRecoverySecurityAnalyzer(f["policy"]).derive(
        f["manifest"], f["p8b"], f["p8i"], f["p8h"], f["request"].evaluated_at_epoch
    )
    return next(x for x in facts if x.recovery_id == recovery_id).risks


def test_clean_fixture_allows_three_recovery_paths():
    f = build_fixture()
    assessment = AgentRollbackRecoverySecurityAnalyzer(f["policy"]).evaluate(
        f["request"], f["manifest"], f["p8b"], f["p8i"], f["p8h"]
    )
    assert assessment.recovery_count == 3
    assert assessment.allowed_recovery_count == 3
    assert assessment.denied_recovery_count == 0
    assert all(x.decision == RecoveryDecision.ALLOW for x in assessment.recoveries)


def test_policy_and_schema_versions_are_pinned():
    assert P8J_RECOVERY_POLICY_VERSION == "agent-rollback-recovery-persistence-boundary-security-v1"
    assert P8J_RECOVERY_SCHEMA_VERSION == "aegis-agent-recovery-persistence-manifest-v1"
    assert P8J_ASSESSMENT_SCHEMA_VERSION == "aegis-agent-recovery-persistence-assessment-v1"
    assert P8J_ASSESSMENT_MODE == "deterministic-evidence-bound-agent-recovery-security-v1"


def test_manifest_digest_is_exact_and_content_sensitive():
    f = build_fixture()
    original = agent_recovery_manifest_digest(f["manifest"])
    changed = replace(f["manifest"], created_at_epoch=f["manifest"].created_at_epoch - 1)
    assert original == f["policy"].expected_graph_sha256
    assert agent_recovery_manifest_digest(changed) != original


def test_assessment_exposes_only_synthetic_claims():
    f = build_fixture()
    assessment = AgentRollbackRecoverySecurityAnalyzer(f["policy"]).evaluate(
        f["request"], f["manifest"], f["p8b"], f["p8i"], f["p8h"]
    )
    assert assessment.exact_recovery_graph_binding_verified
    assert assessment.persistence_revocation_and_quarantine_enforced
    assert assessment.destructive_rollback_authorization_checked
    assert not assessment.caller_declared_recovery_safety_trusted
    assert not assessment.production_backup_restore_enforcement
    assert not assessment.cryptographic_checkpoint_attestation
    assert assessment.network_operations == 0


def test_vulnerable_baseline_trusts_caller_declarations():
    assert VulnerableDeclaredRecoverySafety().accepts()


def test_compromised_checkpoint_cannot_be_resumed():
    risks = _risks("resume-compromised", "recovery-safe-resume")
    assert RecoveryRisk.RESUME_AFTER_COMPROMISE in risks
    assert RecoveryRisk.CHECKPOINT_UNTRUSTED in risks


def test_rollback_floor_prevents_unsafe_history_rewind():
    risks = _risks("rollback-past-floor", "recovery-compromise-rollback")
    assert RecoveryRisk.CHECKPOINT_ROLLBACK_PAST_FLOOR in risks


def test_source_only_compromise_must_be_quarantined():
    risks = _risks("rollback-missing-quarantine", "recovery-compromise-rollback")
    assert RecoveryRisk.QUARANTINE_BYPASS in risks


def test_revoked_credential_cannot_be_resurrected():
    risks = _risks("recovery-restore-credential-recovery-safe-resume", "recovery-safe-resume")
    assert RecoveryRisk.CREDENTIAL_RESURRECTION in risks
    assert RecoveryRisk.ITEM_REVOKED in risks


def test_rejected_message_cannot_be_restored():
    risks = _risks("recovery-restore-rejected-message-recovery-safe-resume", "recovery-safe-resume")
    assert RecoveryRisk.UNSAFE_MESSAGE_REINTRODUCTION in risks
    assert RecoveryRisk.ITEM_QUARANTINED in risks


def test_poisoned_artifact_cannot_be_restored():
    risks = _risks("recovery-restore-poisoned-artifact-recovery-safe-resume", "recovery-safe-resume")
    assert RecoveryRisk.UNSAFE_ARTIFACT_REINTRODUCTION in risks
    assert RecoveryRisk.ITEM_QUARANTINED in risks


def test_upstream_memory_denial_blocks_recovery():
    risks = _risks("upstream-memory-denied", "recovery-safe-resume")
    assert RecoveryRisk.UPSTREAM_MEMORY_UNSAFE in risks
    assert RecoveryRisk.UNSAFE_MEMORY_REINTRODUCTION in risks


def test_upstream_artifact_denial_blocks_recovery():
    risks = _risks("upstream-artifact-denied", "recovery-safe-resume")
    assert RecoveryRisk.UPSTREAM_ARTIFACT_UNSAFE in risks


def test_upstream_state_denial_blocks_recovery():
    risks = _risks("upstream-state-denied", "recovery-safe-resume")
    assert RecoveryRisk.UPSTREAM_STATE_UNSAFE in risks
    assert RecoveryRisk.STATE_ROLLBACK_UNSAFE in risks


def test_destructive_rollback_requires_bound_authorization():
    risks = _risks("auth-rollback-destructive-off", "recovery-compromise-rollback")
    assert RecoveryRisk.DESTRUCTIVE_ROLLBACK_UNAUTHORIZED in risks


def test_caller_declared_summary_cannot_override_derived_recovery_state():
    f = _attack("declared-denied-lie")
    with pytest.raises(AgentRecoverySecurityRejected):
        AgentRollbackRecoverySecurityAnalyzer(f["policy"]).evaluate(
            f["request"], f["manifest"], f["p8b"], f["p8i"], f["p8h"]
        )


def test_evaluator_metrics_are_deterministic():
    result = run()
    assert EXPECTED_ADVERSARIAL_CASES == 130
    assert result["adversarial_cases"] == 130
    assert result["vulnerable_asr"] == "130/130"
    assert result["hardened_asr"] == "0/130"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
