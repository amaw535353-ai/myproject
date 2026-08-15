from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.incident_forensics_security import (
    P8K_ASSESSMENT_MODE,
    P8K_ASSESSMENT_SCHEMA_VERSION,
    P8K_INCIDENT_POLICY_VERSION,
    P8K_INCIDENT_SCHEMA_VERSION,
    AgentIncidentForensicsRejected,
    AgentProvenanceIncidentForensicsAnalyzer,
    IncidentDecision,
    IncidentRisk,
    agent_incident_forensics_manifest_digest,
)
from aegis.vulnerable.incident_forensics_security import VulnerableCallerDeclaredIncidentSafety
from evals.p8k_fixture import EVENT_IDS, NOW, build_fixture
from evals.p8k_incident_forensics import CASES, EXPECTED_ADVERSARIAL_CASES, run


def _attack(name: str):
    return dict(CASES)[name](build_fixture())


def _risks(name: str):
    f = _attack(name)
    facts = AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).derive(
        f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"], f["request"].evaluated_at_epoch
    )
    return facts[0].risks


def test_clean_fixture_allows_incident_after_complete_containment_and_forensics():
    f = build_fixture()
    assessment = AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).evaluate(
        f["request"], f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"]
    )
    assert assessment.incident_count == 1
    assert assessment.allowed_incident_count == 1
    assert assessment.denied_incident_count == 0
    assert assessment.incidents[0].decision == IncidentDecision.ALLOW
    assert assessment.incidents[0].scope_event_ids == EVENT_IDS
    assert assessment.incidents[0].scope_agent_ids == ("agent-planner", "agent-worker")


def test_policy_and_schema_versions_are_pinned():
    assert P8K_INCIDENT_POLICY_VERSION == "agent-provenance-incident-containment-forensics-v1"
    assert P8K_INCIDENT_SCHEMA_VERSION == "aegis-agent-incident-forensics-manifest-v1"
    assert P8K_ASSESSMENT_SCHEMA_VERSION == "aegis-agent-incident-forensics-assessment-v1"
    assert P8K_ASSESSMENT_MODE == "deterministic-evidence-bound-agent-incident-forensics-v1"


def test_manifest_digest_is_exact_and_content_sensitive():
    f = build_fixture()
    original = agent_incident_forensics_manifest_digest(f["manifest"])
    changed = replace(f["manifest"], created_at_epoch=f["manifest"].created_at_epoch - 1)
    assert original == f["policy"].expected_graph_sha256
    assert agent_incident_forensics_manifest_digest(changed) != original


def test_assessment_exposes_only_synthetic_claims():
    f = build_fixture()
    assessment = AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).evaluate(
        f["request"], f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"]
    )
    assert assessment.exact_incident_graph_binding_verified
    assert assessment.tamper_evident_event_chains_verified
    assert assessment.causal_incident_scope_derived
    assert assessment.compromised_agents_quarantined
    assert assessment.evidence_preservation_verified
    assert assessment.deterministic_reconstruction_verified
    assert assessment.controlled_reentry_checked
    assert not assessment.caller_declared_incident_safety_trusted
    assert not assessment.production_siem_or_edr_integration
    assert not assessment.production_distributed_log_integration
    assert not assessment.cryptographic_log_signatures
    assert assessment.network_operations == 0


def test_vulnerable_baseline_trusts_caller_declared_incident_safety():
    assert VulnerableCallerDeclaredIncidentSafety().accepts()


def test_missing_agent_quarantine_is_denied():
    risks = _risks("action-target-contain-quarantine-worker")
    assert IncidentRisk.AGENT_NOT_QUARANTINED in risks


def test_compromised_channel_must_be_isolated():
    risks = _risks("action-target-contain-isolate-channel")
    assert IncidentRisk.CHANNEL_NOT_ISOLATED in risks


def test_compromised_state_and_recovery_objects_are_frozen():
    risks = _risks("action-target-contain-freeze-state")
    assert IncidentRisk.STATE_NOT_FROZEN in risks


def test_compromised_credential_must_be_revoked():
    risks = _risks("action-target-contain-revoke-credential")
    assert IncidentRisk.CREDENTIAL_NOT_REVOKED in risks


def test_preserved_evidence_must_cover_derived_causal_scope():
    risks = _risks("evidence-scope-drop")
    assert IncidentRisk.EVIDENCE_SCOPE_INCOMPLETE in risks


def test_forensic_package_must_preserve_exact_event_hashes():
    risks = _risks("package-preserved-hash-mismatch")
    assert IncidentRisk.FORENSIC_PACKAGE_HASH_MISMATCH in risks


def test_forensic_reconstruction_order_is_deterministic():
    risks = _risks("package-reconstruction-reorder")
    assert IncidentRisk.RECONSTRUCTION_ORDER_INVALID in risks


def test_reentry_is_bound_to_safe_checkpoint_and_rotated_credential():
    checkpoint_risks = _risks("reentry-checkpoint-reentry-worker")
    credential_risks = _risks("reentry-credential-reentry-worker")
    assert IncidentRisk.REENTRY_CHECKPOINT_MISMATCH in checkpoint_risks
    assert IncidentRisk.REENTRY_CREDENTIAL_NOT_ROTATED in credential_risks


def test_reentry_cannot_precede_containment_or_forensic_package():
    risks = _risks("reentry-issued-before-containment-reentry-planner")
    assert IncidentRisk.REENTRY_BEFORE_CONTAINMENT in risks


def test_event_hash_chain_tampering_is_rejected_before_incident_acceptance():
    f = _attack("event-prev-chain-broken")
    with pytest.raises(AgentIncidentForensicsRejected):
        AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).evaluate(
            f["request"], f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"]
        )


def test_unsafe_upstream_message_evidence_blocks_forensic_acceptance():
    f = _attack("upstream-p8g-unsafe-fact")
    with pytest.raises(AgentIncidentForensicsRejected):
        AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).evaluate(
            f["request"], f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"]
        )


def test_caller_declared_scope_cannot_override_derived_scope():
    f = _attack("declared-scope-lie")
    with pytest.raises(AgentIncidentForensicsRejected):
        AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).evaluate(
            f["request"], f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"]
        )


def test_safe_evaluation_time_variants_remain_allowed():
    for offset in (0, 1, 2):
        f = build_fixture()
        request = replace(f["request"], evaluated_at_epoch=NOW + offset)
        assessment = AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).evaluate(
            request, f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"]
        )
        assert assessment.allowed_incident_count == 1


def test_evaluator_metrics_are_deterministic():
    result = run()
    assert EXPECTED_ADVERSARIAL_CASES == 178
    assert result["adversarial_cases"] == 178
    assert result["vulnerable_asr"] == "178/178"
    assert result["hardened_asr"] == "0/178"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
