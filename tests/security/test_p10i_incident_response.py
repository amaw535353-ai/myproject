from __future__ import annotations

from dataclasses import replace
import pytest

from aegis.inference.incident_response_security import InferenceIncidentResponseAnalyzer
from aegis.inference.incident_response_types import *
from aegis.vulnerable.incident_response import VulnerableCallerDeclaredIncidentResponseSafety
from evals.p10i_fixture import build_fixture
from evals.p10i_incident_response import adversarial_fixtures, safe_fixtures


def test_clean_assessment_is_fail_closed_and_carries_mastery_debt():
    f = build_fixture()
    a = InferenceIncidentResponseAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10h"])
    assert a.decision == IncidentDecision.ALLOW
    assert a.risks == ()
    assert a.upstream_p10h_bound and a.detection_verified and a.containment_verified
    assert a.recovery_verified and a.forensic_chain_verified and a.phase10_exit_gate_verified
    assert a.deferred_mastery_debt_carried
    assert a.exit_gate_status == ExitGateStatus.PASS_WITH_DEFERRED
    assert not a.caller_declared_safety_trusted
    assert not a.production_soc_integrated
    assert not a.production_siem_integrated
    assert not a.production_orchestrator_remediation_validated
    assert not a.cross_zone_recovery_validated
    assert not a.hosted_ci_execution_verified
    assert not a.production_validation_claimed
    assert not a.professional_mastery_complete


@pytest.mark.parametrize("name,f", safe_fixtures(), ids=lambda x: x if isinstance(x, str) else None)
def test_safe_corpus(name, f):
    a = InferenceIncidentResponseAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10h"])
    assert a.decision == IncidentDecision.ALLOW, name


@pytest.mark.parametrize("name,f", adversarial_fixtures(), ids=lambda x: x if isinstance(x, str) else None)
def test_adversarial_corpus_blocked(name, f):
    assert VulnerableCallerDeclaredIncidentResponseSafety().accepts(f["request"]), name
    try:
        a = InferenceIncidentResponseAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10h"])
    except InferenceIncidentResponseRejected:
        return
    assert a.decision == IncidentDecision.DENY, name


def test_caller_cannot_flip_final_safety_false_on_clean_evidence():
    f = build_fixture()
    req = replace(f["request"], declared_incident_response_safe=False)
    with pytest.raises(InferenceIncidentResponseRejected) as exc:
        InferenceIncidentResponseAnalyzer(f["policy"]).evaluate(f["manifest"], req, f["p10h"])
    assert exc.value.reason == IncidentRejectReason.DECLARED_SUMMARY_MISMATCH


def test_policy_rejects_missing_mastery_debt_contract():
    f = build_fixture()
    p = replace(f["policy"], required_deferred_mastery_items=())
    with pytest.raises(InferenceIncidentResponseRejected) as exc:
        InferenceIncidentResponseAnalyzer(p)
    assert exc.value.reason == IncidentRejectReason.POLICY_INVALID
