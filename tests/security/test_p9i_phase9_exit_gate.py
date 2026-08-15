from __future__ import annotations

from dataclasses import replace
import pytest

from aegis.training.phase9_exit_security import Phase9IntegratedExitGate, machine_readable_phase9_exit
from aegis.training.phase9_exit_types import MILESTONE_ORDER, SCENARIO_ORDER, Phase9ExitDecision, Phase9ExitRejected, Phase9ExitRejectReason, Phase9ExitRisk, Phase9VerificationStatus
from evals.p9i_fixture import MILESTONE_ASSESSMENT_SHA256, MILESTONE_MANIFEST_SHA256, build_fixture, h, rebind
from evals.p9i_phase9_exit_gate import EXPECTED_ADVERSARIAL_CASES, run

def gate(f): return Phase9IntegratedExitGate(f['policy'])
def derive(f,manifest):
    changed=rebind(f,manifest,keep_policy_pins=False); return gate(changed).derive(changed['manifest'],changed['request'].evaluated_at_epoch)

def test_canonical_blocked_exit():
    f=build_fixture(); a=gate(f).evaluate(f['request'],f['manifest']); assert a.decision==Phase9ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION; assert a.remote_ci_status=='REMOTE_CI_BLOCKED'; assert a.remote_ci_execution_verified is False; assert a.remote_ci_external_limitation is True; assert a.compromise_exercises_passed and a.promotion_fail_closed_verified; assert a.risks==()
def test_machine_readable_boundary():
    f=build_fixture(); r=machine_readable_phase9_exit(gate(f).evaluate(f['request'],f['manifest'])); assert r['phase']=='P9'; assert r['production_claims'] is False; assert r['compromise_exercises']['scenario_count']==8; assert r['remote_ci']['execution_verified'] is False
def test_remote_pass_requires_execution():
    f=build_fixture(Phase9VerificationStatus.REMOTE_CI_PASS); a=gate(f).evaluate(f['request'],f['manifest']); assert a.decision==Phase9ExitDecision.PASS and a.remote_ci_execution_verified
def test_remote_executed_failure_fails():
    f=build_fixture(Phase9VerificationStatus.REMOTE_CI_FAIL); a=gate(f).evaluate(f['request'],f['manifest']); assert a.decision==Phase9ExitDecision.FAIL; assert Phase9ExitRisk.REMOTE_CI_EXECUTION_FAILED in a.risks
def test_exact_historical_phase9_hashes_bound():
    f=build_fixture(); items=f['manifest'].milestone_evidence; assert tuple(i.milestone_id for i in items)==MILESTONE_ORDER; assert {i.milestone_id:i.manifest_sha256 for i in items}==MILESTONE_MANIFEST_SHA256; assert {i.milestone_id:i.assessment_sha256 for i in items}==MILESTONE_ASSESSMENT_SHA256
def test_predecessor_chain_is_exact():
    items=build_fixture()['manifest'].milestone_evidence
    for n,item in enumerate(items): assert item.predecessor_assessment_sha256==('0'*64 if n==0 else items[n-1].assessment_sha256)
def test_compromise_profile_fail_closed():
    items=build_fixture()['manifest'].compromise_exercises; assert tuple(i.scenario_id for i in items)==SCENARIO_ORDER; assert all(i.detected and i.promotion_blocked for i in items); assert items[-1].detection_milestone_id=='P9-H'
def test_wrong_policy_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],policy_version='wrong')
    with pytest.raises(Phase9ExitRejected) as e: gate(f)
    assert e.value.reason==Phase9ExitRejectReason.POLICY_INVALID
def test_outer_manifest_digest_pinned():
    f=build_fixture(); m=replace(f['manifest'],created_at_epoch=f['manifest'].created_at_epoch+1); changed=rebind(f,m,keep_policy_pins=True)
    with pytest.raises(Phase9ExitRejected) as e: gate(changed).evaluate(changed['request'],changed['manifest'])
    assert e.value.reason==Phase9ExitRejectReason.MANIFEST_DIGEST_MISMATCH
def test_stale_request_rejected():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+3601)
    with pytest.raises(Phase9ExitRejected): gate(f).evaluate(f['request'],f['manifest'])
def test_caller_assessment_lie_rejected():
    f=build_fixture(); d=dict(f['request'].declared_assessment_sha256_by_milestone); d['P9-H']=h('forged'); f['request']=replace(f['request'],declared_assessment_sha256_by_milestone=d)
    with pytest.raises(Phase9ExitRejected) as e: gate(f).evaluate(f['request'],f['manifest'])
    assert e.value.reason==Phase9ExitRejectReason.DECLARED_EVIDENCE_MISMATCH
def test_unsafe_upstream_fails():
    f=build_fixture(); m=f['manifest']; items=list(m.milestone_evidence); items[2]=replace(items[2],safe=False); risks,decision,_=derive(f,replace(m,milestone_evidence=tuple(items))); assert Phase9ExitRisk.UPSTREAM_SAFETY_FAILED in risks and decision==Phase9ExitDecision.FAIL
def test_evidence_chain_substitution_fails():
    f=build_fixture(); m=f['manifest']; items=list(m.milestone_evidence); items[5]=replace(items[5],predecessor_assessment_sha256=h('wrong')); risks,_,_=derive(f,replace(m,milestone_evidence=tuple(items))); assert Phase9ExitRisk.EVIDENCE_CHAIN_BROKEN in risks
def test_undetected_compromise_fails():
    f=build_fixture(); m=f['manifest']; items=list(m.compromise_exercises); items[0]=replace(items[0],detected=False); risks,decision,_=derive(f,replace(m,compromise_exercises=tuple(items))); assert Phase9ExitRisk.COMPROMISE_NOT_DETECTED in risks and decision==Phase9ExitDecision.FAIL
def test_promotion_fail_open_fails():
    f=build_fixture(); m=f['manifest']; items=list(m.compromise_exercises); items[6]=replace(items[6],promotion_blocked=False); risks,decision,meta=derive(f,replace(m,compromise_exercises=tuple(items))); assert Phase9ExitRisk.PROMOTION_FAIL_OPEN in risks and decision==Phase9ExitDecision.FAIL and meta['promotion_fail_closed'] is False
def test_production_claim_fails():
    f=build_fixture(); m=f['manifest']; claims=replace(m.claim_profile,production_model_registry_integrated=True); risks,_,_=derive(f,replace(m,claim_profile=claims)); assert Phase9ExitRisk.UNSUPPORTED_PRODUCTION_CLAIM in risks
def test_local_execution_evidence_required():
    f=build_fixture(); m=f['manifest']; records=list(m.verification_records); records[0]=replace(records[0],runner_started=False); risks,_,meta=derive(f,replace(m,verification_records=tuple(records))); assert Phase9ExitRisk.LOCAL_VERIFICATION_INCOMPLETE in risks and meta['local_ok'] is False
def test_evaluator_metrics():
    r=run(); assert EXPECTED_ADVERSARIAL_CASES==254; assert r['adversarial_cases']==254; assert r['vulnerable_asr']=='254/254'; assert r['hardened_asr']=='0/254'; assert r['hardened_fpr']=='0/4'; assert r['safe_task_rate']=='4/4'; assert r['compromise_scenarios']==8; assert r['promotion_fail_closed_verified'] is True; assert r['exit_decision']=='PASS_WITH_EXTERNAL_CI_LIMITATION'
