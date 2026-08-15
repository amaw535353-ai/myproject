from __future__ import annotations
from dataclasses import replace
import pytest
from aegis.inference.scheduler_security import InferenceSchedulerSecurityAnalyzer
from aegis.inference.scheduler_security_types import *
from aegis.inference.tenant_isolation_types import InferenceDecision
from aegis.vulnerable.inference_scheduler import VulnerableCallerDeclaredSchedulerSafety
from evals.p10b_fixture import build_fixture,rebind,safe_beta_selected_fixture
from evals.p10b_scheduler_security import CASES,_safe_cases,run

def ev(f): return InferenceSchedulerSecurityAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10a'])
def risk(f): return InferenceSchedulerSecurityAnalyzer(f['policy']).derive(f['manifest'],f['p10a'])
def reqmut(index,**kw):
    f=build_fixture(); m=f['manifest']; xs=list(m.requests); xs[index]=replace(xs[index],**kw); return rebind(f,replace(m,requests=tuple(xs)),keep_policy_pins=False)
def statemut(index,**kw):
    f=build_fixture(); m=f['manifest']; xs=list(m.tenant_states); xs[index]=replace(xs[index],**kw); return rebind(f,replace(m,tenant_states=tuple(xs)),keep_policy_pins=False)
def test_01_canonical_allow(): assert ev(build_fixture()).decision==SchedulerDecision.ALLOW
def test_02_canonical_no_risks(): assert ev(build_fixture()).risks==()
def test_03_schema_mode():
    a=ev(build_fixture()); assert (a.assessment_schema_version,a.assessment_mode)==(P10B_ASSESSMENT_SCHEMA_VERSION,P10B_ASSESSMENT_MODE)
def test_04_verified_flags():
    a=ev(build_fixture()); assert all((a.upstream_p10a_bound,a.scheduler_identity_verified,a.admission_limits_verified,a.tenant_resource_isolation_verified,a.weighted_fairness_verified,a.starvation_bounds_verified,a.batch_plan_verified))
def test_05_claim_boundary():
    a=ev(build_fixture()); assert not any((a.caller_declared_safety_trusted,a.production_scheduler_integrated,a.production_gpu_quota_enforced,a.production_distributed_fairness_validated,a.production_autoscaler_integrated,a.side_channel_resistance_validated))
def test_06_policy_version_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],policy_version='wrong')
    with pytest.raises(InferenceSchedulerRejected): InferenceSchedulerSecurityAnalyzer(f['policy'])
def test_07_policy_map_coverage_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],tenant_weights={'acme':2,'beta':1})
    with pytest.raises(InferenceSchedulerRejected): InferenceSchedulerSecurityAnalyzer(f['policy'])
def test_08_policy_digest_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_p10a_assessment_sha256='bad')
    with pytest.raises(InferenceSchedulerRejected): InferenceSchedulerSecurityAnalyzer(f['policy'])
def test_09_manifest_digest_pin():
    f=build_fixture(); f['manifest']=replace(f['manifest'],network_operations=1)
    with pytest.raises(InferenceSchedulerRejected): ev(f)
def test_10_stale_request():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+301)
    with pytest.raises(InferenceSchedulerRejected): ev(f)
def test_11_future_skew():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch-6)
    with pytest.raises(InferenceSchedulerRejected): ev(f)
def test_12_upstream_decision():
    f=build_fixture(); f['p10a']=replace(f['p10a'],decision=InferenceDecision.DENY); assert SchedulerRisk.UPSTREAM_P10A_INVALID in risk(f)
def test_13_upstream_digest_binding():
    f=build_fixture(); f['p10a']=replace(f['p10a'],assessment_evidence_sha256='0'*64); assert SchedulerRisk.UPSTREAM_BINDING_MISMATCH in risk(f)
def test_14_tenant_route_binding(): assert SchedulerRisk.REQUEST_TENANT_MISMATCH in risk(reqmut(0,tenant_id='beta'))
def test_15_session_binding(): assert SchedulerRisk.REQUEST_TENANT_MISMATCH in risk(reqmut(2,session_id='tenant/acme/session/x'))
def test_16_request_token_limit(): assert SchedulerRisk.REQUEST_RESOURCE_LIMIT_EXCEEDED in risk(reqmut(1,prompt_tokens=999))
def test_17_tenant_queue_depth():
    f=build_fixture(); f['policy']=replace(f['policy'],max_queue_depth_by_tenant={**f['policy'].max_queue_depth_by_tenant,'acme':1}); assert SchedulerRisk.TENANT_QUEUE_DEPTH_EXCEEDED in risk(f)
def test_18_tenant_token_budget():
    f=build_fixture(); f['policy']=replace(f['policy'],max_reserved_tokens_by_tenant={**f['policy'].max_reserved_tokens_by_tenant,'acme':399}); assert SchedulerRisk.TENANT_TOKEN_BUDGET_EXCEEDED in risk(f)
def test_19_global_capacity():
    f=build_fixture(); m=replace(f['manifest'],resources=replace(f['manifest'].resources,total_slots=99)); f=rebind(f,m,keep_policy_pins=False); assert SchedulerRisk.GLOBAL_CAPACITY_EXCEEDED in risk(f)
def test_20_priority_policy(): assert SchedulerRisk.PRIORITY_POLICY_MISMATCH in risk(reqmut(4,priority_class='root'))
def test_21_starvation_bound(): assert SchedulerRisk.STARVATION_BOUND_EXCEEDED in risk(reqmut(4,queue_age_seconds=1000))
def test_22_fairness_state(): assert SchedulerRisk.FAIRNESS_STATE_MISMATCH in risk(statemut(0,deficit_after=999))
def test_23_fairness_selection():
    f=build_fixture(); m=replace(f['manifest'],selected_batch=replace(f['manifest'].selected_batch,tenant_id='beta',request_ids=('request-beta-0001','request-beta-0002'),total_reserved_tokens=300,total_memory_units=3)); f=rebind(f,m,keep_policy_pins=False); assert SchedulerRisk.FAIRNESS_SELECTION_MISMATCH in risk(f)
def test_24_batch_plan():
    f=build_fixture(); m=replace(f['manifest'],selected_batch=replace(f['manifest'].selected_batch,request_ids=('request-acme-0001',),total_reserved_tokens=200,total_memory_units=2)); f=rebind(f,m,keep_policy_pins=False); assert SchedulerRisk.BATCH_PLAN_MISMATCH in risk(f)
def test_25_replay_ledger():
    f=build_fixture(); ids=f['manifest'].prior_admitted_request_ids+('request-acme-0001',); m=replace(f['manifest'],prior_admitted_request_ids=ids,prior_admitted_ledger_sha256=admitted_ledger_digest(ids)); f=rebind(f,m,keep_policy_pins=False); assert SchedulerRisk.DUPLICATE_REQUEST in risk(f)
def test_26_declared_summary_lie():
    f=build_fixture(); f['request']=replace(f['request'],declared_selected_tenant_id='beta')
    with pytest.raises(InferenceSchedulerRejected): ev(f)
def test_27_vulnerable_corpus():
    v=VulnerableCallerDeclaredSchedulerSafety(); assert all(v.accepts(replace(a(build_fixture())['request'],declared_scheduler_safe=True)) for _,a in CASES)
def test_28_hardened_corpus():
    for name,a in CASES:
        f=a(build_fixture())
        try: accepted=ev(f).decision==SchedulerDecision.ALLOW
        except InferenceSchedulerRejected: accepted=False
        assert not accepted,name
def test_29_safe_variants(): assert len(_safe_cases())==4 and all(ev(f).decision==SchedulerDecision.ALLOW for f in _safe_cases())
def test_30_metrics():
    r=run(); n=r['adversarial_cases']; assert n==135 and r['vulnerable_asr']==f'{n}/{n}' and r['hardened_asr']==f'0/{n}' and r['hardened_fpr']=='0/4' and r['safe_task_rate']=='4/4' and r['decision']=='allow'
def test_31_beta_fair_turn():
    a=ev(safe_beta_selected_fixture()); assert a.selected_tenant_id=='beta' and a.batch_request_ids==('request-beta-0001','request-beta-0002')
