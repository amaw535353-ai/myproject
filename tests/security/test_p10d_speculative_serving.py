from __future__ import annotations
from dataclasses import replace
import pytest
from aegis.inference.speculative_serving_security import InferenceSpeculativeServingAnalyzer
from aegis.inference.speculative_serving_types import *
from aegis.inference.cache_lifecycle_types import CacheDecision,CacheRisk
from aegis.vulnerable.speculative_serving import VulnerableCallerDeclaredSpeculativeServingSafety
from evals.p10d_fixture import build_fixture,rebind,safe_reject_all_draft_fixture,h
from evals.p10d_speculative_serving import CASES,_safe_cases,run

def ev(f): return InferenceSpeculativeServingAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10c'])
def risk(f): return InferenceSpeculativeServingAnalyzer(f['policy']).derive(f['manifest'],f['p10c'])
def smut(i,**kw):
    f=build_fixture(); m=f['manifest']; xs=list(m.services); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,services=tuple(xs)),keep_policy_pins=False)
def tmut(i,**kw):
    f=build_fixture(); m=f['manifest']; xs=list(m.transfers); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,transfers=tuple(xs)),keep_policy_pins=False)
def rmut(**kw):
    f=build_fixture(); m=f['manifest']; r=replace(m.speculative_rounds[0],**kw); return rebind(f,replace(m,speculative_rounds=(r,)),keep_policy_pins=False)
def test_01_canonical_allow(): assert ev(build_fixture()).decision==ServingDecision.ALLOW
def test_02_canonical_no_risks(): assert ev(build_fixture()).risks==()
def test_03_schema_mode():
    a=ev(build_fixture()); assert (a.assessment_schema_version,a.assessment_mode)==(P10D_ASSESSMENT_SCHEMA_VERSION,P10D_ASSESSMENT_MODE)
def test_04_verified_flags():
    a=ev(build_fixture()); assert all((a.upstream_p10c_bound,a.route_identity_verified,a.draft_model_trust_verified,a.service_topology_verified,a.state_transfer_verified,a.speculative_verification_verified,a.final_state_verified))
def test_05_claim_boundary():
    a=ev(build_fixture()); assert not any((a.caller_declared_safety_trusted,a.production_inference_engine_integrated,a.production_rpc_transport_verified,a.cryptographic_service_attestation_verified,a.production_speculative_decoder_validated,a.semantic_token_equivalence_verified,a.side_channel_resistance_validated))
def test_06_policy_version_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],policy_version='wrong')
    with pytest.raises(InferenceSpeculativeServingRejected): InferenceSpeculativeServingAnalyzer(f['policy'])
def test_07_policy_service_coverage_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_service_role_by_id={'prefill-svc-01':ServiceRole.PREFILL})
    with pytest.raises(InferenceSpeculativeServingRejected): InferenceSpeculativeServingAnalyzer(f['policy'])
def test_08_policy_digest_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_p10c_assessment_sha256='bad')
    with pytest.raises(InferenceSpeculativeServingRejected): InferenceSpeculativeServingAnalyzer(f['policy'])
def test_09_manifest_digest_pin():
    f=build_fixture(); f['manifest']=replace(f['manifest'],network_operations=1)
    with pytest.raises(InferenceSpeculativeServingRejected): ev(f)
def test_10_stale_request():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+301)
    with pytest.raises(InferenceSpeculativeServingRejected): ev(f)
def test_11_future_skew():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch-6)
    with pytest.raises(InferenceSpeculativeServingRejected): ev(f)
def test_12_upstream_decision():
    f=build_fixture(); f['p10c']=replace(f['p10c'],decision=CacheDecision.DENY); assert ServingRisk.UPSTREAM_P10C_INVALID in risk(f)
def test_13_upstream_risk():
    f=build_fixture(); f['p10c']=replace(f['p10c'],risks=(CacheRisk.CACHE_OWNER_MISMATCH,)); assert ServingRisk.UPSTREAM_P10C_INVALID in risk(f)
def test_14_upstream_digest():
    f=build_fixture(); f['p10c']=replace(f['p10c'],assessment_evidence_sha256='0'*64); assert ServingRisk.UPSTREAM_BINDING_MISMATCH in risk(f)
def test_15_route_mismatch():
    f=build_fixture(); m=replace(f['manifest'],request_id='request-beta-0001'); f=rebind(f,m,keep_policy_pins=False); assert ServingRisk.REQUEST_ROUTE_MISMATCH in risk(f)
def test_16_target_model_mismatch():
    f=build_fixture(); m=replace(f['manifest'],target_model_sha256=h('bad-target')); f=rebind(f,m,keep_policy_pins=False); assert ServingRisk.TARGET_MODEL_MISMATCH in risk(f)
def test_17_draft_model_mismatch():
    f=build_fixture(); m=replace(f['manifest'],draft_model_revision='draft-attacker'); f=rebind(f,m,keep_policy_pins=False); assert ServingRisk.DRAFT_MODEL_MISMATCH in risk(f)
def test_18_draft_trust_mismatch():
    f=build_fixture(); m=replace(f['manifest'],draft_trust_profile_sha256=h('bad-trust')); f=rebind(f,m,keep_policy_pins=False); assert ServingRisk.DRAFT_TRUST_MISMATCH in risk(f)
def test_19_tokenizer_mismatch():
    f=build_fixture(); m=replace(f['manifest'],tokenizer_sha256=h('bad-tokenizer')); f=rebind(f,m,keep_policy_pins=False); assert ServingRisk.TOKENIZER_MISMATCH in risk(f)
def test_20_service_role(): assert ServingRisk.SERVICE_ROLE_MISMATCH in risk(smut(1,role=ServiceRole.DECODE))
def test_21_service_identity(): assert ServingRisk.SERVICE_IDENTITY_MISMATCH in risk(smut(0,service_identity_sha256=h('bad-identity')))
def test_22_cross_tenant_transfer(): assert ServingRisk.CROSS_TENANT_STATE_TRANSFER in risk(tmut(0,tenant_id='beta'))
def test_23_cross_session_transfer(): assert ServingRisk.CROSS_SESSION_STATE_TRANSFER in risk(tmut(0,session_id='tenant/acme/session/other'))
def test_24_transfer_digest(): assert ServingRisk.STATE_TRANSFER_DIGEST_MISMATCH in risk(tmut(1,state_sha256=h('bad-state')))
def test_25_transfer_replay():
    f=build_fixture(); tid=f['manifest'].transfers[0].transfer_id; ids=f['manifest'].prior_transfer_ids+(tid,); m=replace(f['manifest'],prior_transfer_ids=ids,prior_transfer_ledger_sha256=prior_transfer_ledger_digest(ids)); f=rebind(f,m,keep_policy_pins=False); assert ServingRisk.STATE_TRANSFER_REPLAY in risk(f)
def test_26_partial_target_verification(): assert ServingRisk.TARGET_VERIFICATION_MISMATCH in risk(rmut(target_verified_token_count=3,accepted_token_count=3,rejected_token_count=1))
def test_27_unverified_acceptance(): assert ServingRisk.UNVERIFIED_DRAFT_ACCEPTANCE in risk(rmut(target_verified_token_count=2,accepted_token_count=3,rejected_token_count=1))
def test_28_final_state_mismatch():
    f=build_fixture(); m=replace(f['manifest'],final_state_sha256=h('bad-final')); f=rebind(f,m,keep_policy_pins=False); assert ServingRisk.FINAL_STATE_MISMATCH in risk(f)
def test_29_declared_summary_lie():
    f=build_fixture(); f['request']=replace(f['request'],declared_tenant_id='beta')
    with pytest.raises(InferenceSpeculativeServingRejected): ev(f)
def test_30_vulnerable_corpus():
    v=VulnerableCallerDeclaredSpeculativeServingSafety(); assert all(v.accepts(replace(a(build_fixture())['request'],declared_serving_safe=True)) for _,a in CASES)
def test_31_hardened_corpus():
    for name,a in CASES:
        f=a(build_fixture())
        try: accepted=ev(f).decision==ServingDecision.ALLOW
        except InferenceSpeculativeServingRejected: accepted=False
        assert not accepted,name
def test_32_safe_variants(): assert len(_safe_cases())==4 and all(ev(f).decision==ServingDecision.ALLOW for f in _safe_cases())
def test_33_reject_all_draft_safe():
    a=ev(safe_reject_all_draft_fixture()); assert a.decision==ServingDecision.ALLOW and a.speculative_verification_verified
def test_34_metrics():
    r=run(); n=r['adversarial_cases']; assert n>=120 and r['vulnerable_asr']==f'{n}/{n}' and r['hardened_asr']==f'0/{n}' and r['hardened_fpr']=='0/4' and r['safe_task_rate']=='4/4' and r['decision']=='allow'
