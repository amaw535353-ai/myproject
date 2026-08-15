from __future__ import annotations
from dataclasses import replace
import pytest
from aegis.inference.tenant_isolation_security import InferenceTenantIsolationAnalyzer
from aegis.inference.tenant_isolation_types import *
from aegis.vulnerable.inference_tenant_isolation import VulnerableCallerDeclaredInferenceIsolation
from evals.p10a_fixture import beta_safe_fixture,build_fixture,h,rebind
from evals.p10a_inference_tenant_isolation import CASES,_safe_cases,run

def ev(f): return InferenceTenantIsolationAnalyzer(f['policy']).evaluate(f['request'],f['manifest'])
def risk(f): return InferenceTenantIsolationAnalyzer(f['policy']).derive(f['manifest'])
def mut(obj,**kw):
    f=build_fixture(); m=f['manifest']; return rebind(f,replace(m,**{obj:replace(getattr(m,obj),**kw)}),keep_policy_pins=False)
def test_01_canonical_allow(): assert ev(build_fixture()).decision==InferenceDecision.ALLOW
def test_02_canonical_no_risks(): assert ev(build_fixture()).risks==()
def test_03_schema_mode():
    a=ev(build_fixture()); assert (a.assessment_schema_version,a.assessment_mode)==(P10A_ASSESSMENT_SCHEMA_VERSION,P10A_ASSESSMENT_MODE)
def test_04_derived_flags():
    a=ev(build_fixture()); assert all((a.upstream_deployment_bound,a.upstream_promotion_bound,a.route_identity_verified,a.request_identity_verified,a.batch_isolation_verified,a.kv_and_prefix_cache_isolation_verified,a.output_binding_verified,a.request_replay_clear))
def test_05_claim_boundary():
    a=ev(build_fixture()); assert not any((a.caller_declared_safety_trusted,a.production_inference_gateway_integrated,a.production_scheduler_isolation_enforced,a.production_kv_cache_memory_isolation_verified,a.side_channel_resistance_validated,a.hardware_attestation_verified))
def test_06_policy_version():
    f=build_fixture(); f['policy']=replace(f['policy'],policy_version='wrong');
    with pytest.raises(InferenceTenantIsolationRejected): InferenceTenantIsolationAnalyzer(f['policy'])
def test_07_policy_sha():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_model_artifact_sha256='bad');
    with pytest.raises(InferenceTenantIsolationRejected): InferenceTenantIsolationAnalyzer(f['policy'])
def test_08_policy_map_coverage():
    f=build_fixture(); f['policy']=replace(f['policy'],allowed_principal_ids_by_tenant={'acme':('principal-acme-agent',)});
    with pytest.raises(InferenceTenantIsolationRejected): InferenceTenantIsolationAnalyzer(f['policy'])
def test_09_policy_mutable_revision():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_revision='latest');
    with pytest.raises(InferenceTenantIsolationRejected): InferenceTenantIsolationAnalyzer(f['policy'])
def test_10_manifest_schema():
    f=build_fixture(); f=rebind(f,replace(f['manifest'],schema_version='wrong'),keep_policy_pins=False)
    with pytest.raises(InferenceTenantIsolationRejected): ev(f)
def test_11_manifest_digest_pin():
    f=build_fixture(); f['manifest']=replace(f['manifest'],network_operations=1)
    with pytest.raises(InferenceTenantIsolationRejected): ev(f)
def test_12_stale():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+301)
    with pytest.raises(InferenceTenantIsolationRejected): ev(f)
def test_13_future_skew():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch-6)
    with pytest.raises(InferenceTenantIsolationRejected): ev(f)
def test_14_cross_tenant_batch(): assert InferenceRisk.CROSS_TENANT_BATCH in risk(mut('batch',tenant_ids=('acme','beta'),mixed_tenant_batch=True))
def test_15_kv_owner_swap(): assert InferenceRisk.KV_CACHE_BINDING_MISMATCH in risk(mut('cache',kv_cache_owner_tenant_id='beta'))
def test_16_prefix_reuse(): assert InferenceRisk.CROSS_TENANT_CACHE_REUSE in risk(mut('cache',allow_cross_tenant_reuse=True))
def test_17_adapter_swap(): assert InferenceRisk.ADAPTER_ROUTE_MISMATCH in risk(mut('route',adapter_id='adapter-attacker'))
def test_18_draft_swap(): assert InferenceRisk.DRAFT_MODEL_ROUTE_MISMATCH in risk(mut('route',draft_model_id='draft-attacker-model'))
def test_19_output_swap(): assert InferenceRisk.OUTPUT_BINDING_MISMATCH in risk(mut('output',recipient_tenant_id='beta'))
def test_20_replay():
    f=build_fixture(); ids=f['manifest'].prior_request_ids+(f['manifest'].request_identity.request_id,); m=replace(f['manifest'],prior_request_ids=ids,prior_request_ledger_sha256=prior_request_ledger_digest(ids)); f=rebind(f,m,keep_policy_pins=False); assert InferenceRisk.REQUEST_REPLAY in risk(f)
def test_21_deployment_swap():
    f=build_fixture(); f=rebind(f,replace(f['manifest'],deployment_attestation_sha256=h('swap')),keep_policy_pins=False); assert InferenceRisk.UPSTREAM_DEPLOYMENT_BINDING_MISMATCH in risk(f)
def test_22_promotion_swap():
    f=build_fixture(); f=rebind(f,replace(f['manifest'],p9h_promotion_assessment_sha256=h('swap-promotion')),keep_policy_pins=False); assert InferenceRisk.UPSTREAM_PROMOTION_BINDING_MISMATCH in risk(f)
def test_23_mutable_route(): assert InferenceRisk.MUTABLE_ROUTE_UNSAFE in risk(mut('route',revision='latest'))
def test_24_identity_summary_lie():
    f=build_fixture(); f['request']=replace(f['request'],declared_tenant_id='beta')
    with pytest.raises(InferenceTenantIsolationRejected): ev(f)
def test_25_safety_summary_lie():
    f=mut('cache',allow_cross_tenant_reuse=True)
    with pytest.raises(InferenceTenantIsolationRejected): ev(f)
def test_26_vulnerable_corpus():
    v=VulnerableCallerDeclaredInferenceIsolation(); assert all(v.accepts(a(build_fixture())['request']) for _,a in CASES)
def test_27_hardened_corpus():
    for name,a in CASES:
        f=a(build_fixture())
        try: accepted=ev(f).decision==InferenceDecision.ALLOW
        except InferenceTenantIsolationRejected: accepted=False
        assert not accepted,name
def test_28_safe_variants(): assert len(_safe_cases())==4 and all(ev(f).decision==InferenceDecision.ALLOW for f in _safe_cases())
def test_29_beta_safe():
    a=ev(beta_safe_fixture()); assert (a.tenant_id,a.decision)==('beta',InferenceDecision.ALLOW)
def test_30_metrics():
    r=run(); n=r['adversarial_cases']; assert n==136 and r['vulnerable_asr']==f'{n}/{n}' and r['hardened_asr']==f'0/{n}' and r['hardened_fpr']=='0/4' and r['safe_task_rate']=='4/4' and r['decision']=='allow'
