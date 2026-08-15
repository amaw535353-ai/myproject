from __future__ import annotations
from dataclasses import replace
import pytest
from aegis.inference.adapter_routing_security import InferenceAdapterRoutingAnalyzer
from aegis.inference.adapter_routing_types import *
from aegis.inference.speculative_serving_types import ServingDecision,ServingRisk
from aegis.vulnerable.adapter_routing import VulnerableCallerDeclaredAdapterRoutingSafety
from evals.p10e_fixture import *
from evals.p10e_adapter_routing import CASES,_safe_cases,run

def ev(f): return InferenceAdapterRoutingAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10d'])
def risk(f): return InferenceAdapterRoutingAnalyzer(f['policy']).derive(f['manifest'],f['p10d'])
def amut(i,**kw):
    f=build_fixture(); m=f['manifest']; xs=list(m.adapters); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,adapters=tuple(xs)),keep_policy_pins=False)
def test_01_canonical_allow(): assert ev(build_fixture()).decision==AdapterDecision.ALLOW
def test_02_canonical_no_risks(): assert ev(build_fixture()).risks==()
def test_03_schema_mode():
    a=ev(build_fixture()); assert (a.assessment_schema_version,a.assessment_mode)==(P10E_ASSESSMENT_SCHEMA_VERSION,P10E_ASSESSMENT_MODE)
def test_04_verified_flags():
    a=ev(build_fixture()); assert all((a.upstream_p10d_bound,a.base_route_verified,a.adapter_artifacts_verified,a.tenant_composition_verified,a.authorization_verified,a.hot_swap_verified,a.route_snapshot_verified))
def test_05_claim_boundary():
    a=ev(build_fixture()); assert not any((a.caller_declared_safety_trusted,a.production_adapter_manager_integrated,a.production_model_router_integrated,a.cryptographic_adapter_signature_verified,a.atomic_hot_swap_validated,a.distributed_route_consistency_validated,a.side_channel_resistance_validated))
def test_06_policy_version_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],policy_version='wrong')
    with pytest.raises(InferenceAdapterRoutingRejected): InferenceAdapterRoutingAnalyzer(f['policy'])
def test_07_policy_adapter_maps_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_adapter_artifact_sha256_by_id={})
    with pytest.raises(InferenceAdapterRoutingRejected): InferenceAdapterRoutingAnalyzer(f['policy'])
def test_08_policy_digest_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_p10d_assessment_sha256='bad')
    with pytest.raises(InferenceAdapterRoutingRejected): InferenceAdapterRoutingAnalyzer(f['policy'])
def test_09_manifest_digest_pin():
    f=build_fixture(); f['manifest']=replace(f['manifest'],network_operations=1)
    with pytest.raises(InferenceAdapterRoutingRejected): ev(f)
def test_10_stale_request():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+301)
    with pytest.raises(InferenceAdapterRoutingRejected): ev(f)
def test_11_future_skew():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch-6)
    with pytest.raises(InferenceAdapterRoutingRejected): ev(f)
def test_12_upstream_decision():
    f=build_fixture(); f['p10d']=replace(f['p10d'],decision=ServingDecision.DENY); assert AdapterRisk.UPSTREAM_P10D_INVALID in risk(f)
def test_13_upstream_risk():
    f=build_fixture(); f['p10d']=replace(f['p10d'],risks=(ServingRisk.SYNTHETIC,)); assert AdapterRisk.UPSTREAM_P10D_INVALID in risk(f)
def test_14_upstream_digest():
    f=build_fixture(); f['p10d']=replace(f['p10d'],assessment_evidence_sha256='0'*64); assert AdapterRisk.UPSTREAM_BINDING_MISMATCH in risk(f)
def test_15_upstream_route():
    f=build_fixture(); f['p10d']=replace(f['p10d'],request_id='request-other'); assert AdapterRisk.REQUEST_ROUTE_MISMATCH in risk(f)
def test_16_base_model_mismatch(): assert AdapterRisk.ADAPTER_BASE_BINDING_MISMATCH in risk(amut(0,base_model_sha256=h('bad-base')))
def test_17_adapter_tenant_mismatch(): assert AdapterRisk.ADAPTER_TENANT_MISMATCH in risk(amut(1,tenant_id='beta'))
def test_18_adapter_digest_mismatch(): assert AdapterRisk.ADAPTER_DIGEST_MISMATCH in risk(amut(0,artifact_sha256=h('bad-adapter')))
def test_19_adapter_format_unsafe(): assert AdapterRisk.ADAPTER_FORMAT_UNSAFE in risk(amut(0,serialization_format='pickle'))
def test_20_adapter_rank_policy(): assert AdapterRisk.ADAPTER_PARAMETER_POLICY_MISMATCH in risk(amut(0,rank=128))
def test_21_adapter_provenance(): assert AdapterRisk.ADAPTER_PROVENANCE_MISMATCH in risk(amut(1,provenance_sha256=h('forged-provenance')))
def test_22_composition_order():
    f=build_fixture(); m=f['manifest']; f=rebind(f,replace(m,route_after=replace(m.route_after,active_adapter_ids=tuple(reversed(ADAPTER_IDS)))),keep_policy_pins=False); assert AdapterRisk.ADAPTER_STACK_ORDER_MISMATCH in risk(f)
def test_23_authorization_principal():
    f=build_fixture(); m=f['manifest']; f=rebind(f,replace(m,authorization=replace(m.authorization,principal_id='principal-acme-attacker')),keep_policy_pins=False); assert AdapterRisk.AUTHORIZATION_INVALID in risk(f)
def test_24_authorization_expired():
    f=build_fixture(); m=f['manifest']; f=rebind(f,replace(m,authorization=replace(m.authorization,expires_at_epoch=m.created_at_epoch-1)),keep_policy_pins=False); assert AdapterRisk.AUTHORIZATION_EXPIRED in risk(f)
def test_25_swap_generation():
    f=build_fixture(); m=f['manifest']; f=rebind(f,replace(m,swaps=(replace(m.swaps[0],to_generation=13),)),keep_policy_pins=False); assert AdapterRisk.HOT_SWAP_GENERATION_MISMATCH in risk(f)
def test_26_swap_replay():
    f=build_fixture(); m=f['manifest']; ids=m.prior_swap_ids+(m.swaps[0].swap_id,); f=rebind(f,replace(m,prior_swap_ids=ids,prior_swap_ledger_sha256=prior_swap_ledger_digest(ids)),keep_policy_pins=False); assert AdapterRisk.HOT_SWAP_REPLAY in risk(f)
def test_27_route_snapshot_digest():
    f=build_fixture(); m=f['manifest']; f=rebind(f,replace(m,route_after=replace(m.route_after,composition_sha256=h('bad-composition'))),keep_policy_pins=False); assert AdapterRisk.ROUTE_SNAPSHOT_MISMATCH in risk(f)
def test_28_retired_resurrection():
    f=build_fixture(); m=f['manifest']; f=rebind(f,replace(m,retired_adapter_ids=m.retired_adapter_ids+('adapter-acme-helpdesk',)),keep_policy_pins=False); assert AdapterRisk.RETIRED_ADAPTER_RESURRECTED in risk(f)
def test_29_declared_summary_lie():
    f=build_fixture(); f['request']=replace(f['request'],declared_after_generation=99)
    with pytest.raises(InferenceAdapterRoutingRejected): ev(f)
def test_30_vulnerable_corpus():
    v=VulnerableCallerDeclaredAdapterRoutingSafety(); assert all(v.accepts(replace(a(build_fixture())['request'],declared_adapter_routing_safe=True)) for _,a in CASES)
def test_31_hardened_corpus():
    for name,a in CASES:
        f=a(build_fixture())
        try: accepted=ev(f).decision==AdapterDecision.ALLOW
        except InferenceAdapterRoutingRejected: accepted=False
        assert not accepted,name
def test_32_safe_variants(): assert len(_safe_cases())==4 and all(ev(f).decision==AdapterDecision.ALLOW for f in _safe_cases())
def test_33_metrics():
    r=run(); n=r['adversarial_cases']; assert n>=120 and r['vulnerable_asr']==f'{n}/{n}' and r['hardened_asr']==f'0/{n}' and r['hardened_fpr']=='0/4' and r['safe_task_rate']=='4/4' and r['decision']=='allow'
def test_34_manifest_hash_stable():
    f=build_fixture(); assert f['request'].manifest_sha256==inference_adapter_routing_manifest_digest(f['manifest'])
def test_35_authorization_hash_bound_to_swap():
    f=build_fixture(); assert f['manifest'].swaps[0].authorization_sha256==adapter_authorization_digest(f['manifest'].authorization)
def test_36_route_composition_binds_adapter_artifacts():
    f=build_fixture(); m=f['manifest']; amap={a.adapter_id:a.artifact_sha256 for a in m.adapters}; assert m.route_after.composition_sha256==adapter_composition_digest(m.target_model_sha256,m.tokenizer_sha256,m.route_after.active_adapter_ids,amap)
