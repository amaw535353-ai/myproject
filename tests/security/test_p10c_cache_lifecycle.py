from __future__ import annotations
from dataclasses import replace
import pytest
from aegis.inference.cache_lifecycle_security import InferenceCacheLifecycleAnalyzer
from aegis.inference.cache_lifecycle_types import *
from aegis.inference.scheduler_security_types import SchedulerDecision,SchedulerRisk
from aegis.vulnerable.cache_lifecycle import VulnerableCallerDeclaredCacheLifecycleSafety
from evals.p10c_fixture import build_fixture,rebind,safe_rollback_fixture,h
from evals.p10c_cache_lifecycle import CASES,_safe_cases,run

def ev(f): return InferenceCacheLifecycleAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10b'])
def risk(f): return InferenceCacheLifecycleAnalyzer(f['policy']).derive(f['manifest'],f['p10b'])
def emut(i,**kw):
    f=build_fixture(); m=f['manifest']; xs=list(m.entries); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,entries=tuple(xs)),keep_policy_pins=False)
def test_01_canonical_allow(): assert ev(build_fixture()).decision==CacheDecision.ALLOW
def test_02_canonical_no_risks(): assert ev(build_fixture()).risks==()
def test_03_schema_mode():
    a=ev(build_fixture()); assert (a.assessment_schema_version,a.assessment_mode)==(P10C_ASSESSMENT_SCHEMA_VERSION,P10C_ASSESSMENT_MODE)
def test_04_verified_flags():
    a=ev(build_fixture()); assert all((a.upstream_p10b_bound,a.ownership_verified,a.reuse_isolation_verified,a.eviction_verified,a.zeroization_verified,a.rollback_safety_verified))
def test_05_claim_boundary():
    a=ev(build_fixture()); assert not any((a.caller_declared_safety_trusted,a.production_cache_manager_integrated,a.physical_memory_zeroization_verified,a.distributed_cache_coherence_validated,a.gpu_allocator_integrated,a.side_channel_resistance_validated))
def test_06_policy_version_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],policy_version='wrong')
    with pytest.raises(InferenceCacheLifecycleRejected): InferenceCacheLifecycleAnalyzer(f['policy'])
def test_07_policy_map_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],max_active_entries_by_tenant={'acme':4})
    with pytest.raises(InferenceCacheLifecycleRejected): InferenceCacheLifecycleAnalyzer(f['policy'])
def test_08_policy_digest_rejected():
    f=build_fixture(); f['policy']=replace(f['policy'],expected_p10b_assessment_sha256='bad')
    with pytest.raises(InferenceCacheLifecycleRejected): InferenceCacheLifecycleAnalyzer(f['policy'])
def test_09_manifest_digest_pin():
    f=build_fixture(); f['manifest']=replace(f['manifest'],network_operations=1)
    with pytest.raises(InferenceCacheLifecycleRejected): ev(f)
def test_10_stale_request():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+301)
    with pytest.raises(InferenceCacheLifecycleRejected): ev(f)
def test_11_future_skew():
    f=build_fixture(); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch-6)
    with pytest.raises(InferenceCacheLifecycleRejected): ev(f)
def test_12_upstream_decision():
    f=build_fixture(); f['p10b']=replace(f['p10b'],decision=SchedulerDecision.DENY); assert CacheRisk.UPSTREAM_P10B_INVALID in risk(f)
def test_13_upstream_risk():
    f=build_fixture(); f['p10b']=replace(f['p10b'],risks=('synthetic-risk',)); assert CacheRisk.UPSTREAM_P10B_INVALID in risk(f)
def test_14_upstream_digest():
    f=build_fixture(); f['p10b']=replace(f['p10b'],assessment_evidence_sha256='0'*64); assert CacheRisk.UPSTREAM_BINDING_MISMATCH in risk(f)
def test_15_owner_mismatch(): assert CacheRisk.CACHE_OWNER_MISMATCH in risk(emut(0,tenant_id='beta'))
def test_16_namespace_mismatch(): assert CacheRisk.CACHE_NAMESPACE_MISMATCH in risk(emut(0,namespace='shared/cache/global'))
def test_17_epoch_mismatch(): assert CacheRisk.CACHE_EPOCH_MISMATCH in risk(emut(0,epoch=4))
def test_18_stale_active():
    f=build_fixture(); now=f['manifest'].created_at_epoch; assert CacheRisk.STALE_ACTIVE_ENTRY in risk(emut(0,created_at_epoch=now-200,last_access_epoch=now-121))
def test_19_zeroization_missing(): assert CacheRisk.ZEROIZATION_MISSING in risk(emut(3,state=CacheState.EVICTED,zeroized_at_epoch=0))
def test_20_zeroization_receipt(): assert CacheRisk.ZEROIZATION_RECEIPT_MISMATCH in risk(emut(3,zeroization_receipt_sha256=h('bad-receipt')))
def test_21_retired_resurrection():
    f=build_fixture(); e=f['manifest'].entries[0]; ids=f['manifest'].prior_retired_entry_ids+(e.entry_id,); m=replace(f['manifest'],prior_retired_entry_ids=ids,prior_retired_ledger_sha256=retired_ledger_digest(ids)); f=rebind(f,m,keep_policy_pins=False); assert CacheRisk.RETIRED_ENTRY_RESURRECTED in risk(f)
def test_22_cross_tenant_reuse():
    f=build_fixture(); m=f['manifest']; r=replace(m.reuses[0],tenant_id='beta'); f=rebind(f,replace(m,reuses=(r,)),keep_policy_pins=False); assert CacheRisk.CROSS_TENANT_REUSE in risk(f)
def test_23_reuse_generation():
    f=build_fixture(); m=f['manifest']; r=replace(m.reuses[0],target_generation=99); f=rebind(f,replace(m,reuses=(r,)),keep_policy_pins=False); assert CacheRisk.PREFIX_REUSE_MISMATCH in risk(f)
def test_24_rollback_auth():
    f=safe_rollback_fixture(); f['manifest']=replace(f['manifest'],rollback=replace(f['manifest'].rollback,authorization_sha256=h('wrong'))); f=rebind(f,f['manifest'],keep_policy_pins=False); assert CacheRisk.ROLLBACK_UNAUTHORIZED in risk(f)
def test_25_rollback_safe_variant(): assert ev(safe_rollback_fixture()).decision==CacheDecision.ALLOW
def test_26_declared_summary_lie():
    f=build_fixture(); f['request']=replace(f['request'],declared_cache_epoch=99)
    with pytest.raises(InferenceCacheLifecycleRejected): ev(f)
def test_27_vulnerable_corpus():
    v=VulnerableCallerDeclaredCacheLifecycleSafety(); assert all(v.accepts(replace(a(build_fixture())['request'],declared_cache_lifecycle_safe=True)) for _,a in CASES)
def test_28_hardened_corpus():
    for name,a in CASES:
        f=a(build_fixture())
        try: accepted=ev(f).decision==CacheDecision.ALLOW
        except InferenceCacheLifecycleRejected: accepted=False
        assert not accepted,name
def test_29_safe_variants(): assert len(_safe_cases())==4 and all(ev(f).decision==CacheDecision.ALLOW for f in _safe_cases())
def test_30_metrics():
    r=run(); n=r['adversarial_cases']; assert n>=100 and r['vulnerable_asr']==f'{n}/{n}' and r['hardened_asr']==f'0/{n}' and r['hardened_fpr']=='0/4' and r['safe_task_rate']=='4/4' and r['decision']=='allow'
