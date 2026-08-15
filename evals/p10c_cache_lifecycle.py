from __future__ import annotations
from dataclasses import replace
import hashlib,json
from aegis.inference.cache_lifecycle_security import InferenceCacheLifecycleAnalyzer
from aegis.inference.cache_lifecycle_types import *
from aegis.inference.scheduler_security_types import SchedulerDecision,SchedulerRisk
from aegis.vulnerable.cache_lifecycle import VulnerableCallerDeclaredCacheLifecycleSafety
from evals.p10c_fixture import build_fixture,h,rebind,safe_rollback_fixture

def _manifest(f,**kw): return rebind(f,replace(f['manifest'],**kw),keep_policy_pins=False)
def _request(f,**kw): return {**f,'request':replace(f['request'],**kw)}
def _policy(f,**kw): return {**f,'policy':replace(f['policy'],**kw)}
def _up(f,**kw): return {**f,'p10b':replace(f['p10b'],**kw)}
def _entry(f,i,**kw):
    m=f['manifest']; xs=list(m.entries); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,entries=tuple(xs)),keep_policy_pins=False)
def _reuse(f,**kw):
    m=f['manifest']; r=replace(m.reuses[0],**kw); return rebind(f,replace(m,reuses=(r,)),keep_policy_pins=False)
def _rollback(f,**kw): return _manifest(f,rollback=replace(f['manifest'].rollback,**kw))

CASES=[
('manifest-schema',lambda f:_manifest(f,schema_version='wrong-schema')),
('manifest-id-pin',lambda f:rebind(f,replace(f['manifest'],manifest_id='p10c-other'),keep_policy_pins=True)),
('manifest-created-zero',lambda f:_manifest(f,created_at_epoch=0)),
('manifest-cache-epoch',lambda f:_manifest(f,cache_epoch=6)),
('manifest-upstream-digest',lambda f:_manifest(f,p10b_assessment_sha256=h('forged-p10b'))),
('manifest-scheduler',lambda f:_manifest(f,upstream_scheduler_id='scheduler-attacker')),
('manifest-batch',lambda f:_manifest(f,upstream_batch_id='sched-batch-attacker')),
('manifest-zero-method',lambda f:_manifest(f,zeroization_method_sha256=h('wrong-zero-method'))),
('network-operation',lambda f:_manifest(f,network_operations=1)),
('request-stale',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch+301)),
('request-too-early',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch-6)),
('request-manifest-id',lambda f:_request(f,manifest_id='caller-other')),
('request-manifest-digest',lambda f:_request(f,manifest_sha256=h('caller-manifest'))),
('policy-version',lambda f:_policy(f,policy_version='wrong-policy')),
('policy-p10b-sha',lambda f:_policy(f,expected_p10b_assessment_sha256='bad')),
('policy-tenant-map',lambda f:_policy(f,max_active_entries_by_tenant={'acme':4,'beta':3})),
('policy-zero-method',lambda f:_policy(f,expected_zeroization_method_sha256='bad')),
('policy-generation-map-empty',lambda f:_policy(f,min_generation_by_namespace={})),
]
CASES += [
('p10b-decision-deny',lambda f:_up(f,decision=SchedulerDecision.DENY)),
('p10b-risk',lambda f:_up(f,risks=(SchedulerRisk.SYNTHETIC,))),
('p10b-schema',lambda f:_up(f,assessment_schema_version='wrong-schema')),
('p10b-mode',lambda f:_up(f,assessment_mode='caller-mode')),
('p10b-digest',lambda f:_up(f,assessment_evidence_sha256=h('wrong-p10b'))),
('p10b-scheduler',lambda f:_up(f,scheduler_id='scheduler-inference-02')),
('p10b-batch',lambda f:_up(f,batch_id='sched-batch-0099')),
]
for field in ('upstream_p10a_bound','scheduler_identity_verified','admission_limits_verified','tenant_resource_isolation_verified','weighted_fairness_verified','starvation_bounds_verified','batch_plan_verified'):
    CASES.append((f'p10b-flag-{field}',lambda f,field=field:_up(f,**{field:False})))
for field in ('caller_declared_safety_trusted','production_scheduler_integrated','production_gpu_quota_enforced','production_distributed_fairness_validated','production_autoscaler_integrated','side_channel_resistance_validated'):
    CASES.append((f'p10b-nonclaim-{field}',lambda f,field=field:_up(f,**{field:True})))
for i in range(5):
    CASES += [
      (f'entry-{i}-tenant',lambda f,i=i:_entry(f,i,tenant_id='attacker')),
      (f'entry-{i}-session',lambda f,i=i:_entry(f,i,session_id='tenant/attacker/session/x')),
      (f'entry-{i}-namespace',lambda f,i=i:_entry(f,i,namespace='shared/cache/global')),
      (f'entry-{i}-epoch',lambda f,i=i:_entry(f,i,epoch=4)),
      (f'entry-{i}-generation',lambda f,i=i:_entry(f,i,generation=max(0,f['manifest'].entries[i].generation-1))),
      (f'entry-{i}-key',lambda f,i=i:_entry(f,i,key_sha256=h(f'forged-key-{i}'))),
      (f'entry-{i}-payload',lambda f,i=i:_entry(f,i,payload_sha256=h(f'forged-payload-{i}'))),
      (f'entry-{i}-stale',lambda f,i=i:_entry(f,i,created_at_epoch=f['manifest'].created_at_epoch-200,last_access_epoch=f['manifest'].created_at_epoch-121)),
    ]
CASES=[x for x in CASES if x[0]!='entry-3-stale']
CASES += [
('active-eviction-timestamp',lambda f:_entry(f,0,evicted_at_epoch=f['manifest'].created_at_epoch-1)),
('active-zeroized-timestamp',lambda f:_entry(f,1,zeroized_at_epoch=f['manifest'].created_at_epoch-1)),
('zeroized-to-evicted',lambda f:_entry(f,3,state=CacheState.EVICTED,zeroized_at_epoch=0)),
('zeroized-missing-eviction',lambda f:_entry(f,3,evicted_at_epoch=0)),
('zeroized-time-order',lambda f:_entry(f,3,zeroized_at_epoch=f['manifest'].entries[3].evicted_at_epoch-1)),
('zeroized-receipt',lambda f:_entry(f,3,zeroization_receipt_sha256=h('forged-receipt'))),
('retired-resurrected',lambda f:_manifest(f,prior_retired_entry_ids=f['manifest'].prior_retired_entry_ids+(f['manifest'].entries[0].entry_id,),prior_retired_ledger_sha256=retired_ledger_digest(f['manifest'].prior_retired_entry_ids+(f['manifest'].entries[0].entry_id,)))),
('retired-ledger-digest',lambda f:_manifest(f,prior_retired_ledger_sha256=h('forged-retired-ledger'))),
('retired-ledger-drop',lambda f:_manifest(f,prior_retired_entry_ids=f['manifest'].prior_retired_entry_ids[:-1])),
('cache-capacity',lambda f:_policy(f,max_active_entries_by_tenant={**f['policy'].max_active_entries_by_tenant,'acme':1})),
]
CASES += [
('reuse-source',lambda f:_reuse(f,source_entry_id='cache-kv-beta-g3')),
('reuse-target',lambda f:_reuse(f,target_entry_id='cache-kv-beta-g3')),
('reuse-tenant',lambda f:_reuse(f,tenant_id='beta')),
('reuse-session',lambda f:_reuse(f,session_id='tenant/beta/shared-prefix')),
('reuse-source-generation',lambda f:_reuse(f,source_generation=1)),
('reuse-target-generation',lambda f:_reuse(f,target_generation=99)),
('reuse-source-key',lambda f:_reuse(f,source_key_sha256=h('wrong-source-key'))),
('reuse-target-key',lambda f:_reuse(f,target_key_sha256=h('wrong-target-key'))),
('reuse-parent',lambda f:_entry(f,2,parent_entry_id='cache-prefix-acme-g3')),
('reuse-source-zeroized',lambda f:_entry(f,1,state=CacheState.ZEROIZED,evicted_at_epoch=f['manifest'].created_at_epoch-4,zeroized_at_epoch=f['manifest'].created_at_epoch-3,zeroization_receipt_sha256=h('not-valid'))),
('kv-cross-session-reuse',lambda f:_manifest(f,reuses=(CacheReuseEvidence('reuse-kv-cross-0001','cache-kv-beta-g2-retired','cache-kv-beta-g3','request-beta-0001','beta','tenant/beta/session/other',2,3,f['manifest'].entries[3].key_sha256,f['manifest'].entries[4].key_sha256),))),
]
CASES += [
('rollback-wrong-auth',lambda f:_rollback(f,requested=True,authorization_sha256=h('wrong-auth'))),
('rollback-wrong-tenant',lambda f:_rollback(f,requested=True,tenant_id='beta',authorization_sha256=h('rollback-auth:beta'))),
('rollback-wrong-session',lambda f:_rollback(f,requested=True,session_id='tenant/acme/session/other')),
('rollback-wrong-target',lambda f:_rollback(f,requested=True,target_entry_id='cache-kv-beta-g3')),
('rollback-equal-generation',lambda f:_rollback(f,requested=True,current_generation=5,target_generation=5)),
('rollback-forward-generation',lambda f:_rollback(f,requested=True,current_generation=4,target_generation=5)),
('rollback-retired-target',lambda f:_manifest(f,rollback=replace(f['manifest'].rollback,requested=True,target_entry_id='cache-prefix-acme-g5'),prior_retired_entry_ids=f['manifest'].prior_retired_entry_ids+('cache-prefix-acme-g5',),prior_retired_ledger_sha256=retired_ledger_digest(f['manifest'].prior_retired_entry_ids+('cache-prefix-acme-g5',)))),
]
SUM={'declared_scheduler_id':'scheduler-attacker','declared_batch_id':'sched-batch-other','declared_cache_epoch':99,'declared_active_entry_ids':('cache-kv-acme-g3',),'declared_zeroized_entry_ids':(), 'declared_upstream_p10b_bound':False,'declared_ownership_safe':False,'declared_reuse_isolation_safe':False,'declared_eviction_safe':False,'declared_zeroization_safe':False,'declared_rollback_safe':False,'declared_cache_lifecycle_safe':False}
for field,value in SUM.items(): CASES.append((f'summary-{field}',lambda f,field=field,value=value:_request(f,**{field:value})))
EXPECTED_ADVERSARIAL_CASES=len(CASES)

def _hardened(f):
    try: return InferenceCacheLifecycleAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10b']).decision==CacheDecision.ALLOW
    except InferenceCacheLifecycleRejected: return False
def _safe_cases():
    a=build_fixture(); b=build_fixture(); b['request']=replace(b['request'],evaluated_at_epoch=b['manifest'].created_at_epoch+20); c=build_fixture(); c['request']=replace(c['request'],evaluated_at_epoch=c['manifest'].created_at_epoch+30); return [a,b,c,safe_rollback_fixture()]
def _dataset_digest(): return hashlib.sha256('\n'.join(n for n,_ in CASES).encode()).hexdigest()
def _fixture_digest():
    f=build_fixture(); material={'manifest':f['request'].manifest_sha256,'policy':f['policy'].policy_version,'cases':_dataset_digest(),'p10b':f['p10b'].assessment_evidence_sha256}; return hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def run():
    v=VulnerableCallerDeclaredCacheLifecycleSafety(); va=ha=0; accepted=[]
    for name,attack in CASES:
        f=attack(build_fixture()); req=replace(f['request'],declared_cache_lifecycle_safe=True); va+=int(v.accepts(req)); ok=_hardened(f); ha+=int(ok); accepted += [name] if ok else []
    safe=_safe_cases(); failures=sum(not _hardened(f) for f in safe); f=build_fixture(); a=InferenceCacheLifecycleAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10b'])
    return {'adversarial_cases':len(CASES),'vulnerable_asr':f'{va}/{len(CASES)}','hardened_asr':f'{ha}/{len(CASES)}','accepted_attacks':accepted,'hardened_fpr':f'{failures}/{len(safe)}','safe_task_rate':f'{len(safe)-failures}/{len(safe)}','cache_manifest_sha256':f['request'].manifest_sha256,'adversarial_dataset_sha256':_dataset_digest(),'fixture_evaluator_sha256':_fixture_digest(),'clean_assessment_sha256':a.assessment_evidence_sha256,'decision':a.decision.value}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
