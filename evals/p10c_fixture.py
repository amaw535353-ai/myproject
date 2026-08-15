from __future__ import annotations
from dataclasses import replace
import hashlib
from aegis.inference.scheduler_security_types import *
from aegis.inference.cache_lifecycle_types import *

NOW=1_800_030_200
MANIFEST_ID='p10c-cache-lifecycle-001'
P10B_CLEAN_ASSESSMENT_SHA256='a46197f548332077d3245fd10bc37d2a356b51e5f9e035add82a9751f68f0388'
def h(label:str)->str: return hashlib.sha256(label.encode()).hexdigest()
def p10b_assessment():
    return VerifiedInferenceSchedulerAssessment('p10b-scheduler-admission-001','scheduler-inference-01','sched-batch-0042','acme',SchedulerDecision.ALLOW,(),h('p10a-clean'),('request-acme-0001','request-acme-peer-0002','request-beta-0001','request-beta-0002','request-gamma-0001'),('request-acme-0001','request-acme-peer-0002'),('acme','beta','gamma'),1000,9,True,True,True,True,True,True,True,False,False,False,False,False,False,P10B_ASSESSMENT_SCHEMA_VERSION,P10B_ASSESSMENT_MODE,P10B_CLEAN_ASSESSMENT_SHA256)
ZERO_METHOD=h('zeroization-method:p10c:v1')
def _receipt(entry_id,payload): return digest_json({'entry_id':entry_id,'payload_sha256':payload,'zeroization_method_sha256':ZERO_METHOD})
def _entries():
    p1=h('payload:kv-acme-g3'); p2=h('payload:prefix-acme-g4'); p3=h('payload:prefix-acme-g5'); p4=h('payload:kv-beta-retired-g2'); p5=h('payload:kv-beta-g3')
    return (
      CacheEntryEvidence('cache-kv-acme-g3',CacheKind.KV,'acme','tenant/acme/session/s-001','tenant/acme/session/s-001/kv/epoch/5/gen/3',5,3,h('key:kv-acme'),p1,CacheState.ACTIVE,'cache-kv-acme-g2',NOW-50,NOW-5,0,0,'0'*64),
      CacheEntryEvidence('cache-prefix-acme-g4',CacheKind.PREFIX,'acme','tenant/acme/shared-prefix','tenant/acme/prefix-cache/epoch/5/gen/4',5,4,h('key:prefix-acme'),p2,CacheState.ACTIVE,'cache-prefix-acme-g3',NOW-80,NOW-10,0,0,'0'*64),
      CacheEntryEvidence('cache-prefix-acme-g5',CacheKind.PREFIX,'acme','tenant/acme/shared-prefix','tenant/acme/prefix-cache/epoch/5/gen/5',5,5,h('key:prefix-acme'),p3,CacheState.ACTIVE,'cache-prefix-acme-g4',NOW-20,NOW-2,0,0,'0'*64),
      CacheEntryEvidence('cache-kv-beta-g2-retired',CacheKind.KV,'beta','tenant/beta/session/s-009','tenant/beta/session/s-009/kv/epoch/5/gen/2',5,2,h('key:kv-beta-old'),p4,CacheState.ZEROIZED,'cache-kv-beta-g1',NOW-100,NOW-60,NOW-40,NOW-35,_receipt('cache-kv-beta-g2-retired',p4)),
      CacheEntryEvidence('cache-kv-beta-g3',CacheKind.KV,'beta','tenant/beta/session/s-009','tenant/beta/session/s-009/kv/epoch/5/gen/3',5,3,h('key:kv-beta'),p5,CacheState.ACTIVE,'cache-kv-beta-g2-retired',NOW-15,NOW-1,0,0,'0'*64),
    )
def _manifest():
    entries=_entries(); prior=('cache-retired-global-0001','cache-retired-global-0002')
    return InferenceCacheLifecycleManifest(P10C_SCHEMA_VERSION,MANIFEST_ID,NOW,P10B_CLEAN_ASSESSMENT_SHA256,'scheduler-inference-01','sched-batch-0042',5,ZERO_METHOD,entries,(CacheReuseEvidence('reuse-prefix-acme-0001','cache-prefix-acme-g4','cache-prefix-acme-g5','request-acme-0001','acme','tenant/acme/shared-prefix',4,5,h('key:prefix-acme'),h('key:prefix-acme')),),CacheRollbackEvidence(False,'rollback-none-0001','acme','tenant/acme/shared-prefix','tenant/acme/prefix-cache/epoch/5/gen/5',6,5,'cache-prefix-acme-g5',h('rollback-auth:acme')),prior,retired_ledger_digest(prior),0)
def request_for(m):
    active=tuple(e.entry_id for e in m.entries if e.state==CacheState.ACTIVE); zeroized=tuple(e.entry_id for e in m.entries if e.state==CacheState.ZEROIZED)
    return InferenceCacheLifecycleRequest(m.manifest_id,inference_cache_lifecycle_manifest_digest(m),m.created_at_epoch+10,m.upstream_scheduler_id,m.upstream_batch_id,m.cache_epoch,active,zeroized,True,True,True,True,True,True,True)
def build_fixture():
    m=_manifest(); floors={e.namespace:e.generation for e in m.entries}; ids=tuple(e.entry_id for e in m.entries); keys={e.entry_id:e.key_sha256 for e in m.entries}; payloads={e.entry_id:e.payload_sha256 for e in m.entries}; p=InferenceCacheLifecyclePolicy(P10C_POLICY_VERSION,MANIFEST_ID,inference_cache_lifecycle_manifest_digest(m),P10B_CLEAN_ASSESSMENT_SHA256,'scheduler-inference-01','sched-batch-0042',('acme','beta','gamma'),ZERO_METHOD,ids,keys,payloads,{'acme':h('rollback-auth:acme'),'beta':h('rollback-auth:beta'),'gamma':h('rollback-auth:gamma')},{'acme':4,'beta':3,'gamma':2},floors,m.prior_retired_ledger_sha256,120,300,5); return {'manifest':m,'policy':p,'request':request_for(m),'p10b':p10b_assessment()}
def rebind(f,m,*,keep_policy_pins=True):
    p=f['policy']
    if not keep_policy_pins:
        floors={e.namespace:e.generation for e in m.entries}; p=replace(p,expected_manifest_id=m.manifest_id,expected_manifest_sha256=inference_cache_lifecycle_manifest_digest(m),min_generation_by_namespace=floors)
    return {'manifest':m,'policy':p,'request':request_for(m),'p10b':f['p10b']}
def safe_rollback_fixture():
    f=build_fixture(); m=f['manifest']; t=m.entries[2]; rb=CacheRollbackEvidence(True,'rollback-acme-0001','acme',t.session_id,t.namespace,6,t.generation,t.entry_id,h('rollback-auth:acme')); return rebind(f,replace(m,rollback=rb),keep_policy_pins=False)
