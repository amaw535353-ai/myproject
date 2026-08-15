from __future__ import annotations
from dataclasses import replace
import hashlib,json
from aegis.inference.scheduler_security import InferenceSchedulerSecurityAnalyzer
from aegis.inference.scheduler_security_types import SchedulerDecision,InferenceSchedulerRejected,admitted_ledger_digest
from aegis.inference.tenant_isolation_types import InferenceDecision
from aegis.vulnerable.inference_scheduler import VulnerableCallerDeclaredSchedulerSafety
from evals.p10b_fixture import build_fixture,h,rebind,safe_beta_selected_fixture

def _manifest(f,**kw): return rebind(f,replace(f['manifest'],**kw),keep_policy_pins=False)
def _request(f,**kw): return {**f,'request':replace(f['request'],**kw)}
def _policy(f,**kw): return {**f,'policy':replace(f['policy'],**kw)}
def _upstream(f,**kw): return {**f,'p10a':replace(f['p10a'],**kw)}
def _req(f,index,**kw):
    m=f['manifest']; xs=list(m.requests); xs[index]=replace(xs[index],**kw); return rebind(f,replace(m,requests=tuple(xs)),keep_policy_pins=False)
def _state(f,index,**kw):
    m=f['manifest']; xs=list(m.tenant_states); xs[index]=replace(xs[index],**kw); return rebind(f,replace(m,tenant_states=tuple(xs)),keep_policy_pins=False)
def _res(f,**kw): return _manifest(f,resources=replace(f['manifest'].resources,**kw))
def _batch(f,**kw): return _manifest(f,selected_batch=replace(f['manifest'].selected_batch,**kw))

CASES=[
('manifest-schema',lambda f:_manifest(f,schema_version='wrong-schema')),
('manifest-id',lambda f:rebind(f,replace(f['manifest'],manifest_id='p10b-other'),keep_policy_pins=True)),
('manifest-created-zero',lambda f:_manifest(f,created_at_epoch=0)),
('scheduler-id',lambda f:_manifest(f,scheduler_id='scheduler-attacker')),
('scheduling-epoch-negative',lambda f:_manifest(f,scheduling_epoch=-1)),
('upstream-digest',lambda f:_manifest(f,p10a_assessment_sha256=h('forged-p10a'))),
('upstream-request-id',lambda f:_manifest(f,upstream_request_id='request-beta-0001')),
('upstream-tenant',lambda f:_manifest(f,upstream_tenant_id='beta')),
('upstream-session',lambda f:_manifest(f,upstream_session_id='tenant/beta/session/s-009')),
('network-operation',lambda f:_manifest(f,network_operations=1)),
('request-stale',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch+301)),
('request-too-early',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch-6)),
('request-manifest-id',lambda f:_request(f,manifest_id='caller-other')),
('request-manifest-digest',lambda f:_request(f,manifest_sha256=h('caller-manifest'))),
('policy-version',lambda f:_policy(f,policy_version='wrong-policy')),
('policy-manifest-sha',lambda f:_policy(f,expected_manifest_sha256='bad')),
('policy-tenant-map',lambda f:_policy(f,tenant_weights={'acme':2,'beta':1})),
('policy-priority-map',lambda f:_policy(f,priority_rank={'high':3,'normal':2})),
('policy-zero-quantum',lambda f:_policy(f,deficit_quantum=0)),
]
CASES += [
('p10a-decision-deny',lambda f:_upstream(f,decision=InferenceDecision.DENY)),
('p10a-risk',lambda f:_upstream(f,risks=('synthetic-risk',))),
('p10a-schema',lambda f:_upstream(f,assessment_schema_version='wrong-schema')),
('p10a-mode',lambda f:_upstream(f,assessment_mode='caller-mode')),
('p10a-assessment-digest',lambda f:_upstream(f,assessment_evidence_sha256=h('wrong-assessment'))),
('p10a-request-id',lambda f:_upstream(f,request_id='request-beta-0001')),
('p10a-tenant',lambda f:_upstream(f,tenant_id='beta')),
('p10a-session',lambda f:_upstream(f,session_id='tenant/beta/session/s-009')),
]
for field in ('upstream_deployment_bound','upstream_promotion_bound','route_identity_verified','request_identity_verified','batch_isolation_verified','kv_and_prefix_cache_isolation_verified','output_binding_verified','request_replay_clear'):
    CASES.append((f'p10a-flag-{field}',lambda f,field=field:_upstream(f,**{field:False})))
for field in ('caller_declared_safety_trusted','production_inference_gateway_integrated','production_scheduler_isolation_enforced','production_kv_cache_memory_isolation_verified','side_channel_resistance_validated','hardware_attestation_verified'):
    CASES.append((f'p10a-nonclaim-{field}',lambda f,field=field:_upstream(f,**{field:True})))
for i in range(5):
    CASES += [
      (f'req-{i}-tenant',lambda f,i=i:_req(f,i,tenant_id='attacker')),
      (f'req-{i}-session',lambda f,i=i:_req(f,i,session_id='tenant/attacker/session/x')),
      (f'req-{i}-priority',lambda f,i=i:_req(f,i,priority_class='root')),
      (f'req-{i}-prompt-tokens',lambda f,i=i:_req(f,i,prompt_tokens=1000)),
      (f'req-{i}-output-tokens',lambda f,i=i:_req(f,i,max_output_tokens=1000)),
      (f'req-{i}-memory',lambda f,i=i:_req(f,i,memory_units=99)),
      (f'req-{i}-starvation',lambda f,i=i:_req(f,i,queue_age_seconds=9999)),
    ]
CASES += [
('selected-request-unadmitted',lambda f:_req(f,0,admitted=False)),
('selected-peer-unadmitted',lambda f:_req(f,1,admitted=False)),
('current-request-cancelled',lambda f:_req(f,0,cancelled=True,admitted=False)),
('running-not-admitted-shape',lambda f:_req(f,2,running=True,admitted=False)),
('duplicate-request-id',lambda f:_req(f,4,request_id='request-beta-0001')),
]
for i in range(3):
    CASES += [
      (f'state-{i}-weight',lambda f,i=i:_state(f,i,configured_weight=99)),
      (f'state-{i}-deficit-before',lambda f,i=i:_state(f,i,deficit_before=9999)),
      (f'state-{i}-service',lambda f,i=i:_state(f,i,service_units=123)),
      (f'state-{i}-deficit-after',lambda f,i=i:_state(f,i,deficit_after=123)),
      (f'state-{i}-active',lambda f,i=i:_state(f,i,active_requests=99)),
      (f'state-{i}-queued',lambda f,i=i:_state(f,i,queued_requests=99)),
      (f'state-{i}-tokens',lambda f,i=i:_state(f,i,reserved_tokens=9999)),
      (f'state-{i}-memory',lambda f,i=i:_state(f,i,reserved_memory_units=999)),
    ]
CASES += [
('state-drop',lambda f:_manifest(f,tenant_states=f['manifest'].tenant_states[:-1])),
('state-duplicate-tenant',lambda f:_state(f,2,tenant_id='beta')),
('resource-worker',lambda f:_res(f,worker_pool_id='worker-pool-attacker')),
('resource-total-slots',lambda f:_res(f,total_slots=99)),
('resource-active-slots',lambda f:_res(f,active_slots=3)),
('resource-total-memory',lambda f:_res(f,total_memory_units=99)),
('resource-used-memory',lambda f:_res(f,used_memory_units=5)),
('batch-scheduler',lambda f:_batch(f,scheduler_id='scheduler-inference-02')),
('batch-tenant',lambda f:_batch(f,tenant_id='beta')),
('batch-request-drop',lambda f:_batch(f,request_ids=('request-acme-0001',),total_reserved_tokens=200,total_memory_units=2)),
('batch-request-foreign',lambda f:_batch(f,request_ids=('request-beta-0001',),tenant_id='acme',total_reserved_tokens=200,total_memory_units=2)),
('batch-token-total',lambda f:_batch(f,total_reserved_tokens=499)),
('batch-memory-total',lambda f:_batch(f,total_memory_units=6)),
('batch-capacity-size',lambda f:_batch(f,request_ids=('request-acme-0001','request-acme-peer-0002','request-beta-0001'),total_reserved_tokens=600,total_memory_units=6)),
('batch-id-empty',lambda f:_batch(f,batch_id='x')),
('ledger-digest',lambda f:_manifest(f,prior_admitted_ledger_sha256=h('forged-ledger'))),
('ledger-drop',lambda f:_manifest(f,prior_admitted_request_ids=f['manifest'].prior_admitted_request_ids[:-1])),
('ledger-replay-current',lambda f:_manifest(f,prior_admitted_request_ids=f['manifest'].prior_admitted_request_ids+('request-acme-0001',),prior_admitted_ledger_sha256=admitted_ledger_digest(f['manifest'].prior_admitted_request_ids+('request-acme-0001',)))),
]
SUM={
'declared_scheduler_id':'scheduler-attacker','declared_batch_id':'sched-batch-attacker','declared_selected_tenant_id':'beta','declared_admitted_request_ids':('request-acme-0001',),'declared_batch_request_ids':('request-beta-0001',),'declared_upstream_p10a_bound':False,'declared_admission_limits_safe':False,'declared_resource_isolation_safe':False,'declared_weighted_fairness_safe':False,'declared_starvation_bounds_safe':False,'declared_batch_plan_safe':False,'declared_scheduler_safe':False}
for field,value in SUM.items(): CASES.append((f'summary-{field}',lambda f,field=field,value=value:_request(f,**{field:value})))
EXPECTED_ADVERSARIAL_CASES=len(CASES)

def _hardened(f):
    try: return InferenceSchedulerSecurityAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10a']).decision==SchedulerDecision.ALLOW
    except InferenceSchedulerRejected: return False
def _safe_cases():
    a=build_fixture(); b=build_fixture(); b['request']=replace(b['request'],evaluated_at_epoch=b['manifest'].created_at_epoch+20); c=build_fixture(); c['request']=replace(c['request'],evaluated_at_epoch=c['manifest'].created_at_epoch+30); return [a,b,c,safe_beta_selected_fixture()]
def _dataset_digest(): return hashlib.sha256('\n'.join(n for n,_ in CASES).encode()).hexdigest()
def _fixture_digest():
    f=build_fixture(); material={'manifest':f['request'].manifest_sha256,'policy':f['policy'].policy_version,'cases':_dataset_digest(),'p10a':f['p10a'].assessment_evidence_sha256}; return hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def run():
    v=VulnerableCallerDeclaredSchedulerSafety(); va=ha=0; accepted=[]
    for name,attack in CASES:
        f=attack(build_fixture()); va+=int(v.accepts(replace(f['request'],declared_scheduler_safe=True))); ok=_hardened(f); ha+=int(ok); accepted += [name] if ok else []
    safe=_safe_cases(); failures=sum(not _hardened(f) for f in safe); f=build_fixture(); a=InferenceSchedulerSecurityAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10a'])
    return {'adversarial_cases':len(CASES),'vulnerable_asr':f'{va}/{len(CASES)}','hardened_asr':f'{ha}/{len(CASES)}','accepted_attacks':accepted,'hardened_fpr':f'{failures}/{len(safe)}','safe_task_rate':f'{len(safe)-failures}/{len(safe)}','scheduler_manifest_sha256':f['request'].manifest_sha256,'adversarial_dataset_sha256':_dataset_digest(),'fixture_evaluator_sha256':_fixture_digest(),'clean_assessment_sha256':a.assessment_evidence_sha256,'decision':a.decision.value}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
