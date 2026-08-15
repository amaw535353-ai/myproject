from __future__ import annotations
from dataclasses import replace
import hashlib,json
from aegis.inference.speculative_serving_security import InferenceSpeculativeServingAnalyzer
from aegis.inference.speculative_serving_types import *
from aegis.inference.cache_lifecycle_types import CacheDecision,CacheRisk
from aegis.vulnerable.speculative_serving import VulnerableCallerDeclaredSpeculativeServingSafety
from evals.p10d_fixture import build_fixture,h,rebind,safe_reject_all_draft_fixture

def _manifest(f,**kw): return rebind(f,replace(f['manifest'],**kw),keep_policy_pins=False)
def _request(f,**kw): return {**f,'request':replace(f['request'],**kw)}
def _policy(f,**kw): return {**f,'policy':replace(f['policy'],**kw)}
def _up(f,**kw): return {**f,'p10c':replace(f['p10c'],**kw)}
def _service(f,i,**kw):
    m=f['manifest']; xs=list(m.services); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,services=tuple(xs)),keep_policy_pins=False)
def _transfer(f,i,**kw):
    m=f['manifest']; xs=list(m.transfers); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,transfers=tuple(xs)),keep_policy_pins=False)
def _round(f,i=0,**kw):
    m=f['manifest']; xs=list(m.speculative_rounds); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,speculative_rounds=tuple(xs)),keep_policy_pins=False)

CASES=[
('manifest-schema',lambda f:_manifest(f,schema_version='wrong-schema')),
('manifest-id-pin',lambda f:rebind(f,replace(f['manifest'],manifest_id='p10d-other'),keep_policy_pins=True)),
('manifest-created-zero',lambda f:_manifest(f,created_at_epoch=0)),
('manifest-upstream-digest',lambda f:_manifest(f,p10c_assessment_sha256=h('forged-p10c'))),
('manifest-scheduler',lambda f:_manifest(f,upstream_scheduler_id='scheduler-attacker')),
('manifest-batch',lambda f:_manifest(f,upstream_batch_id='sched-batch-attacker')),
('manifest-cache-epoch',lambda f:_manifest(f,cache_epoch=6)),
('manifest-request',lambda f:_manifest(f,request_id='request-beta-0001')),
('manifest-tenant',lambda f:_manifest(f,tenant_id='beta',session_id='tenant/beta/session/s-009')),
('manifest-session',lambda f:_manifest(f,session_id='tenant/acme/session/other')),
('manifest-target-model',lambda f:_manifest(f,target_model_id='attacker-model')),
('manifest-target-revision',lambda f:_manifest(f,target_model_revision='rev-attacker')),
('manifest-target-digest',lambda f:_manifest(f,target_model_sha256=h('attacker-target'))),
('manifest-draft-model',lambda f:_manifest(f,draft_model_id='attacker-draft')),
('manifest-draft-revision',lambda f:_manifest(f,draft_model_revision='draft-attacker')),
('manifest-draft-digest',lambda f:_manifest(f,draft_model_sha256=h('attacker-draft'))),
('manifest-tokenizer',lambda f:_manifest(f,tokenizer_sha256=h('attacker-tokenizer'))),
('manifest-draft-trust',lambda f:_manifest(f,draft_trust_profile_sha256=h('attacker-trust'))),
('manifest-handoff-state',lambda f:_manifest(f,handoff_state_sha256=h('attacker-handoff'))),
('manifest-final-state',lambda f:_manifest(f,final_state_sha256=h('forged-final'))),
('network-operation',lambda f:_manifest(f,network_operations=1)),
('request-stale',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch+301)),
('request-too-early',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch-6)),
('request-manifest-id',lambda f:_request(f,manifest_id='caller-other')),
('request-manifest-digest',lambda f:_request(f,manifest_sha256=h('caller-manifest'))),
('policy-version',lambda f:_policy(f,policy_version='wrong-policy')),
('policy-p10c-sha',lambda f:_policy(f,expected_p10c_assessment_sha256='bad')),
('policy-service-map',lambda f:_policy(f,expected_service_role_by_id={'prefill-svc-01':ServiceRole.PREFILL})),
('policy-transfer-map',lambda f:_policy(f,expected_transfer_edges={'transfer-prefill-draft-0001':('prefill-svc-01','draft-svc-01')})),
('policy-round-limit',lambda f:_policy(f,max_speculative_rounds=0)),
('policy-draft-token-limit',lambda f:_policy(f,max_draft_tokens_per_round=0)),
]
CASES += [
('p10c-decision-deny',lambda f:_up(f,decision=CacheDecision.DENY)),
('p10c-risk',lambda f:_up(f,risks=(CacheRisk.CACHE_OWNER_MISMATCH,))),
('p10c-schema',lambda f:_up(f,assessment_schema_version='wrong-schema')),
('p10c-mode',lambda f:_up(f,assessment_mode='caller-mode')),
('p10c-digest',lambda f:_up(f,assessment_evidence_sha256=h('wrong-p10c'))),
('p10c-scheduler',lambda f:_up(f,scheduler_id='scheduler-inference-02')),
('p10c-batch',lambda f:_up(f,batch_id='sched-batch-9999')),
('p10c-cache-epoch',lambda f:_up(f,cache_epoch=4)),
]
for field in ('upstream_p10b_bound','ownership_verified','reuse_isolation_verified','eviction_verified','zeroization_verified','rollback_safety_verified'):
    CASES.append((f'p10c-flag-{field}',lambda f,field=field:_up(f,**{field:False})))
for field in ('caller_declared_safety_trusted','production_cache_manager_integrated','physical_memory_zeroization_verified','distributed_cache_coherence_validated','gpu_allocator_integrated','side_channel_resistance_validated'):
    CASES.append((f'p10c-nonclaim-{field}',lambda f,field=field:_up(f,**{field:True})))
for i in range(3):
    CASES += [
      (f'service-{i}-request',lambda f,i=i:_service(f,i,request_id='request-beta-0001')),
      (f'service-{i}-tenant',lambda f,i=i:_service(f,i,tenant_id='beta')),
      (f'service-{i}-session',lambda f,i=i:_service(f,i,session_id='tenant/beta/session/s-009')),
      (f'service-{i}-role',lambda f,i=i:_service(f,i,role=ServiceRole.DRAFT if f['manifest'].services[i].role!=ServiceRole.DRAFT else ServiceRole.DECODE)),
      (f'service-{i}-model-id',lambda f,i=i:_service(f,i,model_id='attacker-model')),
      (f'service-{i}-model-revision',lambda f,i=i:_service(f,i,model_revision='rev-attacker')),
      (f'service-{i}-model-digest',lambda f,i=i:_service(f,i,model_sha256=h(f'attacker-model-{i}'))),
      (f'service-{i}-tokenizer',lambda f,i=i:_service(f,i,tokenizer_sha256=h(f'attacker-tokenizer-{i}'))),
      (f'service-{i}-input',lambda f,i=i:_service(f,i,input_evidence_sha256=h(f'attacker-input-{i}'))),
      (f'service-{i}-output',lambda f,i=i:_service(f,i,output_evidence_sha256=h(f'attacker-output-{i}'))),
      (f'service-{i}-identity',lambda f,i=i:_service(f,i,service_identity_sha256=h(f'attacker-identity-{i}'))),
    ]
CASES += [
('service-drop',lambda f:_manifest(f,services=f['manifest'].services[:-1])),
('service-reorder',lambda f:_manifest(f,services=tuple(reversed(f['manifest'].services)))),
]
for i in range(2):
    CASES += [
      (f'transfer-{i}-sequence',lambda f,i=i:_transfer(f,i,sequence_no=99)),
      (f'transfer-{i}-source',lambda f,i=i:_transfer(f,i,source_service_id='draft-svc-01')),
      (f'transfer-{i}-destination',lambda f,i=i:_transfer(f,i,destination_service_id='prefill-svc-01')),
      (f'transfer-{i}-request',lambda f,i=i:_transfer(f,i,request_id='request-beta-0001')),
      (f'transfer-{i}-tenant',lambda f,i=i:_transfer(f,i,tenant_id='beta')),
      (f'transfer-{i}-session',lambda f,i=i:_transfer(f,i,session_id='tenant/beta/session/s-009')),
      (f'transfer-{i}-epoch',lambda f,i=i:_transfer(f,i,cache_epoch=4)),
      (f'transfer-{i}-state',lambda f,i=i:_transfer(f,i,state_sha256=h(f'attacker-state-{i}'))),
      (f'transfer-{i}-source-output',lambda f,i=i:_transfer(f,i,source_output_sha256=h(f'attacker-source-{i}'))),
      (f'transfer-{i}-dest-input',lambda f,i=i:_transfer(f,i,destination_input_sha256=h(f'attacker-dest-{i}'))),
      (f'transfer-{i}-previous',lambda f,i=i:_transfer(f,i,previous_transfer_sha256=h(f'attacker-prev-{i}'))),
    ]
CASES += [
('transfer-drop',lambda f:_manifest(f,transfers=f['manifest'].transfers[:-1])),
('transfer-reorder',lambda f:_manifest(f,transfers=tuple(reversed(f['manifest'].transfers)))),
('transfer-replay-current',lambda f:_manifest(f,prior_transfer_ids=f['manifest'].prior_transfer_ids+(f['manifest'].transfers[0].transfer_id,),prior_transfer_ledger_sha256=prior_transfer_ledger_digest(f['manifest'].prior_transfer_ids+(f['manifest'].transfers[0].transfer_id,)))),
('prior-ledger-forged',lambda f:_manifest(f,prior_transfer_ledger_sha256=h('forged-ledger'))),
('prior-ledger-drop',lambda f:_manifest(f,prior_transfer_ids=f['manifest'].prior_transfer_ids[:-1])),
]
CASES += [
('round-sequence',lambda f:_round(f,sequence_no=2)),
('round-draft-service',lambda f:_round(f,draft_service_id='prefill-svc-01')),
('round-decode-service',lambda f:_round(f,decode_service_id='draft-svc-01')),
('round-request',lambda f:_round(f,request_id='request-beta-0001')),
('round-tenant',lambda f:_round(f,tenant_id='beta')),
('round-session',lambda f:_round(f,session_id='tenant/beta/session/s-009')),
('round-input-state',lambda f:_round(f,input_state_sha256=h('wrong-round-input'))),
('round-proposal',lambda f:_round(f,proposal_sha256=h('forged-proposal'))),
('round-token-budget',lambda f:_round(f,proposed_token_count=9,target_verified_token_count=9,accepted_token_count=8,rejected_token_count=1)),
('round-partial-verification',lambda f:_round(f,target_verified_token_count=3,accepted_token_count=3,rejected_token_count=1)),
('round-unverified-acceptance',lambda f:_round(f,target_verified_token_count=2,accepted_token_count=3,rejected_token_count=1)),
('round-count-mismatch',lambda f:_round(f,accepted_token_count=2,rejected_token_count=1)),
('round-verification-digest',lambda f:_round(f,target_verification_sha256=h('forged-verification'))),
('round-result-state',lambda f:_round(f,result_state_sha256=h('forged-result'))),
('round-drop',lambda f:_manifest(f,speculative_rounds=())),
]
SUM={
'declared_request_id':'request-beta-0001','declared_tenant_id':'beta','declared_session_id':'tenant/beta/session/s-009','declared_target_model_revision':'rev-attacker','declared_draft_model_revision':'draft-attacker','declared_service_ids':('prefill-svc-01',),'declared_transfer_ids':('transfer-prefill-draft-0001',),'declared_round_ids':('spec-round-other',),'declared_final_state_sha256':h('caller-final'),'declared_upstream_p10c_bound':False,'declared_route_safe':False,'declared_draft_trust_safe':False,'declared_service_binding_safe':False,'declared_state_transfer_safe':False,'declared_speculative_verification_safe':False,'declared_final_state_safe':False,'declared_serving_safe':False}
for field,value in SUM.items(): CASES.append((f'summary-{field}',lambda f,field=field,value=value:_request(f,**{field:value})))
EXPECTED_ADVERSARIAL_CASES=len(CASES)

def _hardened(f):
    try: return InferenceSpeculativeServingAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10c']).decision==ServingDecision.ALLOW
    except InferenceSpeculativeServingRejected: return False
def _safe_cases():
    a=build_fixture(); b=build_fixture(); b['request']=replace(b['request'],evaluated_at_epoch=b['manifest'].created_at_epoch+20); c=build_fixture(); c['request']=replace(c['request'],evaluated_at_epoch=c['manifest'].created_at_epoch+30); return [a,b,c,safe_reject_all_draft_fixture()]
def _dataset_digest(): return hashlib.sha256('\n'.join(n for n,_ in CASES).encode()).hexdigest()
def _fixture_digest():
    f=build_fixture(); material={'manifest':f['request'].manifest_sha256,'policy':f['policy'].policy_version,'cases':_dataset_digest(),'p10c':f['p10c'].assessment_evidence_sha256}; return hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def run():
    v=VulnerableCallerDeclaredSpeculativeServingSafety(); va=ha=0; accepted=[]
    for name,attack in CASES:
        f=attack(build_fixture()); req=replace(f['request'],declared_serving_safe=True); va+=int(v.accepts(req)); ok=_hardened(f); ha+=int(ok); accepted += [name] if ok else []
    safe=_safe_cases(); failures=sum(not _hardened(f) for f in safe); f=build_fixture(); a=InferenceSpeculativeServingAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10c'])
    return {'adversarial_cases':len(CASES),'vulnerable_asr':f'{va}/{len(CASES)}','hardened_asr':f'{ha}/{len(CASES)}','accepted_attacks':accepted,'hardened_fpr':f'{failures}/{len(safe)}','safe_task_rate':f'{len(safe)-failures}/{len(safe)}','serving_manifest_sha256':f['request'].manifest_sha256,'adversarial_dataset_sha256':_dataset_digest(),'fixture_evaluator_sha256':_fixture_digest(),'clean_assessment_sha256':a.assessment_evidence_sha256,'decision':a.decision.value}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
