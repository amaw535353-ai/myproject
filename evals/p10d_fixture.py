from __future__ import annotations
from dataclasses import replace
import hashlib
from aegis.inference.cache_lifecycle_types import *
from aegis.inference.speculative_serving_types import *

NOW=1_800_030_300
MANIFEST_ID='p10d-speculative-serving-001'
P10C_CLEAN_ASSESSMENT_SHA256='27edbe07d57ea8074742416aa028860dec3ae1125899b57a608e1d00c633866f'
REQUEST_ID='request-acme-0001'
TENANT_ID='acme'
SESSION_ID='tenant/acme/session/s-001'
SCHEDULER_ID='scheduler-inference-01'
BATCH_ID='sched-batch-0042'
CACHE_EPOCH=5
TARGET_MODEL_ID='aegisdesk-helpdesk-security'
TARGET_MODEL_REVISION='rev-2026-08-p9h'
DRAFT_MODEL_ID='aegisdesk-helpdesk-draft'
DRAFT_MODEL_REVISION='draft-rev-2026-08-01'

def h(label:str)->str: return hashlib.sha256(label.encode()).hexdigest()
REQUEST_INPUT_SHA256=h('prompt-evidence:request-acme-0001')
TARGET_MODEL_SHA256=h('target-model:aegisdesk-helpdesk-security:rev-2026-08-p9h')
DRAFT_MODEL_SHA256=h('draft-model:aegisdesk-helpdesk-draft:draft-rev-2026-08-01')
TOKENIZER_SHA256=h('tokenizer:aegisdesk-helpdesk:v1')
DRAFT_TRUST_PROFILE_SHA256=h('draft-trust-profile:p10d:v1')

def p10c_assessment():
    return VerifiedInferenceCacheLifecycleAssessment('p10c-cache-lifecycle-001',SCHEDULER_ID,BATCH_ID,CACHE_EPOCH,CacheDecision.ALLOW,(),h('p10b-clean'),('cache-kv-acme-g3','cache-prefix-acme-g4','cache-prefix-acme-g5','cache-kv-beta-g3'),('cache-kv-beta-g2-retired',),('cache-retired-global-0001','cache-retired-global-0002'),True,True,True,True,True,True,False,False,False,False,False,False,P10C_ASSESSMENT_SCHEMA_VERSION,P10C_ASSESSMENT_MODE,P10C_CLEAN_ASSESSMENT_SHA256)

def _service(service_id,role,model_id,revision,model_sha,input_sha,output_sha):
    s=ServingServiceEvidence(service_id,role,REQUEST_ID,TENANT_ID,SESSION_ID,model_id,revision,model_sha,TOKENIZER_SHA256,input_sha,output_sha,'0'*64)
    return replace(s,service_identity_sha256=service_identity_digest(s))

def _manifest():
    prompt=REQUEST_INPUT_SHA256
    prefill_state=h('prefill-state:request-acme-0001:epoch-5')
    proposal=h('draft-proposal:request-acme-0001:round-1')
    final_state=h('decode-final-state:request-acme-0001:round-1')
    prefill=_service('prefill-svc-01',ServiceRole.PREFILL,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,prompt,prefill_state)
    draft=_service('draft-svc-01',ServiceRole.DRAFT,DRAFT_MODEL_ID,DRAFT_MODEL_REVISION,DRAFT_MODEL_SHA256,prefill_state,proposal)
    decode=_service('decode-svc-01',ServiceRole.DECODE,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,prefill_state,final_state)
    prior=('transfer-prior-0001','transfer-prior-0002'); ledger=prior_transfer_ledger_digest(prior)
    t1=StateTransferEvidence('transfer-prefill-draft-0001',1,prefill.service_id,draft.service_id,REQUEST_ID,TENANT_ID,SESSION_ID,CACHE_EPOCH,prefill_state,prefill.output_evidence_sha256,draft.input_evidence_sha256,ledger)
    t2=StateTransferEvidence('transfer-prefill-decode-0002',2,prefill.service_id,decode.service_id,REQUEST_ID,TENANT_ID,SESSION_ID,CACHE_EPOCH,prefill_state,prefill.output_evidence_sha256,decode.input_evidence_sha256,state_transfer_digest(t1))
    r=SpeculativeRoundEvidence('spec-round-0001',1,draft.service_id,decode.service_id,REQUEST_ID,TENANT_ID,SESSION_ID,prefill_state,proposal,4,4,3,1,'0'*64,final_state)
    r=replace(r,target_verification_sha256=target_verification_digest(r,TARGET_MODEL_SHA256,TOKENIZER_SHA256))
    return InferenceSpeculativeServingManifest(P10D_SCHEMA_VERSION,MANIFEST_ID,NOW,P10C_CLEAN_ASSESSMENT_SHA256,SCHEDULER_ID,BATCH_ID,CACHE_EPOCH,REQUEST_ID,TENANT_ID,SESSION_ID,REQUEST_INPUT_SHA256,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,DRAFT_MODEL_ID,DRAFT_MODEL_REVISION,DRAFT_MODEL_SHA256,TOKENIZER_SHA256,DRAFT_TRUST_PROFILE_SHA256,prefill_state,(prefill,draft,decode),(t1,t2),(r,),final_state,prior,ledger,0)

def request_for(m):
    return InferenceSpeculativeServingRequest(m.manifest_id,inference_speculative_serving_manifest_digest(m),m.created_at_epoch+10,m.request_id,m.tenant_id,m.session_id,m.target_model_revision,m.draft_model_revision,tuple(s.service_id for s in m.services),tuple(t.transfer_id for t in m.transfers),tuple(r.round_id for r in m.speculative_rounds),m.final_state_sha256,True,True,True,True,True,True,True,True)

def build_fixture():
    m=_manifest(); roles={s.service_id:s.role for s in m.services}; identities={s.service_id:s.service_identity_sha256 for s in m.services}; edges={t.transfer_id:(t.source_service_id,t.destination_service_id) for t in m.transfers}
    p=InferenceSpeculativeServingPolicy(P10D_POLICY_VERSION,MANIFEST_ID,inference_speculative_serving_manifest_digest(m),P10C_CLEAN_ASSESSMENT_SHA256,SCHEDULER_ID,BATCH_ID,CACHE_EPOCH,REQUEST_ID,TENANT_ID,SESSION_ID,REQUEST_INPUT_SHA256,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,DRAFT_MODEL_ID,DRAFT_MODEL_REVISION,DRAFT_MODEL_SHA256,TOKENIZER_SHA256,DRAFT_TRUST_PROFILE_SHA256,m.handoff_state_sha256,tuple(roles),roles,identities,tuple(edges),edges,tuple(r.round_id for r in m.speculative_rounds),8,4,m.prior_transfer_ledger_sha256,300,5)
    return {'manifest':m,'policy':p,'request':request_for(m),'p10c':p10c_assessment()}

def rebind(f,m,*,keep_policy_pins=True):
    p=f['policy']
    if not keep_policy_pins:
        p=replace(p,expected_manifest_id=m.manifest_id,expected_manifest_sha256=inference_speculative_serving_manifest_digest(m))
    return {'manifest':m,'policy':p,'request':request_for(m),'p10c':f['p10c']}

def safe_reject_all_draft_fixture():
    f=build_fixture(); m=f['manifest']; decode=m.services[2]; new_final=h('decode-final-state:request-acme-0001:reject-all'); services=list(m.services); services[2]=replace(decode,output_evidence_sha256=new_final)
    r=replace(m.speculative_rounds[0],accepted_token_count=0,rejected_token_count=4,result_state_sha256=new_final,target_verification_sha256='0'*64); r=replace(r,target_verification_sha256=target_verification_digest(r,m.target_model_sha256,m.tokenizer_sha256))
    return rebind(f,replace(m,services=tuple(services),speculative_rounds=(r,),final_state_sha256=new_final),keep_policy_pins=False)
