from __future__ import annotations
from dataclasses import replace
import hashlib
from aegis.inference.speculative_serving_types import *
from aegis.inference.adapter_routing_types import *

NOW=1_800_030_600
MANIFEST_ID='p10e-adapter-routing-001'
P10D_CLEAN_ASSESSMENT_SHA256='3d1d51ad6fddcd75c77ef31c39e9b86a93201c743a9221ab551c73ed96b7c3fa'
P10D_MANIFEST_SHA256='76cc93eefe3fae01edbf9b4f5f3c83039d8c1ab6515e024ebdcf82ce556c24fc'
REQUEST_ID='request-acme-0001'; TENANT_ID='acme'; SESSION_ID='tenant/acme/session/s-001'; PRINCIPAL_ID='principal-acme-agent'
TARGET_MODEL_ID='aegisdesk-helpdesk-security'; TARGET_MODEL_REVISION='rev-2026-08-p9h'
DRAFT_MODEL_ID='aegisdesk-helpdesk-draft'; DRAFT_MODEL_REVISION='draft-rev-2026-08-01'
def h(label:str)->str: return hashlib.sha256(label.encode()).hexdigest()
TARGET_MODEL_SHA256=h('target-model:aegisdesk-helpdesk-security:rev-2026-08-p9h')
TOKENIZER_SHA256=h('tokenizer:aegisdesk-helpdesk:v1')
ADAPTER_IDS=('adapter-security-policy','adapter-acme-helpdesk')

def p10d_assessment():
    return VerifiedInferenceSpeculativeServingAssessment('p10d-speculative-serving-001',P10D_MANIFEST_SHA256,REQUEST_ID,TENANT_ID,SESSION_ID,ServingDecision.ALLOW,(),h('p10c-clean'),'scheduler-inference-01','sched-batch-0042',5,TARGET_MODEL_ID,TARGET_MODEL_REVISION,DRAFT_MODEL_ID,DRAFT_MODEL_REVISION,('prefill-svc-01','draft-svc-01','decode-svc-01'),('transfer-prefill-draft-0001','transfer-prefill-decode-0002'),('spec-round-0001',),h('decode-final-state:request-acme-0001:round-1'),True,True,True,True,True,True,True,False,False,False,False,False,False,False,P10D_ASSESSMENT_SCHEMA_VERSION,P10D_ASSESSMENT_MODE,P10D_CLEAN_ASSESSMENT_SHA256)

def _adapter(adapter_id,revision,label,generation,parents=()):
    return RuntimeAdapterEvidence(adapter_id,AdapterKind.LORA,revision,h(label),'safetensors',TENANT_ID,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,TOKENIZER_SHA256,generation,16,32000,('q_proj','v_proj'),parents,h(f'provenance:{adapter_id}:p9c-p9h'))

def _snapshot(snapshot_id,generation,active,adapters):
    amap={a.adapter_id:a.artifact_sha256 for a in adapters}
    return AdapterRouteSnapshot(snapshot_id,REQUEST_ID,TENANT_ID,SESSION_ID,generation,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,TOKENIZER_SHA256,active,adapter_composition_digest(TARGET_MODEL_SHA256,TOKENIZER_SHA256,active,amap))

def _manifest():
    adapters=(
        _adapter('adapter-security-policy','adapter-rev-2026-08-01','adapter-security-policy:2026-08-01',11),
        _adapter('adapter-acme-helpdesk','adapter-rev-2026-08-15','adapter-acme-helpdesk:2026-08-15',12,('adapter-security-policy',)),
    )
    before=_snapshot('adapter-route-before-001',11,('adapter-security-policy',),adapters)
    after=_snapshot('adapter-route-after-001',12,ADAPTER_IDS,adapters)
    auth=AdapterAuthorizationEvidence('adapter-hot-swap-auth-acme-001','adapter-hot-swap-grant-acme-001',PRINCIPAL_ID,TENANT_ID,'hot-swap-adapter-stack',ADAPTER_IDS,TARGET_MODEL_SHA256,NOW-30,NOW+120)
    prior=('adapter-swap-prior-0001','adapter-swap-prior-0002'); ledger=prior_swap_ledger_digest(prior)
    swap=AdapterHotSwapEvidence('adapter-swap-acme-0001',1,REQUEST_ID,TENANT_ID,SESSION_ID,11,12,before.active_adapter_ids,after.active_adapter_ids,adapter_authorization_digest(auth),route_snapshot_digest(before),route_snapshot_digest(after),ledger)
    return InferenceAdapterRoutingManifest(P10E_SCHEMA_VERSION,MANIFEST_ID,NOW,P10D_CLEAN_ASSESSMENT_SHA256,REQUEST_ID,TENANT_ID,SESSION_ID,PRINCIPAL_ID,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,TOKENIZER_SHA256,adapters,auth,before,(swap,),after,prior,ledger,('adapter-retired-global-0001',),0)

def request_for(m):
    return InferenceAdapterRoutingRequest(m.manifest_id,inference_adapter_routing_manifest_digest(m),m.created_at_epoch+10,m.request_id,m.tenant_id,m.session_id,m.principal_id,m.target_model_revision,m.route_before.active_adapter_ids,m.route_after.active_adapter_ids,m.route_after.generation,tuple(s.swap_id for s in m.swaps),True,True,True,True,True,True,True,True)

def policy_for(m):
    revisions={a.adapter_id:a.revision for a in m.adapters}; kinds={a.adapter_id:a.kind for a in m.adapters}; generations={a.adapter_id:a.generation for a in m.adapters}; parents={a.adapter_id:a.parent_adapter_ids for a in m.adapters}; artifacts={a.adapter_id:a.artifact_sha256 for a in m.adapters}; provenance={a.adapter_id:a.provenance_sha256 for a in m.adapters}
    return InferenceAdapterRoutingPolicy(P10E_POLICY_VERSION,m.manifest_id,inference_adapter_routing_manifest_digest(m),P10D_CLEAN_ASSESSMENT_SHA256,REQUEST_ID,TENANT_ID,SESSION_ID,PRINCIPAL_ID,TARGET_MODEL_ID,TARGET_MODEL_REVISION,TARGET_MODEL_SHA256,TOKENIZER_SHA256,ADAPTER_IDS,revisions,kinds,generations,parents,artifacts,provenance,(AdapterKind.LORA,AdapterKind.ADAPTER),('safetensors',),('q_proj','k_proj','v_proj','o_proj'),64,128000,3,(('adapter-security-policy',),ADAPTER_IDS),m.authorization.authorization_id,m.authorization.grant_id,m.authorization.action,11,('adapter-security-policy',),12,ADAPTER_IDS,tuple(s.swap_id for s in m.swaps),m.prior_swap_ledger_sha256,300,5)

def build_fixture():
    m=_manifest(); return {'manifest':m,'policy':policy_for(m),'request':request_for(m),'p10d':p10d_assessment()}

def rebind(f,m,*,keep_policy_pins=True):
    p=f['policy']
    if not keep_policy_pins: p=replace(p,expected_manifest_id=m.manifest_id,expected_manifest_sha256=inference_adapter_routing_manifest_digest(m))
    return {'manifest':m,'policy':p,'request':request_for(m),'p10d':f['p10d']}

def safe_auth_window_fixture():
    f=build_fixture(); a=replace(f['manifest'].authorization,issued_at_epoch=NOW-120,expires_at_epoch=NOW+600); m=replace(f['manifest'],authorization=a); s=replace(m.swaps[0],authorization_sha256=adapter_authorization_digest(a)); m=replace(m,swaps=(s,)); f=rebind(f,m,keep_policy_pins=False); return f
def safe_uppercase_digest_fixture():
    f=build_fixture(); xs=list(f['manifest'].adapters); xs[0]=replace(xs[0],artifact_sha256=xs[0].artifact_sha256.upper()); m=replace(f['manifest'],adapters=tuple(xs)); before=_snapshot(m.route_before.snapshot_id,m.route_before.generation,m.route_before.active_adapter_ids,m.adapters); after=_snapshot(m.route_after.snapshot_id,m.route_after.generation,m.route_after.active_adapter_ids,m.adapters); s=replace(m.swaps[0],before_snapshot_sha256=route_snapshot_digest(before),after_snapshot_sha256=route_snapshot_digest(after)); m=replace(m,route_before=before,route_after=after,swaps=(s,)); f=rebind(f,m,keep_policy_pins=False); f['policy']=replace(f['policy'],expected_adapter_artifact_sha256_by_id={**f['policy'].expected_adapter_artifact_sha256_by_id,'adapter-security-policy':m.adapters[0].artifact_sha256}); return f
