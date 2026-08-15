from __future__ import annotations
from dataclasses import replace
import hashlib
from aegis.inference.tenant_isolation_types import *

NOW=1_800_030_000; MANIFEST_ID='p10a-inference-isolation-001'; P9H_PROMOTION_ASSESSMENT_SHA256='8daa403475acdf99254740ac7ba1c6384696acd4eb3fb1b57b09d98232946888'
def h(label:str)->str: return hashlib.sha256(label.encode()).hexdigest()
def _manifest():
    prior=('request-global-old-0001','request-global-old-0002')
    return InferenceTenantIsolationManifest(P10A_SCHEMA_VERSION,MANIFEST_ID,NOW,'deploy-attestation-p5h-001',h('p5h-deployment-attestation-001'),P9H_PROMOTION_ASSESSMENT_SHA256,
        InferenceRouteEvidence('deployment-aegisdesk-prod-001','endpoint-helpdesk-001','aegisdesk-helpdesk-security','rev-2026-08-p9h',h('model-artifact:p10a'),h('tokenizer:p10a'),'adapter-security-policy',h('adapter-security-policy:p10a'),'aegisdesk-helpdesk-draft','rev-2026-08-draft-001',h('draft-model:p10a')),
        InferenceRequestIdentityEvidence('request-acme-0001','acme','principal-acme-agent','tenant/acme/session/s-001','tenant/acme/conversation/c-001',7,3,h('nonce:request-acme-0001'),h('authz:acme')),
        InferenceBatchIsolationEvidence('batch-acme-001','scheduler-inference-01','acme',('request-acme-0001','request-acme-peer-0002'),('acme','acme'),False),
        InferenceCacheBindingEvidence('tenant/acme/session/s-001/epoch/3','acme','tenant/acme/session/s-001',3,True,'tenant/acme/prefix-cache','acme',h('prefix-cache-key:acme:001'),False),
        InferenceOutputBindingEvidence('tenant/acme/session/s-001/channel/stream','acme','tenant/acme/session/s-001','tenant/acme/response/r-001'),prior,prior_request_ledger_digest(prior),0)
def request_for(m):
    q=m.request_identity; r=m.route; b=m.batch; c=m.cache; o=m.output
    return InferenceTenantIsolationRequest(m.manifest_id,inference_tenant_isolation_manifest_digest(m),m.created_at_epoch+10,q.request_id,q.tenant_id,q.principal_id,q.session_id,r.model_id,r.revision,b.batch_id,c.kv_cache_namespace,o.output_channel_id,True,True,True,True,True,True,True,True)
def build_fixture():
    m=_manifest(); p=InferenceTenantIsolationPolicy(P10A_POLICY_VERSION,MANIFEST_ID,inference_tenant_isolation_manifest_digest(m),m.deployment_attestation_id,m.deployment_attestation_sha256,P9H_PROMOTION_ASSESSMENT_SHA256,m.route.deployment_id,m.route.endpoint_id,m.route.model_id,m.route.revision,m.route.model_artifact_sha256,m.route.tokenizer_sha256,m.route.adapter_id,m.route.adapter_sha256,m.route.draft_model_id,m.route.draft_revision,m.route.draft_model_artifact_sha256,('acme','beta'),{'acme':('principal-acme-agent','principal-acme-operator'),'beta':('principal-beta-agent','principal-beta-operator')},('scheduler-inference-01','scheduler-inference-02'),{'acme':h('authz:acme'),'beta':h('authz:beta')},m.prior_request_ledger_sha256,10_000,300,5)
    return {'manifest':m,'policy':p,'request':request_for(m)}
def rebind(f,m,*,keep_policy_pins=True):
    p=f['policy']
    if not keep_policy_pins: p=replace(p,expected_manifest_id=m.manifest_id,expected_manifest_sha256=inference_tenant_isolation_manifest_digest(m))
    return {'manifest':m,'policy':p,'request':request_for(m)}
def beta_safe_fixture():
    f=build_fixture(); m=f['manifest']; q=replace(m.request_identity,request_id='request-beta-0001',tenant_id='beta',principal_id='principal-beta-agent',session_id='tenant/beta/session/s-009',conversation_id='tenant/beta/conversation/c-009',sequence_no=9,session_epoch=4,nonce_sha256=h('nonce:request-beta-0001'),authorization_context_sha256=h('authz:beta'))
    b=replace(m.batch,batch_id='batch-beta-001',scheduler_id='scheduler-inference-02',partition_key='beta',request_ids=('request-beta-peer-0002','request-beta-0001'),tenant_ids=('beta','beta'))
    c=replace(m.cache,kv_cache_namespace='tenant/beta/session/s-009/epoch/4',kv_cache_owner_tenant_id='beta',kv_cache_session_id='tenant/beta/session/s-009',kv_cache_epoch=4,prefix_cache_namespace='tenant/beta/prefix-cache',prefix_cache_owner_tenant_id='beta',prefix_cache_key_sha256=h('prefix-cache-key:beta:009'))
    o=replace(m.output,output_channel_id='tenant/beta/session/s-009/channel/stream',recipient_tenant_id='beta',recipient_session_id='tenant/beta/session/s-009',response_object_id='tenant/beta/response/r-009')
    return rebind(f,replace(m,request_identity=q,batch=b,cache=c,output=o),keep_policy_pins=False)
