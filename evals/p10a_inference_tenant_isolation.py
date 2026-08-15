from __future__ import annotations
from dataclasses import replace
import hashlib,json
from aegis.inference.tenant_isolation_security import InferenceTenantIsolationAnalyzer
from aegis.inference.tenant_isolation_types import InferenceDecision,InferenceTenantIsolationRejected
from aegis.vulnerable.inference_tenant_isolation import VulnerableCallerDeclaredInferenceIsolation
from evals.p10a_fixture import beta_safe_fixture,build_fixture,h,rebind

def _nest(f,name,**kw):
    m=f['manifest']; return rebind(f,replace(m,**{name:replace(getattr(m,name),**kw)}),keep_policy_pins=False)
def _manifest(f,**kw): return rebind(f,replace(f['manifest'],**kw),keep_policy_pins=False)
def _request(f,**kw): return {**f,'request':replace(f['request'],**kw)}
def _policy(f,**kw): return {**f,'policy':replace(f['policy'],**kw)}
CASES=[]
CASES += [
('manifest-schema',lambda f:_manifest(f,schema_version='wrong-schema')),
('manifest-id',lambda f:rebind(f,replace(f['manifest'],manifest_id='p10a-other-manifest'),keep_policy_pins=True)),
('manifest-created-zero',lambda f:_manifest(f,created_at_epoch=0)),
('deployment-attestation-id',lambda f:_manifest(f,deployment_attestation_id='deploy-attestation-p5h-attacker')),
('deployment-attestation-digest',lambda f:_manifest(f,deployment_attestation_sha256=h('forged-deployment-attestation'))),
('p9h-promotion-digest',lambda f:_manifest(f,p9h_promotion_assessment_sha256=h('forged-p9h-promotion'))),
('network-operation',lambda f:_manifest(f,network_operations=1)),
('request-manifest-id',lambda f:_request(f,manifest_id='p10a-caller-other')),
('request-manifest-digest',lambda f:_request(f,manifest_sha256=h('caller-forged-manifest'))),
('request-stale',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch+301)),
('request-too-early',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch-6)),
('policy-version',lambda f:_policy(f,policy_version='wrong-policy'))]
M={
'route':{
'deployment_id':('deployment-attacker-001','deployment-aegisdesk-shadow-001','deployment-beta-001'),'endpoint_id':('endpoint-attacker-001','endpoint-helpdesk-shadow','endpoint-other-tenant'),'model_id':('aegisdesk-other-model','attacker-model','aegisdesk-helpdesk-draft'),'revision':('latest','main','rev-attacker-001'),'model_artifact_sha256':(h('model-swap-1'),h('model-swap-2'),h('model-swap-3')),'tokenizer_sha256':(h('tokenizer-swap-1'),h('tokenizer-swap-2'),h('tokenizer-swap-3')),'adapter_id':('adapter-attacker','adapter-other-tenant','adapter-helpdesk-lora'),'adapter_sha256':(h('adapter-swap-1'),h('adapter-swap-2'),h('adapter-swap-3')),'draft_model_id':('draft-attacker-model','other-draft-model','aegisdesk-helpdesk-security'),'draft_revision':('latest','prod','rev-draft-attacker'),'draft_model_artifact_sha256':(h('draft-swap-1'),h('draft-swap-2'),h('draft-swap-3'))},
'request_identity':{
'request_id':('request-beta-9999','request-acme-replay','request-attacker-0001'),'tenant_id':('beta','attacker','other-tenant'),'principal_id':('principal-beta-agent','principal-attacker','principal-acme-unknown'),'session_id':('tenant/beta/session/s-001','tenant/acme/session/s-attacker','session-unscoped-001'),'conversation_id':('tenant/beta/conversation/c-001','conversation-unscoped-001'),'sequence_no':(10001,50000,999999),'session_epoch':(2,99,1000),'authorization_context_sha256':(h('authz:beta'),h('authz:attacker'),h('authz:stale'))},
'batch':{'scheduler_id':('scheduler-attacker','scheduler-inference-99','scheduler-external'),'partition_key':('beta','global','shared'),'request_ids':(('request-beta-0001',),('request-acme-peer-0002',),('request-acme-0001','request-acme-0001')),'tenant_ids':(('acme','beta'),('beta','beta'),('acme',)),'mixed_tenant_batch':(True,True,True)},
'cache':{'kv_cache_namespace':('tenant/beta/session/s-001/epoch/3','shared/kv/session/s-001/epoch/3','tenant/acme/session/s-001/epoch/2'),'kv_cache_owner_tenant_id':('beta','attacker','shared'),'kv_cache_session_id':('tenant/beta/session/s-001','tenant/acme/session/s-other','shared/session/s-001'),'kv_cache_epoch':(2,4,999),'prefix_cache_namespace':('tenant/beta/prefix-cache','shared/prefix-cache','global/prefix-cache'),'prefix_cache_owner_tenant_id':('beta','attacker','shared'),'allow_cross_tenant_reuse':(True,True,True)},
'output':{'output_channel_id':('tenant/beta/session/s-001/channel/stream','shared/channel/stream','tenant/acme/session/s-other/channel/stream'),'recipient_tenant_id':('beta','attacker','shared'),'recipient_session_id':('tenant/beta/session/s-001','tenant/acme/session/s-other','shared/session/s-001'),'response_object_id':('tenant/beta/response/r-001','shared/response/r-001','attacker/response/r-001')}}
PREFIX={'route':'route','request_identity':'identity','batch':'batch','cache':'cache','output':'output'}
for obj,fields in M.items():
    for field,values in fields.items():
        for i,value in enumerate(values,1): CASES.append((f'{PREFIX[obj]}-{field}-{i}',lambda f,obj=obj,field=field,value=value:_nest(f,obj,**{field:value})))
CASES += [
('replay-current-request',lambda f:_manifest(f,prior_request_ids=f['manifest'].prior_request_ids+(f['manifest'].request_identity.request_id,))),
('ledger-digest-swap',lambda f:_manifest(f,prior_request_ledger_sha256=h('forged-ledger'))),
('ledger-entry-drop',lambda f:_manifest(f,prior_request_ids=f['manifest'].prior_request_ids[:-1])),
('ledger-entry-replace',lambda f:_manifest(f,prior_request_ids=('request-global-old-0001','request-global-attacker-9999')))]
SUM={'declared_request_id':'request-caller-forged','declared_tenant_id':'beta','declared_principal_id':'principal-beta-agent','declared_session_id':'tenant/beta/session/s-009','declared_model_id':'attacker-model','declared_revision':'latest','declared_batch_id':'batch-beta-001','declared_kv_cache_namespace':'shared/kv','declared_output_channel_id':'shared/channel','declared_upstream_bound':False,'declared_route_bound':False,'declared_request_identity_bound':False,'declared_batch_isolated':False,'declared_cache_isolated':False,'declared_output_isolated':False,'declared_request_fresh':False}
for field,value in SUM.items(): CASES.append((f'request-summary-{field}',lambda f,field=field,value=value:_request(f,**{field:value})))
EXPECTED_ADVERSARIAL_CASES=len(CASES); assert EXPECTED_ADVERSARIAL_CASES==136,EXPECTED_ADVERSARIAL_CASES
def _hardened_accepts(f):
    try: return InferenceTenantIsolationAnalyzer(f['policy']).evaluate(f['request'],f['manifest']).decision==InferenceDecision.ALLOW
    except InferenceTenantIsolationRejected: return False
def _safe_cases():
    a=build_fixture(); b=build_fixture(); m=b['manifest']; b=rebind(b,replace(m,batch=replace(m.batch,scheduler_id='scheduler-inference-02')),keep_policy_pins=False)
    c=build_fixture(); m=c['manifest']; c=rebind(c,replace(m,request_identity=replace(m.request_identity,principal_id='principal-acme-operator')),keep_policy_pins=False)
    return [a,b,c,beta_safe_fixture()]
def _dataset_digest(): return hashlib.sha256('\n'.join(n for n,_ in CASES).encode()).hexdigest()
def _fixture_digest():
    f=build_fixture(); return hashlib.sha256(json.dumps({'manifest':f['request'].manifest_sha256,'policy':f['policy'].policy_version,'cases':_dataset_digest()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
def run():
    v=VulnerableCallerDeclaredInferenceIsolation(); va=ha=0
    for _,attack in CASES:
        f=attack(build_fixture()); va+=int(v.accepts(f['request'])); ha+=int(_hardened_accepts(f))
    safe=_safe_cases(); failures=sum(not _hardened_accepts(f) for f in safe); f=build_fixture(); a=InferenceTenantIsolationAnalyzer(f['policy']).evaluate(f['request'],f['manifest'])
    return {'adversarial_cases':len(CASES),'vulnerable_asr':f'{va}/{len(CASES)}','hardened_asr':f'{ha}/{len(CASES)}','hardened_fpr':f'{failures}/{len(safe)}','safe_task_rate':f'{len(safe)-failures}/{len(safe)}','inference_isolation_manifest_sha256':f['request'].manifest_sha256,'adversarial_dataset_sha256':_dataset_digest(),'fixture_evaluator_sha256':_fixture_digest(),'clean_assessment_sha256':a.assessment_evidence_sha256,'decision':a.decision.value}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
