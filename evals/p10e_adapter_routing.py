from __future__ import annotations
from dataclasses import replace
import hashlib,json
from aegis.inference.adapter_routing_security import InferenceAdapterRoutingAnalyzer
from aegis.inference.adapter_routing_types import *
from aegis.inference.speculative_serving_types import ServingDecision,ServingRisk
from aegis.vulnerable.adapter_routing import VulnerableCallerDeclaredAdapterRoutingSafety
from evals.p10e_fixture import *

def _manifest(f,**kw): return rebind(f,replace(f['manifest'],**kw),keep_policy_pins=False)
def _request(f,**kw): return {**f,'request':replace(f['request'],**kw)}
def _policy(f,**kw): return {**f,'policy':replace(f['policy'],**kw)}
def _up(f,**kw): return {**f,'p10d':replace(f['p10d'],**kw)}
def _adapter(f,i,**kw):
    m=f['manifest']; xs=list(m.adapters); xs[i]=replace(xs[i],**kw); return rebind(f,replace(m,adapters=tuple(xs)),keep_policy_pins=False)
def _auth(f,**kw):
    m=f['manifest']; return rebind(f,replace(m,authorization=replace(m.authorization,**kw)),keep_policy_pins=False)
def _snap(f,which,**kw):
    m=f['manifest']; s=replace(getattr(m,which),**kw); return rebind(f,replace(m,**{which:s}),keep_policy_pins=False)
def _swap(f,**kw):
    m=f['manifest']; s=replace(m.swaps[0],**kw); return rebind(f,replace(m,swaps=(s,)),keep_policy_pins=False)

CASES=[
('manifest-schema',lambda f:_manifest(f,schema_version='wrong-schema')),
('manifest-id',lambda f:rebind(f,replace(f['manifest'],manifest_id='p10e-other'),keep_policy_pins=True)),
('manifest-created-zero',lambda f:_manifest(f,created_at_epoch=0)),
('manifest-upstream-sha',lambda f:_manifest(f,p10d_assessment_sha256=h('forged-p10d'))),
('manifest-request',lambda f:_manifest(f,request_id='request-acme-other')),
('manifest-tenant',lambda f:_manifest(f,tenant_id='beta')),
('manifest-session',lambda f:_manifest(f,session_id='tenant/acme/session/other')),
('manifest-principal',lambda f:_manifest(f,principal_id='principal-acme-attacker')),
('manifest-target-model-id',lambda f:_manifest(f,target_model_id='aegisdesk-other')),
('manifest-target-revision',lambda f:_manifest(f,target_model_revision='rev-other')),
('manifest-target-sha',lambda f:_manifest(f,target_model_sha256=h('forged-base'))),
('manifest-tokenizer',lambda f:_manifest(f,tokenizer_sha256=h('forged-tokenizer'))),
('network-operation',lambda f:_manifest(f,network_operations=1)),
('retired-active',lambda f:_manifest(f,retired_adapter_ids=f['manifest'].retired_adapter_ids+('adapter-acme-helpdesk',))),
('retired-duplicate',lambda f:_manifest(f,retired_adapter_ids=('adapter-retired-global-0001','adapter-retired-global-0001'))),
('prior-ledger-digest',lambda f:_manifest(f,prior_swap_ledger_sha256=h('forged-ledger'))),
('prior-ledger-drop',lambda f:_manifest(f,prior_swap_ids=f['manifest'].prior_swap_ids[:-1])),
('prior-ledger-replay',lambda f:_manifest(f,prior_swap_ids=f['manifest'].prior_swap_ids+(f['manifest'].swaps[0].swap_id,))),
]
CASES += [
('p10d-decision-deny',lambda f:_up(f,decision=ServingDecision.DENY)),
('p10d-risk',lambda f:_up(f,risks=(ServingRisk.UPSTREAM_P10C_INVALID,))),
('p10d-schema',lambda f:_up(f,assessment_schema_version='wrong-schema')),
('p10d-mode',lambda f:_up(f,assessment_mode='caller-mode')),
('p10d-digest',lambda f:_up(f,assessment_evidence_sha256=h('wrong-p10d'))),
('p10d-request',lambda f:_up(f,request_id='request-other')),
('p10d-tenant',lambda f:_up(f,tenant_id='beta')),
('p10d-session',lambda f:_up(f,session_id='tenant/acme/session/other')),
('p10d-model',lambda f:_up(f,target_model_id='aegisdesk-other')),
('p10d-revision',lambda f:_up(f,target_model_revision='rev-other')),
]
for field in ('upstream_p10c_bound','route_identity_verified','draft_model_trust_verified','service_topology_verified','state_transfer_verified','speculative_verification_verified','final_state_verified'):
    CASES.append((f'p10d-flag-{field}',lambda f,field=field:_up(f,**{field:False})))
for field in ('caller_declared_safety_trusted','production_inference_engine_integrated','production_rpc_transport_verified','cryptographic_service_attestation_verified','production_speculative_decoder_validated','semantic_token_equivalence_verified','side_channel_resistance_validated'):
    CASES.append((f'p10d-nonclaim-{field}',lambda f,field=field:_up(f,**{field:True})))
for i in range(2):
    CASES += [
      (f'adapter-{i}-id',lambda f,i=i:_adapter(f,i,adapter_id=f'adapter-forged-{i}')),
      (f'adapter-{i}-kind',lambda f,i=i:_adapter(f,i,kind=AdapterKind.ADAPTER if f['manifest'].adapters[i].kind==AdapterKind.LORA else AdapterKind.LORA)),
      (f'adapter-{i}-revision',lambda f,i=i:_adapter(f,i,revision='adapter-rev-forged')),
      (f'adapter-{i}-digest',lambda f,i=i:_adapter(f,i,artifact_sha256=h(f'forged-adapter-{i}'))),
      (f'adapter-{i}-format',lambda f,i=i:_adapter(f,i,serialization_format='pickle')),
      (f'adapter-{i}-tenant',lambda f,i=i:_adapter(f,i,tenant_id='beta')),
      (f'adapter-{i}-base-id',lambda f,i=i:_adapter(f,i,base_model_id='aegisdesk-other')),
      (f'adapter-{i}-base-revision',lambda f,i=i:_adapter(f,i,base_model_revision='rev-other')),
      (f'adapter-{i}-base-sha',lambda f,i=i:_adapter(f,i,base_model_sha256=h('wrong-base'))),
      (f'adapter-{i}-tokenizer',lambda f,i=i:_adapter(f,i,tokenizer_sha256=h('wrong-tokenizer'))),
      (f'adapter-{i}-generation',lambda f,i=i:_adapter(f,i,generation=99)),
      (f'adapter-{i}-rank',lambda f,i=i:_adapter(f,i,rank=128)),
      (f'adapter-{i}-alpha',lambda f,i=i:_adapter(f,i,alpha_bps=256000)),
      (f'adapter-{i}-target',lambda f,i=i:_adapter(f,i,target_modules=('lm_head',))),
      (f'adapter-{i}-provenance',lambda f,i=i:_adapter(f,i,provenance_sha256=h('forged-provenance'))),
    ]
CASES += [
('adapter-reorder',lambda f:_manifest(f,adapters=tuple(reversed(f['manifest'].adapters)))),
('adapter-drop',lambda f:_manifest(f,adapters=f['manifest'].adapters[:1])),
('adapter-parent-unknown',lambda f:_adapter(f,1,parent_adapter_ids=('adapter-unknown',))),
('adapter-parent-self',lambda f:_adapter(f,1,parent_adapter_ids=('adapter-acme-helpdesk',))),
]
for which in ('route_before','route_after'):
    CASES += [
      (f'{which}-request',lambda f,which=which:_snap(f,which,request_id='request-other')),
      (f'{which}-tenant',lambda f,which=which:_snap(f,which,tenant_id='beta')),
      (f'{which}-session',lambda f,which=which:_snap(f,which,session_id='tenant/acme/session/other')),
      (f'{which}-generation',lambda f,which=which:_snap(f,which,generation=99)),
      (f'{which}-base-id',lambda f,which=which:_snap(f,which,base_model_id='aegisdesk-other')),
      (f'{which}-base-revision',lambda f,which=which:_snap(f,which,base_model_revision='rev-other')),
      (f'{which}-base-sha',lambda f,which=which:_snap(f,which,base_model_sha256=h('wrong-base'))),
      (f'{which}-tokenizer',lambda f,which=which:_snap(f,which,tokenizer_sha256=h('wrong-tokenizer'))),
      (f'{which}-composition-digest',lambda f,which=which:_snap(f,which,composition_sha256=h('wrong-composition'))),
    ]
CASES += [
('before-stack-order',lambda f:_snap(f,'route_before',active_adapter_ids=('adapter-acme-helpdesk',))),
('after-stack-order',lambda f:_snap(f,'route_after',active_adapter_ids=tuple(reversed(ADAPTER_IDS)))),
('after-stack-unknown',lambda f:_snap(f,'route_after',active_adapter_ids=('adapter-security-policy','adapter-unknown'))),
('after-stack-depth',lambda f:_policy(f,max_stack_depth=1)),
('composition-allowlist',lambda f:_policy(f,allowed_compositions=(('adapter-security-policy',),))),
]
CASES += [
('auth-id',lambda f:_auth(f,authorization_id='auth-other')),
('auth-grant',lambda f:_auth(f,grant_id='grant-other')),
('auth-principal',lambda f:_auth(f,principal_id='principal-acme-attacker')),
('auth-tenant',lambda f:_auth(f,tenant_id='beta')),
('auth-action',lambda f:_auth(f,action='load-any-adapter')),
('auth-targets',lambda f:_auth(f,target_adapter_ids=('adapter-security-policy',))),
('auth-base',lambda f:_auth(f,base_model_sha256=h('wrong-base'))),
('auth-expired',lambda f:_auth(f,expires_at_epoch=f['manifest'].created_at_epoch-1)),
('auth-future',lambda f:_auth(f,issued_at_epoch=f['manifest'].created_at_epoch+1)),
]
CASES += [
('swap-id',lambda f:_swap(f,swap_id='adapter-swap-other')),
('swap-sequence',lambda f:_swap(f,sequence_no=2)),
('swap-request',lambda f:_swap(f,request_id='request-other')),
('swap-tenant',lambda f:_swap(f,tenant_id='beta')),
('swap-session',lambda f:_swap(f,session_id='tenant/acme/session/other')),
('swap-from-generation',lambda f:_swap(f,from_generation=10)),
('swap-to-generation',lambda f:_swap(f,to_generation=13)),
('swap-prior-stack',lambda f:_swap(f,prior_adapter_ids=())),
('swap-next-stack',lambda f:_swap(f,next_adapter_ids=('adapter-security-policy',))),
('swap-auth',lambda f:_swap(f,authorization_sha256=h('wrong-auth'))),
('swap-before-snapshot',lambda f:_swap(f,before_snapshot_sha256=h('wrong-before'))),
('swap-after-snapshot',lambda f:_swap(f,after_snapshot_sha256=h('wrong-after'))),
('swap-chain',lambda f:_swap(f,previous_swap_sha256=h('wrong-chain'))),
('swap-replay',lambda f:_manifest(f,prior_swap_ids=f['manifest'].prior_swap_ids+(f['manifest'].swaps[0].swap_id,),prior_swap_ledger_sha256=prior_swap_ledger_digest(f['manifest'].prior_swap_ids+(f['manifest'].swaps[0].swap_id,)))),
('swap-drop',lambda f:_manifest(f,swaps=())),
]
SUM={
'declared_request_id':'request-other','declared_tenant_id':'beta','declared_session_id':'tenant/acme/session/other','declared_principal_id':'principal-acme-attacker','declared_target_model_revision':'rev-other','declared_before_adapter_ids':(), 'declared_after_adapter_ids':('adapter-security-policy',),'declared_after_generation':99,'declared_swap_ids':(),
'declared_upstream_p10d_bound':False,'declared_base_route_bound':False,'declared_adapter_artifacts_safe':False,'declared_tenant_composition_safe':False,'declared_authorization_safe':False,'declared_hot_swap_safe':False,'declared_route_snapshot_safe':False,'declared_adapter_routing_safe':False}
for field,value in SUM.items(): CASES.append((f'summary-{field}',lambda f,field=field,value=value:_request(f,**{field:value})))
CASES += [
('request-stale',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch+301)),
('request-too-early',lambda f:_request(f,evaluated_at_epoch=f['manifest'].created_at_epoch-6)),
('request-manifest-id',lambda f:_request(f,manifest_id='p10e-other')),
('request-manifest-digest',lambda f:_request(f,manifest_sha256=h('wrong-manifest'))),
('policy-version',lambda f:_policy(f,policy_version='wrong-policy')),
('policy-manifest-sha',lambda f:_policy(f,expected_manifest_sha256='bad')),
('policy-p10d-sha',lambda f:_policy(f,expected_p10d_assessment_sha256='bad')),
('policy-adapter-map',lambda f:_policy(f,expected_adapter_artifact_sha256_by_id={'adapter-security-policy':h('only-one')})),
('policy-provenance-map',lambda f:_policy(f,expected_adapter_provenance_sha256_by_id={})),
('policy-kinds-empty',lambda f:_policy(f,allowed_adapter_kinds=())),
('policy-formats-empty',lambda f:_policy(f,allowed_serialization_formats=())),
('policy-targets-empty',lambda f:_policy(f,allowed_target_modules=())),
('policy-rank-zero',lambda f:_policy(f,max_adapter_rank=0)),
('policy-alpha-zero',lambda f:_policy(f,max_adapter_alpha_bps=0)),
('policy-depth-zero',lambda f:_policy(f,max_stack_depth=0)),
('policy-generation-nonadvance',lambda f:_policy(f,expected_after_generation=f['policy'].expected_before_generation)),
('policy-swap-empty',lambda f:_policy(f,expected_swap_ids=())),
]
EXPECTED_ADVERSARIAL_CASES=len(CASES)

def _hardened(f):
    try: return InferenceAdapterRoutingAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10d']).decision==AdapterDecision.ALLOW
    except InferenceAdapterRoutingRejected: return False

def _safe_cases():
    a=build_fixture(); b=build_fixture(); b['request']=replace(b['request'],evaluated_at_epoch=b['manifest'].created_at_epoch+20); return [a,b,safe_auth_window_fixture(),safe_uppercase_digest_fixture()]
def _dataset_digest(): return hashlib.sha256('\n'.join(n for n,_ in CASES).encode()).hexdigest()
def _fixture_digest():
    f=build_fixture(); material={'manifest':f['request'].manifest_sha256,'policy':f['policy'].policy_version,'cases':_dataset_digest(),'p10d':f['p10d'].assessment_evidence_sha256}; return hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def run():
    v=VulnerableCallerDeclaredAdapterRoutingSafety(); va=ha=0; accepted=[]
    for name,attack in CASES:
        f=attack(build_fixture()); req=replace(f['request'],declared_adapter_routing_safe=True); va+=int(v.accepts(req)); ok=_hardened(f); ha+=int(ok); accepted += [name] if ok else []
    safe=_safe_cases(); failures=sum(not _hardened(f) for f in safe); f=build_fixture(); a=InferenceAdapterRoutingAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p10d'])
    return {'adversarial_cases':len(CASES),'vulnerable_asr':f'{va}/{len(CASES)}','hardened_asr':f'{ha}/{len(CASES)}','accepted_attacks':accepted,'hardened_fpr':f'{failures}/{len(safe)}','safe_task_rate':f'{len(safe)-failures}/{len(safe)}','adapter_routing_manifest_sha256':f['request'].manifest_sha256,'adversarial_dataset_sha256':_dataset_digest(),'fixture_evaluator_sha256':_fixture_digest(),'clean_assessment_sha256':a.assessment_evidence_sha256,'decision':a.decision.value}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
