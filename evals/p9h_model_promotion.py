from __future__ import annotations
from dataclasses import asdict, replace
import hashlib, json
from aegis.training.model_promotion_security import ModelRegistryPromotionAnalyzer
from aegis.training.model_promotion_types import ModelPromotionSecurityRejected, PromotionDecision
from aegis.training.sensitive_data_types import SensitiveDataDecision
from aegis.vulnerable.model_promotion import VulnerableCallerDeclaredModelPromotionSafety
from evals.p9h_fixture import NOW, build_fixture, h, rebind

def _artifact(f,i,**u):
    m=f['manifest']; a=list(m.artifacts); a[i]=replace(a[i],**u); return rebind(f,manifest=replace(m,artifacts=tuple(a)))
def _bridge(f,**u):
    m=f['manifest']; return rebind(f,manifest=replace(m,phase5_bridge=replace(m.phase5_bridge,**u)))
def _auth(f,**u):
    m=f['manifest']; return rebind(f,manifest=replace(m,authorization=replace(m.authorization,**u)))
def adversarial_cases():
    b=build_fixture(); out=[]; u=b['p9g']; m=b['manifest']
    specs=[('upstream_decision_deny',{'decision':SensitiveDataDecision.DENY}),('upstream_has_risk',{'risks':('synthetic-risk',)}),('upstream_p9f_unbound',{'upstream_p9f_bound':False}),('input_governance_false',{'input_governance_verified':False}),('output_governance_false',{'output_governance_verified':False}),('canary_clear_false',{'canary_reproduction_clear':False}),('sensitive_policy_false',{'sensitive_data_policy_verified':False}),('caller_trust_true',{'caller_declared_safety_trusted':True}),('production_dlp_claim',{'production_dlp_integrated':True}),('comprehensive_pii_claim',{'comprehensive_pii_detection_validated':True}),('legal_compliance_claim',{'legal_compliance_verified':True}),('differential_privacy_claim',{'differential_privacy_verified':True}),('memorization_absence_claim',{'memorization_absence_proven':True}),('upstream_schema_swap',{'assessment_schema_version':'other-schema'}),('upstream_mode_swap',{'assessment_mode':'other-mode'}),('upstream_assessment_digest_swap',{'assessment_evidence_sha256':h('other-p9g')})]
    out += [(n,rebind(b,p9g=replace(u,**x))) for n,x in specs]
    specs=[('p9g_digest_swap',{'p9g_assessment_sha256':h('swapped-p9g')}),('governance_id_swap',{'governance_id':'other-governance'}),('evaluation_id_swap',{'evaluation_id':'other-evaluation'}),('checkpoint_id_swap',{'checkpoint_id':'ckpt-other'}),('execution_id_swap',{'execution_id':'execution-other'}),('job_id_swap',{'job_id':'job-other'}),('model_id_swap',{'model_id':'model-other'}),('revision_swap',{'revision':'revision-other'}),('base_model_id_swap',{'base_model_id':'base-other'}),('base_revision_swap',{'base_model_revision':'base-rev-other'}),('checkpoint_artifact_swap',{'final_checkpoint_artifact_sha256':h('other-checkpoint')})]
    out += [(n,rebind(b,manifest=replace(m,**x))) for n,x in specs]
    for i,a in enumerate(m.artifacts):
        p=a.artifact_id.replace('.','_'); out += [(f'{p}_id_swap',_artifact(b,i,artifact_id=f'other-{i}')),(f'{p}_role_swap',_artifact(b,i,component_role='external_data' if a.component_role!='external_data' else 'config')),(f'{p}_format_swap',_artifact(b,i,artifact_format='pickle')),(f'{p}_digest_swap',_artifact(b,i,sha256=h(f'tamper:{i}'))),(f'{p}_size_swap',_artifact(b,i,size_bytes=a.size_bytes+1)),(f'{p}_source_swap',_artifact(b,i,source='untrusted://artifact'))]
    out += [('artifact_order_reversed',rebind(b,manifest=replace(m,artifacts=tuple(reversed(m.artifacts))))),('artifact_missing',rebind(b,manifest=replace(m,artifacts=m.artifacts[:-1]))),('artifact_extra',rebind(b,manifest=replace(m,artifacts=m.artifacts+(replace(m.artifacts[-1],artifact_id='extra.onnx'),))))]
    specs=[('p5a_policy_swap',{'p5a_policy_version':'other-p5a-policy'}),('p5a_schema_swap',{'p5a_manifest_schema_version':'other-p5a-schema'}),('p5b_policy_swap',{'p5b_policy_version':'other-p5b-policy'}),('p5b_schema_swap',{'p5b_manifest_schema_version':'other-p5b-schema'}),('p5c_policy_swap',{'p5c_policy_version':'other-p5c-policy'}),('p5c_schema_swap',{'p5c_release_schema_version':'other-p5c-schema'}),('package_id_swap',{'package_id':'other-package'}),('package_publisher_swap',{'package_publisher_id':'other-publisher'}),('package_manifest_digest_swap',{'package_manifest_sha256':h('other-package-manifest')}),('registry_id_swap',{'registry_id':'other-registry'}),('channel_swap',{'channel':'other-channel'}),('tag_swap',{'tag':'release-other'}),('release_digest_swap',{'release_digest':h('other-release')}),('mutable_latest_tag',{'tag':'latest'})]
    out += [(n,_bridge(b,**x)) for n,x in specs]
    specs=[('registry_namespace_swap',{'registry_namespace':'other/namespace'}),('registry_model_name_swap',{'registry_model_name':'other-model'}),('registry_version_swap',{'registry_version':'2026.08.15-other'}),('mutable_latest_version',{'registry_version':'latest'}),('artifact_uri_swap',{'immutable_artifact_uri':'registry+sha256://other/value'}),('non_digest_uri',{'immutable_artifact_uri':'registry://mutable/model'}),('overwrite_existing',{'overwrite_existing':True}),('mutable_alias_update',{'mutable_alias_update':True})]
    out += [(n,rebind(b,manifest=replace(m,**x))) for n,x in specs]
    specs=[('auth_id_swap',{'authorization_id':'auth-other'}),('grant_id_swap',{'grant_id':'grant-other'}),('principal_swap',{'principal_id':'principal-other'}),('auth_action_swap',{'action':'deploy-model'}),('auth_target_swap',{'target':'other/target@version'}),('auth_p9g_digest_swap',{'p9g_assessment_sha256':h('other-auth-p9g')}),('auth_expired',{'expires_at_epoch':NOW-1}),('auth_future',{'issued_at_epoch':NOW+10,'expires_at_epoch':NOW+100})]
    out += [(n,_auth(b,**x)) for n,x in specs]
    specs=[('predecessor_swap',{'predecessor_version':'other-predecessor'}),('rollback_digest_swap',{'rollback_release_digest':h('other-rollback')}),('revocation_epoch_swap',{'revocation_epoch':m.revocation_epoch+1}),('revocation_before_promotion',{'revocation_epoch':NOW-1}),('unexpected_network',{'network_operations':1})]
    out += [(n,rebind(b,manifest=replace(m,**x))) for n,x in specs]
    r=b['request']; specs=[('request_promotion_id_swap',{'promotion_id':'other-promotion'}),('request_model_id_swap',{'declared_model_id':'other-model'}),('request_revision_swap',{'declared_revision':'other-revision'}),('request_namespace_swap',{'declared_registry_namespace':'other/ns'}),('request_registry_model_swap',{'declared_registry_model_name':'other-registry-model'}),('request_registry_version_swap',{'declared_registry_version':'other-version'}),('request_artifact_ids_reordered',{'declared_artifact_ids':tuple(reversed(r.declared_artifact_ids))}),('request_stale',{'evaluated_at_epoch':NOW+301}),('request_predates',{'evaluated_at_epoch':NOW-6})]
    out += [(n,{**b,'request':replace(r,**x)}) for n,x in specs]
    p=b['policy']; specs=[('policy_version_invalid',{'policy_version':'other-policy'}),('policy_manifest_digest_invalid',{'expected_manifest_sha256':'x'}),('policy_upstream_digest_invalid',{'expected_p9g_assessment_sha256':'x'}),('policy_artifact_order_duplicate',{'expected_artifact_order':p.expected_artifact_order[:-1]+(p.expected_artifact_order[0],)}),('policy_role_invalid',{'expected_role_by_artifact_id':{**p.expected_role_by_artifact_id,p.expected_artifact_order[0]:'bad-role'}}),('policy_no_primary',{'expected_role_by_artifact_id':{k:'config' for k in p.expected_role_by_artifact_id}}),('policy_mutable_version',{'expected_registry_version':'latest'}),('policy_mutable_tag',{'expected_tag':'latest'}),('policy_revocation_invalid',{'expected_revocation_epoch':0}),('policy_age_invalid',{'max_manifest_age_seconds':-1}),('policy_skew_invalid',{'max_future_skew_seconds':-1}),('policy_package_digest_invalid',{'expected_package_manifest_sha256':'x'}),('policy_release_digest_invalid',{'expected_release_digest':'x'}),('policy_rollback_digest_invalid',{'expected_rollback_release_digest':'x'}),('policy_artifact_digest_invalid',{'expected_sha256_by_artifact_id':{**p.expected_sha256_by_artifact_id,p.expected_artifact_order[0]:'x'}})]
    out += [(n,{**b,'policy':replace(p,**x)}) for n,x in specs]
    return out

def benign_cases():
    b=build_fixture(); m=b['manifest']; out=[('canonical',b)]
    out.append(('uppercase_artifact_digests',rebind(b,manifest=replace(m,artifacts=tuple(replace(a,sha256=a.sha256.upper()) for a in m.artifacts)))))
    out.append(('trusted_source_suffix',rebind(b,manifest=replace(m,artifacts=tuple(replace(a,source=a.source+'?immutable=true') for a in m.artifacts)))))
    out.append(('alternate_valid_authorization_window',rebind(b,manifest=replace(m,authorization=replace(m.authorization,issued_at_epoch=NOW-20,expires_at_epoch=NOW+200)))))
    return out

def _allows(f):
    try: return ModelRegistryPromotionAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p9g']).decision is PromotionDecision.ALLOW
    except ModelPromotionSecurityRejected: return False

def run_evaluation():
    attacks=adversarial_cases(); benign=benign_cases(); v=VulnerableCallerDeclaredModelPromotionSafety(); c=build_fixture(); clean=ModelRegistryPromotionAnalyzer(c['policy']).evaluate(c['request'],c['manifest'],c['p9g']); names=[n for n,_ in attacks]; evidence={'attack_names':names,'benign_names':[n for n,_ in benign],'clean_assessment':asdict(clean)}
    return {'adversarial_cases':len(attacks),'vulnerable_attack_successes':sum(v.evaluate(x['request']) for _,x in attacks),'hardened_attack_successes':sum(_allows(x) for _,x in attacks),'hardened_false_positives':sum(not _allows(x) for _,x in benign),'safe_task_successes':sum(_allows(x) for _,x in benign),'safe_task_total':len(benign),'manifest_sha256':c['policy'].expected_manifest_sha256,'adversarial_dataset_sha256':hashlib.sha256(json.dumps(names,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'fixture_evaluator_evidence_sha256':hashlib.sha256(json.dumps(evidence,sort_keys=True,default=str,separators=(',',':')).encode()).hexdigest(),'clean_assessment_sha256':clean.assessment_evidence_sha256}
def main():
    r=run_evaluation(); assert r['vulnerable_attack_successes']==r['adversarial_cases'] and r['hardened_attack_successes']==0 and r['hardened_false_positives']==0 and r['safe_task_successes']==r['safe_task_total']; print(json.dumps(r,sort_keys=True)); return 0
if __name__=='__main__': raise SystemExit(main())
