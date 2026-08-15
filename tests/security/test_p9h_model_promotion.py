from __future__ import annotations
from dataclasses import replace
import pytest
from aegis.training.model_promotion_security import ModelRegistryPromotionAnalyzer
from aegis.training.model_promotion_types import ModelPromotionSecurityRejected, PromotionDecision, PromotionRejectReason, PromotionRisk
from aegis.vulnerable.model_promotion import VulnerableCallerDeclaredModelPromotionSafety
from evals.p9h_fixture import NOW, build_fixture, h, rebind
from evals.p9h_model_promotion import adversarial_cases, benign_cases, run_evaluation

def evaluate(f): return ModelRegistryPromotionAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p9g'])
def test_clean_promotion_is_allowed_and_evidence_bound():
    a=evaluate(build_fixture()); assert a.decision is PromotionDecision.ALLOW and a.risks==() and a.upstream_p9g_bound and a.training_lineage_verified and a.phase5_provenance_handoff_bound and a.registry_target_immutable and a.promotion_authorization_verified and a.rollback_and_revocation_bound
def test_clean_assessment_preserves_claim_boundary():
    a=evaluate(build_fixture()); assert not a.caller_declared_safety_trusted and not a.registry_write_executed and not a.production_model_registry_integrated and not a.cryptographic_promotion_signature_verified and not a.deployment_executed
def test_all_adversarial_cases_fail_closed():
    for name,f in adversarial_cases():
        try: a=evaluate(f)
        except ModelPromotionSecurityRejected: continue
        assert a.decision is PromotionDecision.DENY,name
def test_vulnerable_baseline_accepts_every_attack(): assert all(VulnerableCallerDeclaredModelPromotionSafety().evaluate(f['request']) for _,f in adversarial_cases())
def test_benign_variants_remain_allowed():
    for name,f in benign_cases(): assert evaluate(f).decision is PromotionDecision.ALLOW,name
def _risks(f): return ModelRegistryPromotionAnalyzer(f['policy']).derive(f['manifest'],f['p9g'],NOW)
def test_upstream_failure_maps_to_upstream_risk():
    f=build_fixture(); c=rebind(f,p9g=replace(f['p9g'],input_governance_verified=False)); assert PromotionRisk.UPSTREAM_P9G_INVALID in _risks(c)
def test_upstream_digest_swap_maps_to_binding_risk():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],p9g_assessment_sha256=h('other'))); assert PromotionRisk.UPSTREAM_BINDING_MISMATCH in _risks(c)
def test_lineage_swap_maps_to_training_lineage_risk():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],job_id='other-job')); assert PromotionRisk.TRAINING_LINEAGE_MISMATCH in _risks(c)
def test_model_swap_maps_to_model_identity_risk():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],model_id='other-model')); assert PromotionRisk.MODEL_IDENTITY_MISMATCH in _risks(c)
def test_artifact_reorder_maps_to_coverage_risk():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],artifacts=tuple(reversed(f['manifest'].artifacts)))); assert PromotionRisk.ARTIFACT_COVERAGE_MISMATCH in _risks(c)
def test_artifact_digest_swap_maps_to_metadata_risk():
    f=build_fixture(); aa=list(f['manifest'].artifacts); aa[0]=replace(aa[0],sha256=h('tampered')); c=rebind(f,manifest=replace(f['manifest'],artifacts=tuple(aa))); assert PromotionRisk.ARTIFACT_METADATA_MISMATCH in _risks(c)
def test_phase5_constant_swap_maps_to_bridge_risk():
    f=build_fixture(); b=replace(f['manifest'].phase5_bridge,p5c_policy_version='other'); c=rebind(f,manifest=replace(f['manifest'],phase5_bridge=b)); assert PromotionRisk.PHASE5_BRIDGE_MISMATCH in _risks(c)
def test_registry_target_swap_maps_to_registry_identity_risk():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],registry_namespace='other/ns')); assert PromotionRisk.REGISTRY_IDENTITY_MISMATCH in _risks(c)
def test_mutable_latest_version_fails_closed():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],registry_version='latest')); assert PromotionRisk.MUTABLE_REFERENCE_UNSAFE in _risks(c)
def test_overwrite_existing_fails_closed():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],overwrite_existing=True)); assert PromotionRisk.MUTABLE_REFERENCE_UNSAFE in _risks(c)
def test_authorization_principal_swap_fails_closed():
    f=build_fixture(); a=replace(f['manifest'].authorization,principal_id='other'); c=rebind(f,manifest=replace(f['manifest'],authorization=a)); assert PromotionRisk.PROMOTION_AUTHORIZATION_INVALID in _risks(c)
def test_expired_authorization_fails_closed():
    f=build_fixture(); a=replace(f['manifest'].authorization,expires_at_epoch=NOW-1); c=rebind(f,manifest=replace(f['manifest'],authorization=a)); assert PromotionRisk.AUTHORIZATION_EXPIRED in _risks(c)
def test_predecessor_swap_fails_closed():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],predecessor_version='other')); assert PromotionRisk.PREDECESSOR_MISMATCH in _risks(c)
def test_rollback_release_swap_fails_closed():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],rollback_release_digest=h('other'))); assert PromotionRisk.ROLLBACK_BINDING_MISMATCH in _risks(c)
def test_revocation_epoch_swap_fails_closed():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],revocation_epoch=f['manifest'].revocation_epoch+1)); assert PromotionRisk.REVOCATION_POLICY_MISMATCH in _risks(c)
def test_network_operation_fails_closed():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],network_operations=1)); assert PromotionRisk.NETWORK_OPERATION_UNEXPECTED in _risks(c)
def test_unbound_manifest_digest_rejected():
    f=build_fixture(); r=replace(f['request'],manifest_sha256=h('wrong'))
    with pytest.raises(ModelPromotionSecurityRejected) as e: ModelRegistryPromotionAnalyzer(f['policy']).evaluate(r,f['manifest'],f['p9g'])
    assert e.value.reason is PromotionRejectReason.REQUEST_INVALID
def test_stale_request_rejected():
    f=build_fixture(); r=replace(f['request'],evaluated_at_epoch=NOW+301)
    with pytest.raises(ModelPromotionSecurityRejected) as e: ModelRegistryPromotionAnalyzer(f['policy']).evaluate(r,f['manifest'],f['p9g'])
    assert e.value.reason is PromotionRejectReason.REQUEST_INVALID
def test_caller_cannot_claim_safe_when_evidence_denies():
    f=build_fixture(); c=rebind(f,manifest=replace(f['manifest'],overwrite_existing=True))
    with pytest.raises(ModelPromotionSecurityRejected) as e: evaluate(c)
    assert e.value.reason is PromotionRejectReason.DECLARED_SUMMARY_MISMATCH
def test_policy_rejects_unsafe_phase5_artifact_format():
    f=build_fixture(); p=replace(f['policy'],expected_format_by_artifact_id={**f['policy'].expected_format_by_artifact_id,f['policy'].expected_artifact_order[0]:'pickle'})
    with pytest.raises(ModelPromotionSecurityRejected) as e: ModelRegistryPromotionAnalyzer(p)
    assert e.value.reason is PromotionRejectReason.POLICY_INVALID
def test_evaluator_metrics_are_closed():
    r=run_evaluation(); assert r['adversarial_cases']>=100 and r['vulnerable_attack_successes']==r['adversarial_cases'] and r['hardened_attack_successes']==0 and r['hardened_false_positives']==0 and r['safe_task_successes']==r['safe_task_total']==4
