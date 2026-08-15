from dataclasses import replace
import pytest
from aegis.training.data_poisoning_security import TrainingDataPoisoningAnalyzer
from aegis.training.data_poisoning_types import *
from aegis.vulnerable.training_data_poisoning import VulnerableCallerDeclaredTrainingDataSafety
from evals.p9b_fixture import build_fixture,rebind,h
from evals.p9b_training_data_poisoning import build_attacks

def test_clean_allows():
 f=build_fixture(); a=TrainingDataPoisoningAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p9a']); assert a.decision==PoisoningDecision.ALLOW and a.upstream_p9a_bound and a.label_integrity_verified and not a.caller_declared_training_data_safety_trusted

def test_clean_counts_and_score():
 f=build_fixture(); a=TrainingDataPoisoningAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p9a']); assert a.record_count==8 and a.contributor_count==3 and a.reviewed_record_count==2 and a.weighted_risk_score==450

def test_vulnerable_accepts_all_attacks():
 v=VulnerableCallerDeclaredTrainingDataSafety(); attacks=build_attacks(); assert attacks and all(v.evaluate(x['request'],x['manifest'],x['p9a']) for _,x in attacks)

def test_hardened_rejects_all_attacks():
 for name,f in build_attacks():
  try:
   a=TrainingDataPoisoningAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p9a']); assert a.decision==PoisoningDecision.DENY,name
  except TrainingDataPoisoningRejected: pass

def test_upstream_binding_required():
 f=build_fixture(); x=rebind(f,p9a=replace(f['p9a'],split_isolation_verified=False)); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.UPSTREAM_P9A_INVALID in risks

def test_label_tamper_denied():
 f=build_fixture(); rs=list(f['manifest'].records); rs[0]=replace(rs[0],label='evil'); x=rebind(f,replace(f['manifest'],records=tuple(rs))); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.LABEL_MISMATCH in risks

def test_poison_signal_requires_quarantine():
 f=build_fixture(); rs=list(f['manifest'].records); rs[0]=replace(rs[0],poisoning_signal_ids=('trigger',)); x=rebind(f,replace(f['manifest'],records=tuple(rs))); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.POISONING_SIGNAL_PRESENT in risks and PoisoningRisk.QUARANTINE_REQUIRED in risks

def test_low_trust_requires_review():
 f=build_fixture(); rs=list(f['manifest'].records); rs[6]=replace(rs[6],review_ids=()); x=rebind(f,replace(f['manifest'],records=tuple(rs))); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.REVIEW_REQUIRED in risks

def test_review_evidence_tamper_denied():
 f=build_fixture(); vs=list(f['manifest'].reviews); vs[0]=replace(vs[0],evidence_sha256=h('forged')); x=rebind(f,replace(f['manifest'],reviews=tuple(vs))); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.REVIEW_INVALID in risks

def test_contributor_concentration_denied():
 f=build_fixture(); rs=tuple(replace(r,contributor_id='contrib-curated-a') for r in f['manifest'].records); x=rebind(f,replace(f['manifest'],records=rs)); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.CONTRIBUTOR_CONCENTRATION in risks

def test_duplicate_cluster_abuse_denied():
 f=build_fixture(); rs=list(f['manifest'].records); rs[:4]=[replace(r,duplicate_cluster_id='same') for r in rs[:4]]; x=rebind(f,replace(f['manifest'],records=tuple(rs))); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.DUPLICATE_CLUSTER_ABUSE in risks

def test_unnecessary_quarantine_denied():
 f=build_fixture(); rs=list(f['manifest'].records); rs[0]=replace(rs[0],quarantined=True); m=replace(f['manifest'],records=tuple(rs),included_record_ids=tuple(r.record_id for r in rs[1:])); x=rebind(f,m); risks,*_=TrainingDataPoisoningAnalyzer(x['policy']).derive(x['manifest'],x['p9a'],x['request'].evaluated_at_epoch); assert PoisoningRisk.QUARANTINE_BYPASS in risks

def test_request_summary_cannot_override():
 f=build_fixture()
 with pytest.raises(TrainingDataPoisoningRejected):
  TrainingDataPoisoningAnalyzer(f['policy']).evaluate(replace(f['request'],declared_weighted_risk_score=0),f['manifest'],f['p9a'])

def test_manifest_digest_pinned():
 f=build_fixture(); rs=list(f['manifest'].records); rs[0]=replace(rs[0],label='evil'); m=replace(f['manifest'],records=tuple(rs))
 with pytest.raises(TrainingDataPoisoningRejected):
  TrainingDataPoisoningAnalyzer(f['policy']).evaluate(replace(f['request'],manifest_sha256=training_poisoning_manifest_digest(m)),m,f['p9a'])

def test_policy_version_pinned():
 f=build_fixture()
 with pytest.raises(TrainingDataPoisoningRejected):
  TrainingDataPoisoningAnalyzer(replace(f['policy'],policy_version='wrong'))

def test_production_flags_false():
 f=build_fixture(); a=TrainingDataPoisoningAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p9a']); assert not a.production_data_quality_platform_integrated and not a.semantic_poisoning_detection_validated and not a.human_review_identity_cryptographically_authenticated

def test_assessment_profile_pinned():
 f=build_fixture(); a=TrainingDataPoisoningAnalyzer(f['policy']).evaluate(f['request'],f['manifest'],f['p9a']); assert a.assessment_schema_version==P9B_ASSESSMENT_SCHEMA_VERSION and a.assessment_mode==P9B_ASSESSMENT_MODE

def test_manifest_shape_duplicate_record_rejected():
 f=build_fixture(); m=replace(f['manifest'],records=f['manifest'].records+(f['manifest'].records[0],)); x=rebind(f,m)
 with pytest.raises(TrainingDataPoisoningRejected):
  TrainingDataPoisoningAnalyzer(x['policy']).evaluate(x['request'],x['manifest'],x['p9a'])

def test_reviewed_records_are_bound_to_payload():
 f=build_fixture(); assert all(v.reviewed_payload_sha256==next(r.payload_sha256 for r in f['manifest'].records if r.record_id==v.record_id) for v in f['manifest'].reviews)
