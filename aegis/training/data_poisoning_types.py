from __future__ import annotations
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib, json
from typing import Mapping

P9B_POLICY_VERSION='training-data-poisoning-label-integrity-v1'
P9B_SCHEMA_VERSION='aegis-training-poisoning-manifest-v1'
P9B_ASSESSMENT_SCHEMA_VERSION='aegis-training-poisoning-assessment-v1'
P9B_ASSESSMENT_MODE='deterministic-evidence-bound-training-poisoning-v1'
ZERO_SHA256='0'*64

class ContributorTrust(str, Enum):
    TRUSTED='trusted'; REVIEWED='reviewed'; UNTRUSTED='untrusted'
class ReviewDecision(str, Enum):
    APPROVE='approve'; REJECT='reject'
class PoisoningDecision(str, Enum):
    ALLOW='allow'; DENY='deny'
class PoisoningRisk(str, Enum):
    UPSTREAM_P9A_INVALID='upstream_p9a_invalid'
    UPSTREAM_BINDING_MISMATCH='upstream_binding_mismatch'
    RECORD_COVERAGE_MISMATCH='record_coverage_mismatch'
    RECORD_DIGEST_MISMATCH='record_digest_mismatch'
    RECORD_SOURCE_MISMATCH='record_source_mismatch'
    CONTRIBUTOR_IDENTITY_MISMATCH='contributor_identity_mismatch'
    CONTRIBUTOR_TRUST_MISMATCH='contributor_trust_mismatch'
    CONTRIBUTOR_WEIGHT_MISMATCH='contributor_weight_mismatch'
    CONTRIBUTOR_CONCENTRATION='contributor_concentration'
    LABEL_MISMATCH='label_mismatch'
    LABEL_CONFIDENCE_INVALID='label_confidence_invalid'
    ANOMALY_SCORE_EXCEEDED='anomaly_score_exceeded'
    POISONING_SIGNAL_PRESENT='poisoning_signal_present'
    DUPLICATE_CLUSTER_ABUSE='duplicate_cluster_abuse'
    REVIEW_REQUIRED='review_required'
    REVIEW_INVALID='review_invalid'
    REVIEW_CONFLICT='review_conflict'
    QUARANTINE_REQUIRED='quarantine_required'
    QUARANTINE_BYPASS='quarantine_bypass'
    INCLUDED_RECORD_SET_MISMATCH='included_record_set_mismatch'
class PoisoningRejectReason(str, Enum):
    POLICY_INVALID='policy_invalid'; MANIFEST_INVALID='manifest_invalid'; MANIFEST_DIGEST_MISMATCH='manifest_digest_mismatch'; REQUEST_INVALID='request_invalid'; DECLARED_SUMMARY_MISMATCH='declared_summary_mismatch'
class TrainingDataPoisoningRejected(ValueError):
    def __init__(self, reason:PoisoningRejectReason, message:str):
        super().__init__(f'{reason.value}: {message}'); self.reason=reason; self.message=message

def reject(reason, message): raise TrainingDataPoisoningRejected(reason, message)

def _jsonable(v):
    if isinstance(v, Enum): return v.value
    if is_dataclass(v): return {k:_jsonable(x) for k,x in asdict(v).items()}
    if isinstance(v, Mapping): return {str(k.value if isinstance(k,Enum) else k):_jsonable(x) for k,x in sorted(v.items(), key=lambda i:str(i[0]))}
    if isinstance(v,(tuple,list)): return [_jsonable(x) for x in v]
    return v

def canonical_json_bytes(v): return json.dumps(_jsonable(v),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest_json(v): return hashlib.sha256(canonical_json_bytes(v)).hexdigest()

@dataclass(frozen=True)
class ContributorEvidence:
    contributor_id:str; trust:ContributorTrust; trust_weight_bps:int
@dataclass(frozen=True)
class LabelReviewEvidence:
    review_id:str; record_id:str; reviewer_id:str; decision:ReviewDecision; approved_label:str; reviewed_payload_sha256:str; evidence_sha256:str
@dataclass(frozen=True)
class TrainingRecordSecurityEvidence:
    record_id:str; payload_sha256:str; source_id:str; contributor_id:str; label:str; label_confidence_bps:int; anomaly_score_bps:int; poisoning_signal_ids:tuple[str,...]; duplicate_cluster_id:str; quarantined:bool; review_ids:tuple[str,...]
@dataclass(frozen=True)
class TrainingPoisoningManifest:
    schema_version:str; manifest_id:str; dataset_id:str; dataset_version:str; created_at_epoch:int; p9a_assessment_sha256:str; p9a_final_dataset_sha256:str; contributors:tuple[ContributorEvidence,...]; records:tuple[TrainingRecordSecurityEvidence,...]; reviews:tuple[LabelReviewEvidence,...]; included_record_ids:tuple[str,...]
@dataclass(frozen=True)
class TrainingPoisoningPolicy:
    policy_version:str; expected_manifest_id:str; expected_dataset_id:str; expected_dataset_version:str; expected_manifest_sha256:str; expected_p9a_assessment_sha256:str; expected_p9a_final_dataset_sha256:str; expected_record_sha256_by_id:Mapping[str,str]; expected_source_by_record_id:Mapping[str,str]; expected_contributor_by_record_id:Mapping[str,str]; expected_label_by_record_id:Mapping[str,str]; contributor_trust_by_id:Mapping[str,ContributorTrust]; contributor_weight_bps_by_id:Mapping[str,int]; trusted_reviewer_ids:tuple[str,...]; minimum_review_weight_bps:int; max_contributor_share_bps:int; max_anomaly_score_bps:int; max_duplicate_cluster_size:int; allowed_poisoning_signal_ids:tuple[str,...]; min_label_confidence_bps:int; max_manifest_age_seconds:int; max_future_skew_seconds:int
@dataclass(frozen=True)
class TrainingPoisoningRequest:
    manifest_id:str; manifest_sha256:str; dataset_id:str; dataset_version:str; evaluated_at_epoch:int; declared_included_record_ids:tuple[str,...]; declared_quarantined_record_ids:tuple[str,...]; declared_weighted_risk_score:int; declared_training_data_safe:bool; declared_label_integrity_verified:bool
@dataclass(frozen=True)
class VerifiedTrainingPoisoningAssessment:
    manifest_id:str; dataset_id:str; dataset_version:str; decision:PoisoningDecision; risks:tuple[PoisoningRisk,...]; record_count:int; included_record_ids:tuple[str,...]; quarantined_record_ids:tuple[str,...]; contributor_count:int; reviewed_record_count:int; weighted_risk_score:int; upstream_p9a_bound:bool; record_integrity_verified:bool; label_integrity_verified:bool; contributor_trust_verified:bool; poisoning_indicators_clear:bool; caller_declared_training_data_safety_trusted:bool; production_data_quality_platform_integrated:bool; semantic_poisoning_detection_validated:bool; human_review_identity_cryptographically_authenticated:bool; assessment_schema_version:str; assessment_mode:str; assessment_evidence_sha256:str

def review_evidence_digest(review:LabelReviewEvidence)->str:
    return digest_json({'review_id':review.review_id,'record_id':review.record_id,'reviewer_id':review.reviewer_id,'decision':review.decision,'approved_label':review.approved_label,'reviewed_payload_sha256':review.reviewed_payload_sha256})
def training_poisoning_manifest_digest(m:TrainingPoisoningManifest)->str: return digest_json(m)
