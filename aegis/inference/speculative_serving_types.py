from __future__ import annotations
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib, json
from typing import Mapping

P10D_POLICY_VERSION='inference-speculative-disaggregated-serving-v1'
P10D_SCHEMA_VERSION='aegis-inference-speculative-serving-manifest-v1'
P10D_ASSESSMENT_SCHEMA_VERSION='aegis-inference-speculative-serving-assessment-v1'
P10D_ASSESSMENT_MODE='deterministic-evidence-bound-speculative-disaggregated-serving-v1'

class ServingDecision(str,Enum): ALLOW='allow'; DENY='deny'
class ServiceRole(str,Enum): PREFILL='prefill'; DRAFT='draft'; DECODE='decode'
class ServingRisk(str,Enum):
    UPSTREAM_P10C_INVALID='upstream_p10c_invalid'
    UPSTREAM_BINDING_MISMATCH='upstream_binding_mismatch'
    REQUEST_ROUTE_MISMATCH='request_route_mismatch'
    TARGET_MODEL_MISMATCH='target_model_mismatch'
    DRAFT_MODEL_MISMATCH='draft_model_mismatch'
    DRAFT_TRUST_MISMATCH='draft_trust_mismatch'
    TOKENIZER_MISMATCH='tokenizer_mismatch'
    SERVICE_COVERAGE_MISMATCH='service_coverage_mismatch'
    SERVICE_IDENTITY_MISMATCH='service_identity_mismatch'
    SERVICE_ROLE_MISMATCH='service_role_mismatch'
    CROSS_TENANT_STATE_TRANSFER='cross_tenant_state_transfer'
    CROSS_SESSION_STATE_TRANSFER='cross_session_state_transfer'
    STATE_TRANSFER_COVERAGE_MISMATCH='state_transfer_coverage_mismatch'
    STATE_TRANSFER_SEQUENCE_MISMATCH='state_transfer_sequence_mismatch'
    STATE_TRANSFER_DIGEST_MISMATCH='state_transfer_digest_mismatch'
    STATE_TRANSFER_REPLAY='state_transfer_replay'
    PREFILL_DECODE_STATE_MISMATCH='prefill_decode_state_mismatch'
    SPECULATIVE_ROUND_COVERAGE_MISMATCH='speculative_round_coverage_mismatch'
    SPECULATIVE_ROUND_MISMATCH='speculative_round_mismatch'
    DRAFT_TOKEN_BUDGET_EXCEEDED='draft_token_budget_exceeded'
    TARGET_VERIFICATION_MISMATCH='target_verification_mismatch'
    UNVERIFIED_DRAFT_ACCEPTANCE='unverified_draft_acceptance'
    FINAL_STATE_MISMATCH='final_state_mismatch'
    PRIOR_TRANSFER_LEDGER_MISMATCH='prior_transfer_ledger_mismatch'
    NETWORK_OPERATION_UNEXPECTED='network_operation_unexpected'
class ServingRejectReason(str,Enum):
    POLICY_INVALID='policy_invalid'; MANIFEST_INVALID='manifest_invalid'; MANIFEST_DIGEST_MISMATCH='manifest_digest_mismatch'; REQUEST_INVALID='request_invalid'; DECLARED_SUMMARY_MISMATCH='declared_summary_mismatch'
class InferenceSpeculativeServingRejected(ValueError):
    def __init__(self,reason:ServingRejectReason,message:str): self.reason=reason; self.message=message; super().__init__(f'{reason.value}: {message}')
def reject(reason,message): raise InferenceSpeculativeServingRejected(reason,message)
def _jsonable(v):
    if isinstance(v,Enum): return v.value
    if is_dataclass(v): return {k:_jsonable(x) for k,x in asdict(v).items()}
    if isinstance(v,Mapping): return {str(k.value if isinstance(k,Enum) else k):_jsonable(x) for k,x in sorted(v.items(),key=lambda p:str(p[0]))}
    if isinstance(v,(tuple,list)): return [_jsonable(x) for x in v]
    return v
def digest_json(v): return hashlib.sha256(json.dumps(_jsonable(v),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

@dataclass(frozen=True)
class ServingServiceEvidence:
    service_id:str; role:ServiceRole; request_id:str; tenant_id:str; session_id:str; model_id:str; model_revision:str; model_sha256:str; tokenizer_sha256:str; input_evidence_sha256:str; output_evidence_sha256:str; service_identity_sha256:str
@dataclass(frozen=True)
class StateTransferEvidence:
    transfer_id:str; sequence_no:int; source_service_id:str; destination_service_id:str; request_id:str; tenant_id:str; session_id:str; cache_epoch:int; state_sha256:str; source_output_sha256:str; destination_input_sha256:str; previous_transfer_sha256:str
@dataclass(frozen=True)
class SpeculativeRoundEvidence:
    round_id:str; sequence_no:int; draft_service_id:str; decode_service_id:str; request_id:str; tenant_id:str; session_id:str; input_state_sha256:str; proposal_sha256:str; proposed_token_count:int; target_verified_token_count:int; accepted_token_count:int; rejected_token_count:int; target_verification_sha256:str; result_state_sha256:str
@dataclass(frozen=True)
class InferenceSpeculativeServingManifest:
    schema_version:str; manifest_id:str; created_at_epoch:int; p10c_assessment_sha256:str; upstream_scheduler_id:str; upstream_batch_id:str; cache_epoch:int; request_id:str; tenant_id:str; session_id:str; request_input_sha256:str; target_model_id:str; target_model_revision:str; target_model_sha256:str; draft_model_id:str; draft_model_revision:str; draft_model_sha256:str; tokenizer_sha256:str; draft_trust_profile_sha256:str; handoff_state_sha256:str; services:tuple[ServingServiceEvidence,...]; transfers:tuple[StateTransferEvidence,...]; speculative_rounds:tuple[SpeculativeRoundEvidence,...]; final_state_sha256:str; prior_transfer_ids:tuple[str,...]; prior_transfer_ledger_sha256:str; network_operations:int=0
@dataclass(frozen=True)
class InferenceSpeculativeServingPolicy:
    policy_version:str; expected_manifest_id:str; expected_manifest_sha256:str; expected_p10c_assessment_sha256:str; expected_upstream_scheduler_id:str; expected_upstream_batch_id:str; expected_cache_epoch:int; expected_request_id:str; expected_tenant_id:str; expected_session_id:str; expected_request_input_sha256:str; expected_target_model_id:str; expected_target_model_revision:str; expected_target_model_sha256:str; expected_draft_model_id:str; expected_draft_model_revision:str; expected_draft_model_sha256:str; expected_tokenizer_sha256:str; expected_draft_trust_profile_sha256:str; expected_handoff_state_sha256:str; expected_service_ids:tuple[str,...]; expected_service_role_by_id:Mapping[str,ServiceRole]; expected_service_identity_sha256_by_id:Mapping[str,str]; expected_transfer_ids:tuple[str,...]; expected_transfer_edges:Mapping[str,tuple[str,str]]; expected_round_ids:tuple[str,...]; max_draft_tokens_per_round:int; max_speculative_rounds:int; expected_prior_transfer_ledger_sha256:str; max_manifest_age_seconds:int; max_future_skew_seconds:int
@dataclass(frozen=True)
class InferenceSpeculativeServingRequest:
    manifest_id:str; manifest_sha256:str; evaluated_at_epoch:int; declared_request_id:str; declared_tenant_id:str; declared_session_id:str; declared_target_model_revision:str; declared_draft_model_revision:str; declared_service_ids:tuple[str,...]; declared_transfer_ids:tuple[str,...]; declared_round_ids:tuple[str,...]; declared_final_state_sha256:str; declared_upstream_p10c_bound:bool; declared_route_safe:bool; declared_draft_trust_safe:bool; declared_service_binding_safe:bool; declared_state_transfer_safe:bool; declared_speculative_verification_safe:bool; declared_final_state_safe:bool; declared_serving_safe:bool
@dataclass(frozen=True)
class VerifiedInferenceSpeculativeServingAssessment:
    manifest_id:str; manifest_sha256:str; request_id:str; tenant_id:str; session_id:str; decision:ServingDecision; risks:tuple[ServingRisk,...]; p10c_assessment_sha256:str; scheduler_id:str; batch_id:str; cache_epoch:int; target_model_id:str; target_model_revision:str; draft_model_id:str; draft_model_revision:str; service_ids:tuple[str,...]; transfer_ids:tuple[str,...]; round_ids:tuple[str,...]; final_state_sha256:str; upstream_p10c_bound:bool; route_identity_verified:bool; draft_model_trust_verified:bool; service_topology_verified:bool; state_transfer_verified:bool; speculative_verification_verified:bool; final_state_verified:bool; caller_declared_safety_trusted:bool; production_inference_engine_integrated:bool; production_rpc_transport_verified:bool; cryptographic_service_attestation_verified:bool; production_speculative_decoder_validated:bool; semantic_token_equivalence_verified:bool; side_channel_resistance_validated:bool; assessment_schema_version:str; assessment_mode:str; assessment_evidence_sha256:str

def service_identity_digest(service:ServingServiceEvidence)->str:
    return digest_json({'service_id':service.service_id,'role':service.role,'model_id':service.model_id,'model_revision':service.model_revision,'model_sha256':service.model_sha256,'tokenizer_sha256':service.tokenizer_sha256})
def state_transfer_digest(transfer:StateTransferEvidence)->str: return digest_json(transfer)
def prior_transfer_ledger_digest(ids:tuple[str,...])->str: return digest_json({'prior_transfer_ids':tuple(sorted(ids))})
def target_verification_digest(round:SpeculativeRoundEvidence,target_model_sha256:str,tokenizer_sha256:str)->str:
    return digest_json({'round_id':round.round_id,'request_id':round.request_id,'tenant_id':round.tenant_id,'session_id':round.session_id,'input_state_sha256':round.input_state_sha256,'proposal_sha256':round.proposal_sha256,'proposed_token_count':round.proposed_token_count,'target_verified_token_count':round.target_verified_token_count,'accepted_token_count':round.accepted_token_count,'rejected_token_count':round.rejected_token_count,'target_model_sha256':target_model_sha256,'tokenizer_sha256':tokenizer_sha256})
def inference_speculative_serving_manifest_digest(m:InferenceSpeculativeServingManifest)->str: return digest_json(m)
