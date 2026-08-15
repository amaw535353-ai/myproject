from __future__ import annotations
from dataclasses import asdict,dataclass,is_dataclass
from enum import Enum
import hashlib,json
from typing import Mapping

P10E_POLICY_VERSION='inference-adapter-hot-swap-routing-v1'
P10E_SCHEMA_VERSION='aegis-inference-adapter-hot-swap-manifest-v1'
P10E_ASSESSMENT_SCHEMA_VERSION='aegis-inference-adapter-hot-swap-assessment-v1'
P10E_ASSESSMENT_MODE='deterministic-evidence-bound-adapter-hot-swap-routing-v1'

class AdapterDecision(str,Enum): ALLOW='allow'; DENY='deny'
class AdapterKind(str,Enum): LORA='lora'; ADAPTER='adapter'
class AdapterRisk(str,Enum):
    UPSTREAM_P10D_INVALID='upstream_p10d_invalid'
    UPSTREAM_BINDING_MISMATCH='upstream_binding_mismatch'
    REQUEST_ROUTE_MISMATCH='request_route_mismatch'
    BASE_MODEL_MISMATCH='base_model_mismatch'
    TOKENIZER_MISMATCH='tokenizer_mismatch'
    ADAPTER_COVERAGE_MISMATCH='adapter_coverage_mismatch'
    ADAPTER_IDENTITY_MISMATCH='adapter_identity_mismatch'
    ADAPTER_DIGEST_MISMATCH='adapter_digest_mismatch'
    ADAPTER_FORMAT_UNSAFE='adapter_format_unsafe'
    ADAPTER_BASE_BINDING_MISMATCH='adapter_base_binding_mismatch'
    ADAPTER_TENANT_MISMATCH='adapter_tenant_mismatch'
    ADAPTER_PROVENANCE_MISMATCH='adapter_provenance_mismatch'
    ADAPTER_PARAMETER_POLICY_MISMATCH='adapter_parameter_policy_mismatch'
    ADAPTER_STACK_ORDER_MISMATCH='adapter_stack_order_mismatch'
    ADAPTER_STACK_DEPTH_EXCEEDED='adapter_stack_depth_exceeded'
    ADAPTER_COMPOSITION_UNAUTHORIZED='adapter_composition_unauthorized'
    AUTHORIZATION_INVALID='authorization_invalid'
    AUTHORIZATION_EXPIRED='authorization_expired'
    HOT_SWAP_COVERAGE_MISMATCH='hot_swap_coverage_mismatch'
    HOT_SWAP_SEQUENCE_MISMATCH='hot_swap_sequence_mismatch'
    HOT_SWAP_GENERATION_MISMATCH='hot_swap_generation_mismatch'
    HOT_SWAP_REPLAY='hot_swap_replay'
    HOT_SWAP_TRANSITION_INVALID='hot_swap_transition_invalid'
    ROUTE_SNAPSHOT_MISMATCH='route_snapshot_mismatch'
    RETIRED_ADAPTER_RESURRECTED='retired_adapter_resurrected'
    PRIOR_SWAP_LEDGER_MISMATCH='prior_swap_ledger_mismatch'
    NETWORK_OPERATION_UNEXPECTED='network_operation_unexpected'
class AdapterRejectReason(str,Enum): POLICY_INVALID='policy_invalid'; MANIFEST_INVALID='manifest_invalid'; MANIFEST_DIGEST_MISMATCH='manifest_digest_mismatch'; REQUEST_INVALID='request_invalid'; DECLARED_SUMMARY_MISMATCH='declared_summary_mismatch'
class InferenceAdapterRoutingRejected(ValueError):
    def __init__(self,reason:AdapterRejectReason,message:str): self.reason=reason; self.message=message; super().__init__(f'{reason.value}: {message}')
def reject(reason,message): raise InferenceAdapterRoutingRejected(reason,message)
def _jsonable(v):
    if isinstance(v,Enum): return v.value
    if is_dataclass(v): return {k:_jsonable(x) for k,x in asdict(v).items()}
    if isinstance(v,Mapping): return {str(k.value if isinstance(k,Enum) else k):_jsonable(x) for k,x in sorted(v.items(),key=lambda p:str(p[0]))}
    if isinstance(v,(tuple,list)): return [_jsonable(x) for x in v]
    return v
def digest_json(v): return hashlib.sha256(json.dumps(_jsonable(v),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

@dataclass(frozen=True)
class RuntimeAdapterEvidence:
    adapter_id:str; kind:AdapterKind; revision:str; artifact_sha256:str; serialization_format:str; tenant_id:str; base_model_id:str; base_model_revision:str; base_model_sha256:str; tokenizer_sha256:str; generation:int; rank:int; alpha_bps:int; target_modules:tuple[str,...]; parent_adapter_ids:tuple[str,...]; provenance_sha256:str
@dataclass(frozen=True)
class AdapterAuthorizationEvidence:
    authorization_id:str; grant_id:str; principal_id:str; tenant_id:str; action:str; target_adapter_ids:tuple[str,...]; base_model_sha256:str; issued_at_epoch:int; expires_at_epoch:int
@dataclass(frozen=True)
class AdapterRouteSnapshot:
    snapshot_id:str; request_id:str; tenant_id:str; session_id:str; generation:int; base_model_id:str; base_model_revision:str; base_model_sha256:str; tokenizer_sha256:str; active_adapter_ids:tuple[str,...]; composition_sha256:str
@dataclass(frozen=True)
class AdapterHotSwapEvidence:
    swap_id:str; sequence_no:int; request_id:str; tenant_id:str; session_id:str; from_generation:int; to_generation:int; prior_adapter_ids:tuple[str,...]; next_adapter_ids:tuple[str,...]; authorization_sha256:str; before_snapshot_sha256:str; after_snapshot_sha256:str; previous_swap_sha256:str
@dataclass(frozen=True)
class InferenceAdapterRoutingManifest:
    schema_version:str; manifest_id:str; created_at_epoch:int; p10d_assessment_sha256:str; request_id:str; tenant_id:str; session_id:str; principal_id:str; target_model_id:str; target_model_revision:str; target_model_sha256:str; tokenizer_sha256:str; adapters:tuple[RuntimeAdapterEvidence,...]; authorization:AdapterAuthorizationEvidence; route_before:AdapterRouteSnapshot; swaps:tuple[AdapterHotSwapEvidence,...]; route_after:AdapterRouteSnapshot; prior_swap_ids:tuple[str,...]; prior_swap_ledger_sha256:str; retired_adapter_ids:tuple[str,...]; network_operations:int=0
@dataclass(frozen=True)
class InferenceAdapterRoutingPolicy:
    policy_version:str; expected_manifest_id:str; expected_manifest_sha256:str; expected_p10d_assessment_sha256:str; expected_request_id:str; expected_tenant_id:str; expected_session_id:str; expected_principal_id:str; expected_target_model_id:str; expected_target_model_revision:str; expected_target_model_sha256:str; expected_tokenizer_sha256:str; expected_adapter_ids:tuple[str,...]; expected_adapter_revision_by_id:Mapping[str,str]; expected_adapter_kind_by_id:Mapping[str,AdapterKind]; expected_adapter_generation_by_id:Mapping[str,int]; expected_adapter_parent_ids_by_id:Mapping[str,tuple[str,...]]; expected_adapter_artifact_sha256_by_id:Mapping[str,str]; expected_adapter_provenance_sha256_by_id:Mapping[str,str]; allowed_adapter_kinds:tuple[AdapterKind,...]; allowed_serialization_formats:tuple[str,...]; allowed_target_modules:tuple[str,...]; max_adapter_rank:int; max_adapter_alpha_bps:int; max_stack_depth:int; allowed_compositions:tuple[tuple[str,...],...]; expected_authorization_id:str; expected_grant_id:str; expected_authorization_action:str; expected_before_generation:int; expected_before_adapter_ids:tuple[str,...]; expected_after_generation:int; expected_after_adapter_ids:tuple[str,...]; expected_swap_ids:tuple[str,...]; expected_prior_swap_ledger_sha256:str; max_manifest_age_seconds:int; max_future_skew_seconds:int
@dataclass(frozen=True)
class InferenceAdapterRoutingRequest:
    manifest_id:str; manifest_sha256:str; evaluated_at_epoch:int; declared_request_id:str; declared_tenant_id:str; declared_session_id:str; declared_principal_id:str; declared_target_model_revision:str; declared_before_adapter_ids:tuple[str,...]; declared_after_adapter_ids:tuple[str,...]; declared_after_generation:int; declared_swap_ids:tuple[str,...]; declared_upstream_p10d_bound:bool; declared_base_route_bound:bool; declared_adapter_artifacts_safe:bool; declared_tenant_composition_safe:bool; declared_authorization_safe:bool; declared_hot_swap_safe:bool; declared_route_snapshot_safe:bool; declared_adapter_routing_safe:bool
@dataclass(frozen=True)
class VerifiedInferenceAdapterRoutingAssessment:
    manifest_id:str; manifest_sha256:str; request_id:str; tenant_id:str; session_id:str; principal_id:str; decision:AdapterDecision; risks:tuple[AdapterRisk,...]; p10d_assessment_sha256:str; target_model_id:str; target_model_revision:str; adapter_ids:tuple[str,...]; before_adapter_ids:tuple[str,...]; after_adapter_ids:tuple[str,...]; after_generation:int; swap_ids:tuple[str,...]; upstream_p10d_bound:bool; base_route_verified:bool; adapter_artifacts_verified:bool; tenant_composition_verified:bool; authorization_verified:bool; hot_swap_verified:bool; route_snapshot_verified:bool; caller_declared_safety_trusted:bool; production_adapter_manager_integrated:bool; production_model_router_integrated:bool; cryptographic_adapter_signature_verified:bool; atomic_hot_swap_validated:bool; distributed_route_consistency_validated:bool; side_channel_resistance_validated:bool; assessment_schema_version:str; assessment_mode:str; assessment_evidence_sha256:str

def adapter_composition_digest(base_model_sha256:str,tokenizer_sha256:str,adapter_ids:tuple[str,...],artifact_sha256_by_id:Mapping[str,str])->str:
    return digest_json({'base_model_sha256':base_model_sha256.casefold(),'tokenizer_sha256':tokenizer_sha256.casefold(),'adapter_ids':adapter_ids,'adapter_artifact_sha256':[artifact_sha256_by_id[a].casefold() for a in adapter_ids]})
def route_snapshot_digest(snapshot:AdapterRouteSnapshot)->str: return digest_json(snapshot)
def adapter_authorization_digest(auth:AdapterAuthorizationEvidence)->str: return digest_json(auth)
def adapter_hot_swap_digest(swap:AdapterHotSwapEvidence)->str: return digest_json(swap)
def prior_swap_ledger_digest(ids:tuple[str,...])->str: return digest_json({'prior_swap_ids':tuple(sorted(ids))})
def inference_adapter_routing_manifest_digest(m:InferenceAdapterRoutingManifest)->str: return digest_json(m)
