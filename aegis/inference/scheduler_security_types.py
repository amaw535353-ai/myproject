from __future__ import annotations
from dataclasses import asdict,dataclass,is_dataclass
from enum import Enum
import hashlib,json
from typing import Mapping

P10B_POLICY_VERSION='inference-scheduler-fairness-admission-v1'
P10B_SCHEMA_VERSION='aegis-inference-scheduler-admission-manifest-v1'
P10B_ASSESSMENT_SCHEMA_VERSION='aegis-inference-scheduler-admission-assessment-v1'
P10B_ASSESSMENT_MODE='deterministic-evidence-bound-inference-scheduler-fairness-v1'

class SchedulerDecision(str,Enum): ALLOW='allow'; DENY='deny'
class SchedulerRisk(str,Enum):
    UPSTREAM_P10A_INVALID='upstream_p10a_invalid'
    UPSTREAM_BINDING_MISMATCH='upstream_binding_mismatch'
    SCHEDULER_IDENTITY_MISMATCH='scheduler_identity_mismatch'
    REQUEST_COVERAGE_MISMATCH='request_coverage_mismatch'
    REQUEST_TENANT_MISMATCH='request_tenant_mismatch'
    DUPLICATE_REQUEST='duplicate_request'
    REQUEST_RESOURCE_LIMIT_EXCEEDED='request_resource_limit_exceeded'
    TENANT_CONCURRENCY_EXCEEDED='tenant_concurrency_exceeded'
    TENANT_QUEUE_DEPTH_EXCEEDED='tenant_queue_depth_exceeded'
    TENANT_TOKEN_BUDGET_EXCEEDED='tenant_token_budget_exceeded'
    TENANT_MEMORY_BUDGET_EXCEEDED='tenant_memory_budget_exceeded'
    GLOBAL_CAPACITY_EXCEEDED='global_capacity_exceeded'
    PRIORITY_POLICY_MISMATCH='priority_policy_mismatch'
    STARVATION_BOUND_EXCEEDED='starvation_bound_exceeded'
    FAIRNESS_STATE_MISMATCH='fairness_state_mismatch'
    FAIRNESS_SELECTION_MISMATCH='fairness_selection_mismatch'
    BATCH_PLAN_MISMATCH='batch_plan_mismatch'
    BATCH_CAPACITY_EXCEEDED='batch_capacity_exceeded'
    ADMITTED_LEDGER_MISMATCH='admitted_ledger_mismatch'
    NETWORK_OPERATION_UNEXPECTED='network_operation_unexpected'
class SchedulerRejectReason(str,Enum): POLICY_INVALID='policy_invalid'; MANIFEST_INVALID='manifest_invalid'; MANIFEST_DIGEST_MISMATCH='manifest_digest_mismatch'; REQUEST_INVALID='request_invalid'; DECLARED_SUMMARY_MISMATCH='declared_summary_mismatch'
class InferenceSchedulerRejected(ValueError):
    def __init__(self,reason:SchedulerRejectReason,message:str): self.reason=reason; self.message=message; super().__init__(f'{reason.value}: {message}')
def reject(reason,message): raise InferenceSchedulerRejected(reason,message)
def _jsonable(v):
    if isinstance(v,Enum): return v.value
    if is_dataclass(v): return {k:_jsonable(x) for k,x in asdict(v).items()}
    if isinstance(v,Mapping): return {str(k.value if isinstance(k,Enum) else k):_jsonable(x) for k,x in sorted(v.items(),key=lambda p:str(p[0]))}
    if isinstance(v,(tuple,list)): return [_jsonable(x) for x in v]
    return v
def digest_json(v): return hashlib.sha256(json.dumps(_jsonable(v),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

@dataclass(frozen=True)
class SchedulerRequestEvidence:
    request_id:str; tenant_id:str; session_id:str; sequence_no:int; priority_class:str; prompt_tokens:int; max_output_tokens:int; memory_units:int; queue_age_seconds:int; admitted:bool; running:bool; cancelled:bool
@dataclass(frozen=True)
class TenantSchedulerState:
    tenant_id:str; configured_weight:int; deficit_before:int; service_units:int; deficit_after:int; active_requests:int; queued_requests:int; reserved_tokens:int; reserved_memory_units:int
@dataclass(frozen=True)
class SchedulerResourceEvidence:
    worker_pool_id:str; total_slots:int; active_slots:int; total_memory_units:int; used_memory_units:int
@dataclass(frozen=True)
class SchedulerBatchPlanEvidence:
    batch_id:str; scheduler_id:str; tenant_id:str; request_ids:tuple[str,...]; total_reserved_tokens:int; total_memory_units:int
@dataclass(frozen=True)
class InferenceSchedulerManifest:
    schema_version:str; manifest_id:str; created_at_epoch:int; p10a_assessment_sha256:str; upstream_request_id:str; upstream_tenant_id:str; upstream_session_id:str; scheduler_id:str; scheduling_epoch:int; requests:tuple[SchedulerRequestEvidence,...]; tenant_states:tuple[TenantSchedulerState,...]; resources:SchedulerResourceEvidence; selected_batch:SchedulerBatchPlanEvidence; prior_admitted_request_ids:tuple[str,...]; prior_admitted_ledger_sha256:str; network_operations:int=0
@dataclass(frozen=True)
class InferenceSchedulerPolicy:
    policy_version:str; expected_manifest_id:str; expected_manifest_sha256:str; expected_p10a_assessment_sha256:str; expected_upstream_request_id:str; expected_upstream_tenant_id:str; expected_upstream_session_id:str; allowed_scheduler_ids:tuple[str,...]; allowed_worker_pool_ids:tuple[str,...]; allowed_tenant_ids:tuple[str,...]; tenant_weights:Mapping[str,int]; max_concurrent_by_tenant:Mapping[str,int]; max_queue_depth_by_tenant:Mapping[str,int]; max_reserved_tokens_by_tenant:Mapping[str,int]; max_reserved_memory_by_tenant:Mapping[str,int]; allowed_priority_classes:tuple[str,...]; priority_rank:Mapping[str,int]; max_wait_seconds_by_priority:Mapping[str,int]; deficit_quantum:int; max_deficit_units:int; max_request_tokens:int; max_request_memory_units:int; max_global_slots:int; max_global_reserved_tokens:int; max_global_memory_units:int; max_batch_size:int; max_batch_reserved_tokens:int; max_batch_memory_units:int; expected_prior_admitted_ledger_sha256:str; max_manifest_age_seconds:int; max_future_skew_seconds:int
@dataclass(frozen=True)
class InferenceSchedulerRequest:
    manifest_id:str; manifest_sha256:str; evaluated_at_epoch:int; declared_scheduler_id:str; declared_batch_id:str; declared_selected_tenant_id:str; declared_admitted_request_ids:tuple[str,...]; declared_batch_request_ids:tuple[str,...]; declared_upstream_p10a_bound:bool; declared_admission_limits_safe:bool; declared_resource_isolation_safe:bool; declared_weighted_fairness_safe:bool; declared_starvation_bounds_safe:bool; declared_batch_plan_safe:bool; declared_scheduler_safe:bool
@dataclass(frozen=True)
class VerifiedInferenceSchedulerAssessment:
    manifest_id:str; scheduler_id:str; batch_id:str; selected_tenant_id:str; decision:SchedulerDecision; risks:tuple[SchedulerRisk,...]; p10a_assessment_sha256:str; admitted_request_ids:tuple[str,...]; batch_request_ids:tuple[str,...]; tenant_ids:tuple[str,...]; total_reserved_tokens:int; total_reserved_memory_units:int; upstream_p10a_bound:bool; scheduler_identity_verified:bool; admission_limits_verified:bool; tenant_resource_isolation_verified:bool; weighted_fairness_verified:bool; starvation_bounds_verified:bool; batch_plan_verified:bool; caller_declared_safety_trusted:bool; production_scheduler_integrated:bool; production_gpu_quota_enforced:bool; production_distributed_fairness_validated:bool; production_autoscaler_integrated:bool; side_channel_resistance_validated:bool; assessment_schema_version:str; assessment_mode:str; assessment_evidence_sha256:str

def admitted_ledger_digest(ids:tuple[str,...])->str: return digest_json({'admitted_request_ids':tuple(sorted(ids))})
def inference_scheduler_manifest_digest(m:InferenceSchedulerManifest)->str: return digest_json(m)
