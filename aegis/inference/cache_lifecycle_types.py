from __future__ import annotations
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib, json
from typing import Mapping

P10C_POLICY_VERSION='inference-cache-lifecycle-v1'
P10C_SCHEMA_VERSION='aegis-inference-cache-lifecycle-manifest-v1'
P10C_ASSESSMENT_SCHEMA_VERSION='aegis-inference-cache-lifecycle-assessment-v1'
P10C_ASSESSMENT_MODE='deterministic-evidence-bound-inference-cache-lifecycle-v1'

class CacheDecision(str,Enum): ALLOW='allow'; DENY='deny'
class CacheKind(str,Enum): KV='kv'; PREFIX='prefix'
class CacheState(str,Enum): ACTIVE='active'; EVICTED='evicted'; ZEROIZED='zeroized'
class CacheRisk(str,Enum):
    UPSTREAM_P10B_INVALID='upstream_p10b_invalid'
    UPSTREAM_BINDING_MISMATCH='upstream_binding_mismatch'
    CACHE_ENTRY_COVERAGE_MISMATCH='cache_entry_coverage_mismatch'
    CACHE_ENTRY_DIGEST_MISMATCH='cache_entry_digest_mismatch'
    CACHE_OWNER_MISMATCH='cache_owner_mismatch'
    CACHE_NAMESPACE_MISMATCH='cache_namespace_mismatch'
    CACHE_EPOCH_MISMATCH='cache_epoch_mismatch'
    CACHE_GENERATION_ROLLBACK='cache_generation_rollback'
    DUPLICATE_CACHE_ENTRY='duplicate_cache_entry'
    RETIRED_ENTRY_RESURRECTED='retired_entry_resurrected'
    CROSS_TENANT_REUSE='cross_tenant_reuse'
    CROSS_SESSION_KV_REUSE='cross_session_kv_reuse'
    PREFIX_REUSE_MISMATCH='prefix_reuse_mismatch'
    EVICTION_STATE_MISMATCH='eviction_state_mismatch'
    ZEROIZATION_MISSING='zeroization_missing'
    ZEROIZATION_RECEIPT_MISMATCH='zeroization_receipt_mismatch'
    ROLLBACK_UNAUTHORIZED='rollback_unauthorized'
    ROLLBACK_TARGET_MISMATCH='rollback_target_mismatch'
    CACHE_CAPACITY_EXCEEDED='cache_capacity_exceeded'
    STALE_ACTIVE_ENTRY='stale_active_entry'
    RETIRED_LEDGER_MISMATCH='retired_ledger_mismatch'
    NETWORK_OPERATION_UNEXPECTED='network_operation_unexpected'
class CacheRejectReason(str,Enum): POLICY_INVALID='policy_invalid'; MANIFEST_INVALID='manifest_invalid'; MANIFEST_DIGEST_MISMATCH='manifest_digest_mismatch'; REQUEST_INVALID='request_invalid'; DECLARED_SUMMARY_MISMATCH='declared_summary_mismatch'
class InferenceCacheLifecycleRejected(ValueError):
    def __init__(self,reason:CacheRejectReason,message:str): self.reason=reason; self.message=message; super().__init__(f'{reason.value}: {message}')
def reject(reason,message): raise InferenceCacheLifecycleRejected(reason,message)
def _jsonable(v):
    if isinstance(v,Enum): return v.value
    if is_dataclass(v): return {k:_jsonable(x) for k,x in asdict(v).items()}
    if isinstance(v,Mapping): return {str(k.value if isinstance(k,Enum) else k):_jsonable(x) for k,x in sorted(v.items(),key=lambda p:str(p[0]))}
    if isinstance(v,(tuple,list)): return [_jsonable(x) for x in v]
    return v
def digest_json(v): return hashlib.sha256(json.dumps(_jsonable(v),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

@dataclass(frozen=True)
class CacheEntryEvidence:
    entry_id:str; kind:CacheKind; tenant_id:str; session_id:str; namespace:str; epoch:int; generation:int; key_sha256:str; payload_sha256:str; state:CacheState; parent_entry_id:str; created_at_epoch:int; last_access_epoch:int; evicted_at_epoch:int; zeroized_at_epoch:int; zeroization_receipt_sha256:str
@dataclass(frozen=True)
class CacheReuseEvidence:
    operation_id:str; source_entry_id:str; target_entry_id:str; request_id:str; tenant_id:str; session_id:str; source_generation:int; target_generation:int; source_key_sha256:str; target_key_sha256:str
@dataclass(frozen=True)
class CacheRollbackEvidence:
    requested:bool; operation_id:str; tenant_id:str; session_id:str; namespace:str; current_generation:int; target_generation:int; target_entry_id:str; authorization_sha256:str
@dataclass(frozen=True)
class InferenceCacheLifecycleManifest:
    schema_version:str; manifest_id:str; created_at_epoch:int; p10b_assessment_sha256:str; upstream_scheduler_id:str; upstream_batch_id:str; cache_epoch:int; zeroization_method_sha256:str; entries:tuple[CacheEntryEvidence,...]; reuses:tuple[CacheReuseEvidence,...]; rollback:CacheRollbackEvidence; prior_retired_entry_ids:tuple[str,...]; prior_retired_ledger_sha256:str; network_operations:int=0
@dataclass(frozen=True)
class InferenceCacheLifecyclePolicy:
    policy_version:str; expected_manifest_id:str; expected_manifest_sha256:str; expected_p10b_assessment_sha256:str; expected_upstream_scheduler_id:str; expected_upstream_batch_id:str; allowed_tenant_ids:tuple[str,...]; expected_zeroization_method_sha256:str; expected_entry_ids:tuple[str,...]; expected_entry_key_sha256_by_id:Mapping[str,str]; expected_entry_payload_sha256_by_id:Mapping[str,str]; rollback_authorization_sha256_by_tenant:Mapping[str,str]; max_active_entries_by_tenant:Mapping[str,int]; min_generation_by_namespace:Mapping[str,int]; expected_prior_retired_ledger_sha256:str; max_active_entry_age_seconds:int; max_manifest_age_seconds:int; max_future_skew_seconds:int
@dataclass(frozen=True)
class InferenceCacheLifecycleRequest:
    manifest_id:str; manifest_sha256:str; evaluated_at_epoch:int; declared_scheduler_id:str; declared_batch_id:str; declared_cache_epoch:int; declared_active_entry_ids:tuple[str,...]; declared_zeroized_entry_ids:tuple[str,...]; declared_upstream_p10b_bound:bool; declared_ownership_safe:bool; declared_reuse_isolation_safe:bool; declared_eviction_safe:bool; declared_zeroization_safe:bool; declared_rollback_safe:bool; declared_cache_lifecycle_safe:bool
@dataclass(frozen=True)
class VerifiedInferenceCacheLifecycleAssessment:
    manifest_id:str; scheduler_id:str; batch_id:str; cache_epoch:int; decision:CacheDecision; risks:tuple[CacheRisk,...]; p10b_assessment_sha256:str; active_entry_ids:tuple[str,...]; zeroized_entry_ids:tuple[str,...]; retired_entry_ids:tuple[str,...]; upstream_p10b_bound:bool; ownership_verified:bool; reuse_isolation_verified:bool; eviction_verified:bool; zeroization_verified:bool; rollback_safety_verified:bool; caller_declared_safety_trusted:bool; production_cache_manager_integrated:bool; physical_memory_zeroization_verified:bool; distributed_cache_coherence_validated:bool; gpu_allocator_integrated:bool; side_channel_resistance_validated:bool; assessment_schema_version:str; assessment_mode:str; assessment_evidence_sha256:str

def retired_ledger_digest(ids:tuple[str,...])->str: return digest_json({'retired_entry_ids':tuple(sorted(ids))})
def inference_cache_lifecycle_manifest_digest(m:InferenceCacheLifecycleManifest)->str: return digest_json(m)
