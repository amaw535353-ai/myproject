from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P10A_POLICY_VERSION = "inference-tenant-state-isolation-v1"
P10A_SCHEMA_VERSION = "aegis-inference-tenant-state-isolation-manifest-v1"
P10A_ASSESSMENT_SCHEMA_VERSION = "aegis-inference-tenant-state-isolation-assessment-v1"
P10A_ASSESSMENT_MODE = "deterministic-evidence-bound-inference-tenant-state-isolation-v1"


class InferenceDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class InferenceRisk(str, Enum):
    UPSTREAM_DEPLOYMENT_BINDING_MISMATCH = "upstream_deployment_binding_mismatch"
    UPSTREAM_PROMOTION_BINDING_MISMATCH = "upstream_promotion_binding_mismatch"
    ROUTE_IDENTITY_MISMATCH = "route_identity_mismatch"
    MUTABLE_ROUTE_UNSAFE = "mutable_route_unsafe"
    REQUEST_IDENTITY_MISMATCH = "request_identity_mismatch"
    TENANT_SESSION_BINDING_MISMATCH = "tenant_session_binding_mismatch"
    AUTHORIZATION_CONTEXT_MISMATCH = "authorization_context_mismatch"
    BATCH_ISOLATION_MISMATCH = "batch_isolation_mismatch"
    CROSS_TENANT_BATCH = "cross_tenant_batch"
    KV_CACHE_BINDING_MISMATCH = "kv_cache_binding_mismatch"
    PREFIX_CACHE_BINDING_MISMATCH = "prefix_cache_binding_mismatch"
    CROSS_TENANT_CACHE_REUSE = "cross_tenant_cache_reuse"
    ADAPTER_ROUTE_MISMATCH = "adapter_route_mismatch"
    DRAFT_MODEL_ROUTE_MISMATCH = "draft_model_route_mismatch"
    OUTPUT_BINDING_MISMATCH = "output_binding_mismatch"
    REQUEST_REPLAY = "request_replay"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class InferenceRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class InferenceTenantIsolationRejected(ValueError):
    def __init__(self, reason: InferenceRejectReason, message: str):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason.value}: {message}")


def reject(reason: InferenceRejectReason, message: str) -> None:
    raise InferenceTenantIsolationRejected(reason, message)


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(key.value if isinstance(key, Enum) else key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json_bytes(value) -> bytes:
    return json.dumps(
        _jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest_json(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class InferenceRouteEvidence:
    deployment_id: str
    endpoint_id: str
    model_id: str
    revision: str
    model_artifact_sha256: str
    tokenizer_sha256: str
    adapter_id: str
    adapter_sha256: str
    draft_model_id: str
    draft_revision: str
    draft_model_artifact_sha256: str


@dataclass(frozen=True)
class InferenceRequestIdentityEvidence:
    request_id: str
    tenant_id: str
    principal_id: str
    session_id: str
    conversation_id: str
    sequence_no: int
    session_epoch: int
    nonce_sha256: str
    authorization_context_sha256: str


@dataclass(frozen=True)
class InferenceBatchIsolationEvidence:
    batch_id: str
    scheduler_id: str
    partition_key: str
    request_ids: tuple[str, ...]
    tenant_ids: tuple[str, ...]
    mixed_tenant_batch: bool


@dataclass(frozen=True)
class InferenceCacheBindingEvidence:
    kv_cache_namespace: str
    kv_cache_owner_tenant_id: str
    kv_cache_session_id: str
    kv_cache_epoch: int
    prefix_cache_enabled: bool
    prefix_cache_namespace: str
    prefix_cache_owner_tenant_id: str
    prefix_cache_key_sha256: str
    allow_cross_tenant_reuse: bool


@dataclass(frozen=True)
class InferenceOutputBindingEvidence:
    output_channel_id: str
    recipient_tenant_id: str
    recipient_session_id: str
    response_object_id: str


@dataclass(frozen=True)
class InferenceTenantIsolationManifest:
    schema_version: str
    manifest_id: str
    created_at_epoch: int
    deployment_attestation_id: str
    deployment_attestation_sha256: str
    p9h_promotion_assessment_sha256: str
    route: InferenceRouteEvidence
    request_identity: InferenceRequestIdentityEvidence
    batch: InferenceBatchIsolationEvidence
    cache: InferenceCacheBindingEvidence
    output: InferenceOutputBindingEvidence
    prior_request_ids: tuple[str, ...]
    prior_request_ledger_sha256: str
    network_operations: int = 0


@dataclass(frozen=True)
class InferenceTenantIsolationPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_deployment_attestation_id: str
    expected_deployment_attestation_sha256: str
    expected_p9h_promotion_assessment_sha256: str
    expected_deployment_id: str
    expected_endpoint_id: str
    expected_model_id: str
    expected_revision: str
    expected_model_artifact_sha256: str
    expected_tokenizer_sha256: str
    expected_adapter_id: str
    expected_adapter_sha256: str
    expected_draft_model_id: str
    expected_draft_revision: str
    expected_draft_model_artifact_sha256: str
    allowed_tenant_ids: tuple[str, ...]
    allowed_principal_ids_by_tenant: Mapping[str, tuple[str, ...]]
    allowed_scheduler_ids: tuple[str, ...]
    expected_authorization_context_sha256_by_tenant: Mapping[str, str]
    expected_prior_request_ledger_sha256: str
    max_sequence_no: int
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class InferenceTenantIsolationRequest:
    manifest_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_request_id: str
    declared_tenant_id: str
    declared_principal_id: str
    declared_session_id: str
    declared_model_id: str
    declared_revision: str
    declared_batch_id: str
    declared_kv_cache_namespace: str
    declared_output_channel_id: str
    declared_upstream_bound: bool
    declared_route_bound: bool
    declared_request_identity_bound: bool
    declared_batch_isolated: bool
    declared_cache_isolated: bool
    declared_output_isolated: bool
    declared_request_fresh: bool
    declared_isolation_safe: bool


@dataclass(frozen=True)
class VerifiedInferenceTenantIsolationAssessment:
    manifest_id: str
    request_id: str
    tenant_id: str
    principal_id: str
    session_id: str
    deployment_id: str
    endpoint_id: str
    model_id: str
    revision: str
    adapter_id: str
    batch_id: str
    decision: InferenceDecision
    risks: tuple[InferenceRisk, ...]
    deployment_attestation_sha256: str
    p9h_promotion_assessment_sha256: str
    upstream_deployment_bound: bool
    upstream_promotion_bound: bool
    route_identity_verified: bool
    request_identity_verified: bool
    batch_isolation_verified: bool
    kv_and_prefix_cache_isolation_verified: bool
    output_binding_verified: bool
    request_replay_clear: bool
    caller_declared_safety_trusted: bool
    production_inference_gateway_integrated: bool
    production_scheduler_isolation_enforced: bool
    production_kv_cache_memory_isolation_verified: bool
    side_channel_resistance_validated: bool
    hardware_attestation_verified: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def prior_request_ledger_digest(prior_request_ids: tuple[str, ...]) -> str:
    return digest_json({"prior_request_ids": tuple(sorted(prior_request_ids))})


def inference_tenant_isolation_manifest_digest(
    manifest: InferenceTenantIsolationManifest,
) -> str:
    return digest_json(manifest)
