from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P10H_POLICY_VERSION = "inference-replica-failover-routing-v1"
P10H_SCHEMA_VERSION = "aegis-inference-replica-failover-manifest-v1"
P10H_ASSESSMENT_SCHEMA_VERSION = "aegis-inference-replica-failover-assessment-v1"
P10H_ASSESSMENT_MODE = "deterministic-evidence-bound-replica-failover-routing-v1"


class ReplicaDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ReplicaState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    DRAINING = "draining"
    FAILED = "failed"


class ReplicaRisk(str, Enum):
    UPSTREAM_P10G_INVALID = "upstream_p10g_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    REQUEST_ROUTE_MISMATCH = "request_route_mismatch"
    ROUTER_IDENTITY_MISMATCH = "router_identity_mismatch"
    ROUTER_GENERATION_ROLLBACK = "router_generation_rollback"
    REPLICA_COVERAGE_MISMATCH = "replica_coverage_mismatch"
    REPLICA_IDENTITY_MISMATCH = "replica_identity_mismatch"
    REPLICA_ROUTE_MISMATCH = "replica_route_mismatch"
    REPLICA_HEALTH_UNSAFE = "replica_health_unsafe"
    REPLICA_CAPACITY_EXCEEDED = "replica_capacity_exceeded"
    REPLICA_HEARTBEAT_STALE = "replica_heartbeat_stale"
    READY_QUORUM_INSUFFICIENT = "ready_quorum_insufficient"
    ENDPOINT_ALIAS = "endpoint_alias"
    PROCESS_ALIAS = "process_alias"
    LINEAGE_MISMATCH = "lineage_mismatch"
    STALE_REPLICA_NOT_FENCED = "stale_replica_not_fenced"
    ROUTING_COVERAGE_MISMATCH = "routing_coverage_mismatch"
    ROUTING_SEQUENCE_MISMATCH = "routing_sequence_mismatch"
    ROUTING_CHAIN_MISMATCH = "routing_chain_mismatch"
    ROUTING_TO_UNSAFE_REPLICA = "routing_to_unsafe_replica"
    ROUTING_GENERATION_MISMATCH = "routing_generation_mismatch"
    IDEMPOTENCY_BINDING_MISMATCH = "idempotency_binding_mismatch"
    REQUEST_REPLAY = "request_replay"
    PRIOR_REQUEST_LEDGER_MISMATCH = "prior_request_ledger_mismatch"
    SCALE_COVERAGE_MISMATCH = "scale_coverage_mismatch"
    SCALE_SEQUENCE_MISMATCH = "scale_sequence_mismatch"
    SCALE_CHAIN_MISMATCH = "scale_chain_mismatch"
    SCALE_AUTHORIZATION_MISMATCH = "scale_authorization_mismatch"
    SCALE_BOUNDS_UNSAFE = "scale_bounds_unsafe"
    FAILOVER_COVERAGE_MISMATCH = "failover_coverage_mismatch"
    FAILOVER_BINDING_MISMATCH = "failover_binding_mismatch"
    FAILOVER_FENCE_MISSING = "failover_fence_missing"
    FAILOVER_GENERATION_MISMATCH = "failover_generation_mismatch"
    FAILOVER_AUTHORIZATION_MISMATCH = "failover_authorization_mismatch"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class ReplicaRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class InferenceReplicaRoutingRejected(ValueError):
    def __init__(self, reason: ReplicaRejectReason, message: str):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason.value}: {message}")


def reject(reason: ReplicaRejectReason, message: str) -> None:
    raise InferenceReplicaRoutingRejected(reason, message)


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


def digest_json(value) -> str:
    return hashlib.sha256(
        json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ReplicaEvidence:
    replica_id: str
    process_id: str
    endpoint_id: str
    instance_generation: int
    route_generation: int
    state: ReplicaState
    healthy: bool
    accepting_requests: bool
    fenced: bool
    inflight_requests: int
    capacity_requests: int
    started_at_epoch: int
    heartbeat_epoch: int
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    config_sha256: str
    predecessor_replica_id: str
    predecessor_lineage_sha256: str


@dataclass(frozen=True)
class RoutingDecisionEvidence:
    routing_id: str
    sequence_no: int
    router_generation: int
    selected_replica_id: str
    selected_instance_generation: int
    request_id: str
    tenant_id: str
    session_id: str
    stream_id: str
    idempotency_key_sha256: str
    reason_code: str
    previous_routing_sha256: str


@dataclass(frozen=True)
class ScaleEventEvidence:
    scale_event_id: str
    sequence_no: int
    from_desired_replicas: int
    to_desired_replicas: int
    observed_ready_replicas: int
    reason_code: str
    authorization_sha256: str
    previous_scale_event_sha256: str


@dataclass(frozen=True)
class FailoverEvidence:
    failover_id: str
    failed_replica_id: str
    successor_replica_id: str
    failed_instance_generation: int
    successor_instance_generation: int
    failure_epoch: int
    fence_epoch: int
    prior_router_generation: int
    new_router_generation: int
    authorization_sha256: str


@dataclass(frozen=True)
class InferenceReplicaRoutingManifest:
    schema_version: str
    manifest_id: str
    created_at_epoch: int
    p10g_assessment_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    stream_id: str
    output_channel_id: str
    frame_ids: tuple[str, ...]
    router_id: str
    router_generation: int
    replicas: tuple[ReplicaEvidence, ...]
    routing_decisions: tuple[RoutingDecisionEvidence, ...]
    scale_events: tuple[ScaleEventEvidence, ...]
    failovers: tuple[FailoverEvidence, ...]
    prior_request_keys_sha256: tuple[str, ...]
    prior_request_ledger_sha256: str
    network_operations: int = 0


@dataclass(frozen=True)
class InferenceReplicaRoutingPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_p10g_assessment_sha256: str
    expected_request_id: str
    expected_tenant_id: str
    expected_session_id: str
    expected_target_model_id: str
    expected_target_model_revision: str
    expected_adapter_ids: tuple[str, ...]
    expected_adapter_generation: int
    expected_partition_ids: tuple[str, ...]
    expected_stream_id: str
    expected_output_channel_id: str
    expected_frame_ids: tuple[str, ...]
    expected_router_id: str
    expected_router_generation: int
    minimum_router_generation: int
    expected_replica_ids: tuple[str, ...]
    expected_instance_generation_by_replica: Mapping[str, int]
    expected_route_generation_by_replica: Mapping[str, int]
    expected_config_sha256_by_replica: Mapping[str, str]
    expected_replica_identity_sha256_by_replica: Mapping[str, str]
    expected_predecessor_by_replica: Mapping[str, str]
    expected_predecessor_lineage_sha256_by_replica: Mapping[str, str]
    expected_routing_ids: tuple[str, ...]
    allowed_routing_reason_codes: tuple[str, ...]
    expected_scale_event_ids: tuple[str, ...]
    expected_failover_ids: tuple[str, ...]
    min_ready_replicas: int
    max_replicas: int
    max_inflight_per_replica: int
    max_heartbeat_age_seconds: int
    expected_prior_request_ledger_sha256: str
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class InferenceReplicaRoutingRequest:
    manifest_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_request_id: str
    declared_tenant_id: str
    declared_session_id: str
    declared_router_id: str
    declared_router_generation: int
    declared_replica_ids: tuple[str, ...]
    declared_routing_ids: tuple[str, ...]
    declared_upstream_p10g_bound: bool
    declared_replica_identity_safe: bool
    declared_health_capacity_safe: bool
    declared_routing_generation_safe: bool
    declared_autoscaling_safe: bool
    declared_failover_fencing_safe: bool
    declared_replay_safe: bool
    declared_lineage_safe: bool
    declared_replica_routing_safe: bool


@dataclass(frozen=True)
class VerifiedInferenceReplicaRoutingAssessment:
    manifest_id: str
    manifest_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    decision: ReplicaDecision
    risks: tuple[ReplicaRisk, ...]
    p10g_assessment_sha256: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    stream_id: str
    router_id: str
    router_generation: int
    replica_ids: tuple[str, ...]
    routing_ids: tuple[str, ...]
    upstream_p10g_bound: bool
    replica_identity_verified: bool
    health_and_capacity_verified: bool
    routing_generation_verified: bool
    autoscaling_verified: bool
    failover_fencing_verified: bool
    idempotency_replay_verified: bool
    lineage_verified: bool
    caller_declared_safety_trusted: bool
    production_service_mesh_integrated: bool
    production_orchestrator_integrated: bool
    distributed_consensus_validated: bool
    cross_zone_failover_validated: bool
    load_balancer_stickiness_validated: bool
    production_autoscaler_validated: bool
    network_partition_resistance_validated: bool
    exactly_once_delivery_validated: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def replica_identity_digest(replica: ReplicaEvidence) -> str:
    return digest_json({
        "replica_id": replica.replica_id,
        "process_id": replica.process_id,
        "endpoint_id": replica.endpoint_id,
        "instance_generation": replica.instance_generation,
        "route_generation": replica.route_generation,
        "target_model_id": replica.target_model_id,
        "target_model_revision": replica.target_model_revision,
        "adapter_ids": replica.adapter_ids,
        "adapter_generation": replica.adapter_generation,
        "partition_ids": replica.partition_ids,
        "config_sha256": replica.config_sha256,
    })


def replica_lineage_digest(replica: ReplicaEvidence) -> str:
    return digest_json({
        "replica_id": replica.replica_id,
        "instance_generation": replica.instance_generation,
        "config_sha256": replica.config_sha256,
        "predecessor_replica_id": replica.predecessor_replica_id,
        "predecessor_lineage_sha256": replica.predecessor_lineage_sha256,
    })


def routing_decision_digest(event: RoutingDecisionEvidence) -> str:
    return digest_json(event)


def scale_event_digest(event: ScaleEventEvidence) -> str:
    return digest_json(event)


def request_idempotency_digest(request_id: str, tenant_id: str, session_id: str, stream_id: str) -> str:
    return digest_json({
        "request_id": request_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "stream_id": stream_id,
    })


def prior_request_ledger_digest(keys: tuple[str, ...]) -> str:
    return digest_json({"prior_request_keys_sha256": tuple(sorted(x.casefold() for x in keys))})


def scale_authorization_digest(router_id: str, from_desired: int, to_desired: int, reason_code: str) -> str:
    return digest_json({
        "router_id": router_id,
        "from_desired_replicas": from_desired,
        "to_desired_replicas": to_desired,
        "reason_code": reason_code,
    })


def failover_authorization_digest(
    router_id: str,
    failed_replica_id: str,
    successor_replica_id: str,
    new_router_generation: int,
) -> str:
    return digest_json({
        "router_id": router_id,
        "failed_replica_id": failed_replica_id,
        "successor_replica_id": successor_replica_id,
        "new_router_generation": new_router_generation,
    })


def inference_replica_routing_manifest_digest(manifest: InferenceReplicaRoutingManifest) -> str:
    return digest_json(manifest)
