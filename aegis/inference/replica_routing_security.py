from __future__ import annotations

import re

from .streaming_security_types import (
    P10G_ASSESSMENT_MODE,
    P10G_ASSESSMENT_SCHEMA_VERSION,
    StreamDecision,
    VerifiedInferenceStreamingSecurityAssessment,
)
from .replica_routing_types import *

_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9._:/@+-]{1,127}$")


class InferenceReplicaRoutingAnalyzer:
    def __init__(self, policy: InferenceReplicaRoutingPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA.fullmatch(str(value)))

    @staticmethod
    def _id(value: str) -> bool:
        return bool(_ID.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P10H_POLICY_VERSION:
            reject(ReplicaRejectReason.POLICY_INVALID, "unexpected policy version")
        ids = (
            p.expected_manifest_id,
            p.expected_request_id,
            p.expected_tenant_id,
            p.expected_session_id,
            p.expected_target_model_id,
            p.expected_target_model_revision,
            p.expected_stream_id,
            p.expected_output_channel_id,
            p.expected_router_id,
        )
        if not all(map(self._id, ids)) or not p.expected_session_id.startswith(
            f"tenant/{p.expected_tenant_id}/session/"
        ):
            reject(ReplicaRejectReason.POLICY_INVALID, "policy identity pins invalid")
        if not all(
            map(
                self._sha,
                (
                    p.expected_manifest_sha256,
                    p.expected_p10g_assessment_sha256,
                    p.expected_prior_request_ledger_sha256,
                ),
            )
        ):
            reject(ReplicaRejectReason.POLICY_INVALID, "policy digest pins invalid")
        replicas = set(p.expected_replica_ids)
        maps = (
            p.expected_instance_generation_by_replica,
            p.expected_route_generation_by_replica,
            p.expected_config_sha256_by_replica,
            p.expected_replica_identity_sha256_by_replica,
            p.expected_predecessor_by_replica,
            p.expected_predecessor_lineage_sha256_by_replica,
        )
        if not replicas or len(replicas) != len(p.expected_replica_ids) or any(set(m) != replicas for m in maps):
            reject(ReplicaRejectReason.POLICY_INVALID, "replica policy coverage invalid")
        if not all(map(self._id, p.expected_replica_ids)):
            reject(ReplicaRejectReason.POLICY_INVALID, "replica ids malformed")
        if any(not self._sha(x) for x in p.expected_config_sha256_by_replica.values()):
            reject(ReplicaRejectReason.POLICY_INVALID, "replica config digest malformed")
        if any(not self._sha(x) for x in p.expected_replica_identity_sha256_by_replica.values()):
            reject(ReplicaRejectReason.POLICY_INVALID, "replica identity digest malformed")
        for rid in p.expected_replica_ids:
            pred = p.expected_predecessor_by_replica[rid]
            pred_sha = p.expected_predecessor_lineage_sha256_by_replica[rid]
            if pred and not self._id(pred):
                reject(ReplicaRejectReason.POLICY_INVALID, "predecessor id malformed")
            if pred_sha and not self._sha(pred_sha):
                reject(ReplicaRejectReason.POLICY_INVALID, "predecessor lineage digest malformed")
            if p.expected_instance_generation_by_replica[rid] < 0 or p.expected_route_generation_by_replica[rid] < 0:
                reject(ReplicaRejectReason.POLICY_INVALID, "replica generation invalid")
        for values, label in (
            (p.expected_routing_ids, "routing"),
            (p.expected_scale_event_ids, "scale"),
            (p.expected_failover_ids, "failover"),
        ):
            if len(values) != len(set(values)) or any(not self._id(v) for v in values):
                reject(ReplicaRejectReason.POLICY_INVALID, f"{label} ids malformed")
        if not p.expected_routing_ids or not p.expected_failover_ids:
            reject(ReplicaRejectReason.POLICY_INVALID, "routing/failover coverage empty")
        if not p.allowed_routing_reason_codes or len(set(p.allowed_routing_reason_codes)) != len(p.allowed_routing_reason_codes) or not all(map(self._id, p.allowed_routing_reason_codes)):
            reject(ReplicaRejectReason.POLICY_INVALID, "routing reason allowlist invalid")
        if p.expected_router_generation < p.minimum_router_generation or p.minimum_router_generation < 0:
            reject(ReplicaRejectReason.POLICY_INVALID, "router generation floor invalid")
        bounds = (
            p.min_ready_replicas,
            p.max_replicas,
            p.max_inflight_per_replica,
            p.max_heartbeat_age_seconds,
            p.max_manifest_age_seconds,
            p.max_future_skew_seconds,
        )
        if min(bounds) < 0 or min(p.min_ready_replicas, p.max_replicas, p.max_inflight_per_replica) <= 0:
            reject(ReplicaRejectReason.POLICY_INVALID, "policy bounds invalid")
        if p.min_ready_replicas > p.max_replicas or len(p.expected_replica_ids) > p.max_replicas:
            reject(ReplicaRejectReason.POLICY_INVALID, "replica bounds inconsistent")

    def _validate_manifest(self, m: InferenceReplicaRoutingManifest) -> None:
        if (
            m.schema_version != P10H_SCHEMA_VERSION
            or m.manifest_id != self.policy.expected_manifest_id
            or not self._id(m.manifest_id)
            or m.created_at_epoch <= 0
            or not self._sha(m.p10g_assessment_sha256)
        ):
            reject(ReplicaRejectReason.MANIFEST_INVALID, "manifest identity/schema/time invalid")
        ids = (
            m.request_id,
            m.tenant_id,
            m.session_id,
            m.target_model_id,
            m.target_model_revision,
            m.stream_id,
            m.output_channel_id,
            m.router_id,
        )
        if not all(map(self._id, ids)) or not m.session_id.startswith(f"tenant/{m.tenant_id}/session/"):
            reject(ReplicaRejectReason.MANIFEST_INVALID, "manifest route identifiers invalid")
        if m.adapter_generation < 0 or m.router_generation < 0 or m.network_operations < 0:
            reject(ReplicaRejectReason.MANIFEST_INVALID, "manifest generation/network invalid")
        if (
            not m.replicas
            or len({x.replica_id for x in m.replicas}) != len(m.replicas)
            or not m.routing_decisions
        ):
            reject(ReplicaRejectReason.MANIFEST_INVALID, "replica/routing evidence missing or duplicated")
        for r in m.replicas:
            if not all(map(self._id, (r.replica_id, r.process_id, r.endpoint_id))):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "replica identity malformed")
            if min(
                r.instance_generation,
                r.route_generation,
                r.inflight_requests,
                r.capacity_requests,
                r.started_at_epoch,
                r.heartbeat_epoch,
                r.adapter_generation,
            ) < 0 or r.capacity_requests <= 0:
                reject(ReplicaRejectReason.MANIFEST_INVALID, "replica numeric evidence invalid")
            if not self._sha(r.config_sha256):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "replica config digest malformed")
            if r.predecessor_replica_id and not self._id(r.predecessor_replica_id):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "replica predecessor malformed")
            if r.predecessor_lineage_sha256 and not self._sha(r.predecessor_lineage_sha256):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "replica predecessor digest malformed")
        for e in m.routing_decisions:
            if not all(map(self._id, (
                e.routing_id,
                e.selected_replica_id,
                e.request_id,
                e.tenant_id,
                e.session_id,
                e.stream_id,
                e.reason_code,
            ))):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "routing identity malformed")
            if e.sequence_no <= 0 or min(e.router_generation, e.selected_instance_generation) < 0:
                reject(ReplicaRejectReason.MANIFEST_INVALID, "routing generation malformed")
            if not all(map(self._sha, (e.idempotency_key_sha256, e.previous_routing_sha256))):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "routing digest malformed")
        if len({e.routing_id for e in m.routing_decisions}) != len(m.routing_decisions):
            reject(ReplicaRejectReason.MANIFEST_INVALID, "routing ids duplicated")
        for e in m.scale_events:
            if not all(map(self._id, (e.scale_event_id, e.reason_code))) or e.sequence_no <= 0:
                reject(ReplicaRejectReason.MANIFEST_INVALID, "scale identity malformed")
            if min(e.from_desired_replicas, e.to_desired_replicas, e.observed_ready_replicas) < 0:
                reject(ReplicaRejectReason.MANIFEST_INVALID, "scale counts invalid")
            if not all(map(self._sha, (e.authorization_sha256, e.previous_scale_event_sha256))):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "scale digest malformed")
        if len({e.scale_event_id for e in m.scale_events}) != len(m.scale_events):
            reject(ReplicaRejectReason.MANIFEST_INVALID, "scale ids duplicated")
        for e in m.failovers:
            if not all(map(self._id, (e.failover_id, e.failed_replica_id, e.successor_replica_id))):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "failover identity malformed")
            if min(
                e.failed_instance_generation,
                e.successor_instance_generation,
                e.failure_epoch,
                e.fence_epoch,
                e.prior_router_generation,
                e.new_router_generation,
            ) < 0 or not self._sha(e.authorization_sha256):
                reject(ReplicaRejectReason.MANIFEST_INVALID, "failover evidence malformed")
        if len({e.failover_id for e in m.failovers}) != len(m.failovers):
            reject(ReplicaRejectReason.MANIFEST_INVALID, "failover ids duplicated")
        if (
            len(m.prior_request_keys_sha256) != len(set(x.casefold() for x in m.prior_request_keys_sha256))
            or any(not self._sha(x) for x in m.prior_request_keys_sha256)
            or not self._sha(m.prior_request_ledger_sha256)
        ):
            reject(ReplicaRejectReason.MANIFEST_INVALID, "prior request ledger malformed")

    @staticmethod
    def _upstream_ok(a: VerifiedInferenceStreamingSecurityAssessment) -> bool:
        flags = (
            a.upstream_p10f_bound,
            a.output_channel_verified,
            a.frame_integrity_verified,
            a.backpressure_verified,
            a.cancellation_verified,
            a.tool_framing_verified,
            a.replay_verified,
        )
        nonclaims = (
            a.caller_declared_safety_trusted,
            a.production_streaming_gateway_integrated,
            a.kernel_tcp_backpressure_validated,
            a.distributed_cancellation_linearizability_validated,
            a.production_tool_dispatch_integrated,
            a.semantic_output_safety_validated,
            a.remote_client_disconnect_semantics_validated,
        )
        return (
            a.decision == StreamDecision.ALLOW
            and not a.risks
            and all(flags)
            and not any(nonclaims)
            and a.assessment_schema_version == P10G_ASSESSMENT_SCHEMA_VERSION
            and a.assessment_mode == P10G_ASSESSMENT_MODE
        )

    def derive(
        self,
        m: InferenceReplicaRoutingManifest,
        a: VerifiedInferenceStreamingSecurityAssessment,
    ) -> tuple[ReplicaRisk, ...]:
        self._validate_manifest(m)
        p = self.policy
        risks: set[ReplicaRisk] = set()
        replicas = {r.replica_id: r for r in m.replicas}

        if not self._upstream_ok(a):
            risks.add(ReplicaRisk.UPSTREAM_P10G_INVALID)
        if (
            m.p10g_assessment_sha256.casefold() != p.expected_p10g_assessment_sha256.casefold()
            or a.assessment_evidence_sha256.casefold() != p.expected_p10g_assessment_sha256.casefold()
        ):
            risks.add(ReplicaRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            (m.request_id, m.tenant_id, m.session_id)
            != (p.expected_request_id, p.expected_tenant_id, p.expected_session_id)
            or (a.request_id, a.tenant_id, a.session_id)
            != (m.request_id, m.tenant_id, m.session_id)
            or (m.target_model_id, m.target_model_revision)
            != (p.expected_target_model_id, p.expected_target_model_revision)
            or (a.target_model_id, a.target_model_revision)
            != (m.target_model_id, m.target_model_revision)
            or m.adapter_ids != p.expected_adapter_ids
            or a.adapter_ids != m.adapter_ids
            or m.adapter_generation != p.expected_adapter_generation
            or a.adapter_generation != m.adapter_generation
            or m.partition_ids != p.expected_partition_ids
            or a.partition_ids != m.partition_ids
            or m.stream_id != p.expected_stream_id
            or a.stream_id != m.stream_id
            or m.output_channel_id != p.expected_output_channel_id
            or a.output_channel_id != m.output_channel_id
            or m.frame_ids != p.expected_frame_ids
            or a.frame_ids != m.frame_ids
        ):
            risks.add(ReplicaRisk.REQUEST_ROUTE_MISMATCH)
        if m.router_id != p.expected_router_id:
            risks.add(ReplicaRisk.ROUTER_IDENTITY_MISMATCH)
        if m.router_generation != p.expected_router_generation:
            risks.add(ReplicaRisk.ROUTER_IDENTITY_MISMATCH)
        if m.router_generation < p.minimum_router_generation:
            risks.add(ReplicaRisk.ROUTER_GENERATION_ROLLBACK)

        if tuple(r.replica_id for r in m.replicas) != p.expected_replica_ids or set(replicas) != set(p.expected_replica_ids):
            risks.add(ReplicaRisk.REPLICA_COVERAGE_MISMATCH)
        endpoints = [r.endpoint_id for r in m.replicas]
        processes = [r.process_id for r in m.replicas]
        if len(endpoints) != len(set(endpoints)):
            risks.add(ReplicaRisk.ENDPOINT_ALIAS)
        if len(processes) != len(set(processes)):
            risks.add(ReplicaRisk.PROCESS_ALIAS)

        ready = 0
        for r in m.replicas:
            if (
                r.instance_generation != p.expected_instance_generation_by_replica.get(r.replica_id)
                or r.route_generation != p.expected_route_generation_by_replica.get(r.replica_id)
                or r.config_sha256.casefold()
                != p.expected_config_sha256_by_replica.get(r.replica_id, "").casefold()
                or replica_identity_digest(r).casefold()
                != p.expected_replica_identity_sha256_by_replica.get(r.replica_id, "").casefold()
            ):
                risks.add(ReplicaRisk.REPLICA_IDENTITY_MISMATCH)
            if (
                r.target_model_id != m.target_model_id
                or r.target_model_revision != m.target_model_revision
                or r.adapter_ids != m.adapter_ids
                or r.adapter_generation != m.adapter_generation
                or r.partition_ids != m.partition_ids
            ):
                risks.add(ReplicaRisk.REPLICA_ROUTE_MISMATCH)
            if r.state == ReplicaState.READY:
                ready += 1
                if not r.healthy or not r.accepting_requests or r.fenced:
                    risks.add(ReplicaRisk.REPLICA_HEALTH_UNSAFE)
                if r.route_generation != m.router_generation:
                    risks.add(ReplicaRisk.ROUTING_GENERATION_MISMATCH)
            elif r.state == ReplicaState.FAILED:
                if r.healthy or r.accepting_requests or not r.fenced:
                    risks.add(ReplicaRisk.STALE_REPLICA_NOT_FENCED)
            elif r.accepting_requests and r.fenced:
                risks.add(ReplicaRisk.REPLICA_HEALTH_UNSAFE)
            if r.inflight_requests > r.capacity_requests or r.inflight_requests > p.max_inflight_per_replica:
                risks.add(ReplicaRisk.REPLICA_CAPACITY_EXCEEDED)
            if m.created_at_epoch - r.heartbeat_epoch > p.max_heartbeat_age_seconds or r.heartbeat_epoch > m.created_at_epoch + p.max_future_skew_seconds:
                risks.add(ReplicaRisk.REPLICA_HEARTBEAT_STALE)
            pred = p.expected_predecessor_by_replica.get(r.replica_id, "")
            pred_sha = p.expected_predecessor_lineage_sha256_by_replica.get(r.replica_id, "")
            if r.predecessor_replica_id != pred or r.predecessor_lineage_sha256.casefold() != pred_sha.casefold():
                risks.add(ReplicaRisk.LINEAGE_MISMATCH)
            if r.predecessor_replica_id:
                predecessor = replicas.get(r.predecessor_replica_id)
                if (
                    predecessor is None
                    or r.predecessor_lineage_sha256.casefold() != replica_lineage_digest(predecessor).casefold()
                    or r.instance_generation <= predecessor.instance_generation
                ):
                    risks.add(ReplicaRisk.LINEAGE_MISMATCH)
        if ready < p.min_ready_replicas:
            risks.add(ReplicaRisk.READY_QUORUM_INSUFFICIENT)

        if tuple(e.routing_id for e in m.routing_decisions) != p.expected_routing_ids:
            risks.add(ReplicaRisk.ROUTING_COVERAGE_MISMATCH)
        previous = m.prior_request_ledger_sha256
        expected_key = request_idempotency_digest(m.request_id, m.tenant_id, m.session_id, m.stream_id)
        for seq, e in enumerate(m.routing_decisions, 1):
            if e.sequence_no != seq:
                risks.add(ReplicaRisk.ROUTING_SEQUENCE_MISMATCH)
            if e.previous_routing_sha256.casefold() != previous.casefold():
                risks.add(ReplicaRisk.ROUTING_CHAIN_MISMATCH)
            if (
                (e.request_id, e.tenant_id, e.session_id, e.stream_id)
                != (m.request_id, m.tenant_id, m.session_id, m.stream_id)
                or e.idempotency_key_sha256.casefold() != expected_key.casefold()
            ):
                risks.add(ReplicaRisk.IDEMPOTENCY_BINDING_MISMATCH)
            selected = replicas.get(e.selected_replica_id)
            if (
                selected is None
                or selected.state != ReplicaState.READY
                or not selected.healthy
                or not selected.accepting_requests
                or selected.fenced
                or e.selected_instance_generation != selected.instance_generation
            ):
                risks.add(ReplicaRisk.ROUTING_TO_UNSAFE_REPLICA)
            if e.router_generation != m.router_generation:
                risks.add(ReplicaRisk.ROUTING_GENERATION_MISMATCH)
            if e.reason_code not in p.allowed_routing_reason_codes:
                risks.add(ReplicaRisk.ROUTING_TO_UNSAFE_REPLICA)
            previous = routing_decision_digest(e)

        ledger = prior_request_ledger_digest(m.prior_request_keys_sha256)
        if (
            ledger.casefold() != m.prior_request_ledger_sha256.casefold()
            or ledger.casefold() != p.expected_prior_request_ledger_sha256.casefold()
        ):
            risks.add(ReplicaRisk.PRIOR_REQUEST_LEDGER_MISMATCH)
        if expected_key.casefold() in {x.casefold() for x in m.prior_request_keys_sha256}:
            risks.add(ReplicaRisk.REQUEST_REPLAY)

        if tuple(e.scale_event_id for e in m.scale_events) != p.expected_scale_event_ids:
            risks.add(ReplicaRisk.SCALE_COVERAGE_MISMATCH)
        scale_previous = m.prior_request_ledger_sha256
        for seq, e in enumerate(m.scale_events, 1):
            if e.sequence_no != seq:
                risks.add(ReplicaRisk.SCALE_SEQUENCE_MISMATCH)
            if e.previous_scale_event_sha256.casefold() != scale_previous.casefold():
                risks.add(ReplicaRisk.SCALE_CHAIN_MISMATCH)
            auth = scale_authorization_digest(
                m.router_id, e.from_desired_replicas, e.to_desired_replicas, e.reason_code
            )
            if e.authorization_sha256.casefold() != auth.casefold():
                risks.add(ReplicaRisk.SCALE_AUTHORIZATION_MISMATCH)
            if (
                e.from_desired_replicas <= 0
                or e.to_desired_replicas <= 0
                or e.to_desired_replicas > p.max_replicas
                or e.observed_ready_replicas > e.to_desired_replicas
            ):
                risks.add(ReplicaRisk.SCALE_BOUNDS_UNSAFE)
            scale_previous = scale_event_digest(e)

        if tuple(e.failover_id for e in m.failovers) != p.expected_failover_ids:
            risks.add(ReplicaRisk.FAILOVER_COVERAGE_MISMATCH)
        for e in m.failovers:
            failed = replicas.get(e.failed_replica_id)
            successor = replicas.get(e.successor_replica_id)
            if (
                failed is None
                or successor is None
                or failed.replica_id == successor.replica_id
                or e.failed_instance_generation != failed.instance_generation
                or e.successor_instance_generation != successor.instance_generation
            ):
                risks.add(ReplicaRisk.FAILOVER_BINDING_MISMATCH)
            if failed is not None and (
                failed.state != ReplicaState.FAILED or not failed.fenced or failed.accepting_requests
            ):
                risks.add(ReplicaRisk.FAILOVER_FENCE_MISSING)
            if successor is not None and (
                successor.state != ReplicaState.READY
                or not successor.healthy
                or not successor.accepting_requests
                or successor.fenced
            ):
                risks.add(ReplicaRisk.FAILOVER_BINDING_MISMATCH)
            if (
                e.fence_epoch < e.failure_epoch
                or e.prior_router_generation >= e.new_router_generation
                or e.new_router_generation != m.router_generation
            ):
                risks.add(ReplicaRisk.FAILOVER_GENERATION_MISMATCH)
            auth = failover_authorization_digest(
                m.router_id, e.failed_replica_id, e.successor_replica_id, e.new_router_generation
            )
            if e.authorization_sha256.casefold() != auth.casefold():
                risks.add(ReplicaRisk.FAILOVER_AUTHORIZATION_MISMATCH)
            for route in m.routing_decisions:
                if route.router_generation >= e.new_router_generation and route.selected_replica_id == e.failed_replica_id:
                    risks.add(ReplicaRisk.STALE_REPLICA_NOT_FENCED)

        if m.network_operations:
            risks.add(ReplicaRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(risks, key=lambda x: x.value))

    def evaluate(
        self,
        request: InferenceReplicaRoutingRequest,
        m: InferenceReplicaRoutingManifest,
        a: VerifiedInferenceStreamingSecurityAssessment,
    ) -> VerifiedInferenceReplicaRoutingAssessment:
        self._validate_manifest(m)
        actual = inference_replica_routing_manifest_digest(m)
        if actual.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(ReplicaRejectReason.MANIFEST_DIGEST_MISMATCH, "replica manifest differs from policy pin")
        if request.manifest_id != m.manifest_id or request.manifest_sha256.casefold() != actual.casefold():
            reject(ReplicaRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if (
            request.evaluated_at_epoch < m.created_at_epoch - self.policy.max_future_skew_seconds
            or request.evaluated_at_epoch > m.created_at_epoch + self.policy.max_manifest_age_seconds
        ):
            reject(ReplicaRejectReason.REQUEST_INVALID, "manifest freshness invalid")
        identity = (
            request.declared_request_id,
            request.declared_tenant_id,
            request.declared_session_id,
            request.declared_router_id,
            request.declared_router_generation,
            request.declared_replica_ids,
            request.declared_routing_ids,
        )
        evidence = (
            m.request_id,
            m.tenant_id,
            m.session_id,
            m.router_id,
            m.router_generation,
            tuple(r.replica_id for r in m.replicas),
            tuple(e.routing_id for e in m.routing_decisions),
        )
        if identity != evidence:
            reject(ReplicaRejectReason.DECLARED_SUMMARY_MISMATCH, "caller identity summary disagrees with evidence")
        risks = self.derive(m, a)
        decision = ReplicaDecision.ALLOW if not risks else ReplicaDecision.DENY
        safe = not risks
        declared = (
            request.declared_upstream_p10g_bound,
            request.declared_replica_identity_safe,
            request.declared_health_capacity_safe,
            request.declared_routing_generation_safe,
            request.declared_autoscaling_safe,
            request.declared_failover_fencing_safe,
            request.declared_replay_safe,
            request.declared_lineage_safe,
            request.declared_replica_routing_safe,
        )
        if declared != (safe,) * 9:
            reject(ReplicaRejectReason.DECLARED_SUMMARY_MISMATCH, "caller safety summary disagrees with derived evidence")

        identity_bad = {
            ReplicaRisk.REPLICA_COVERAGE_MISMATCH,
            ReplicaRisk.REPLICA_IDENTITY_MISMATCH,
            ReplicaRisk.REPLICA_ROUTE_MISMATCH,
            ReplicaRisk.ENDPOINT_ALIAS,
            ReplicaRisk.PROCESS_ALIAS,
        }
        health_bad = {
            ReplicaRisk.REPLICA_HEALTH_UNSAFE,
            ReplicaRisk.REPLICA_CAPACITY_EXCEEDED,
            ReplicaRisk.REPLICA_HEARTBEAT_STALE,
            ReplicaRisk.READY_QUORUM_INSUFFICIENT,
        }
        generation_bad = {
            ReplicaRisk.ROUTER_IDENTITY_MISMATCH,
            ReplicaRisk.ROUTER_GENERATION_ROLLBACK,
            ReplicaRisk.ROUTING_GENERATION_MISMATCH,
            ReplicaRisk.ROUTING_SEQUENCE_MISMATCH,
            ReplicaRisk.ROUTING_CHAIN_MISMATCH,
            ReplicaRisk.ROUTING_TO_UNSAFE_REPLICA,
        }
        scale_bad = {
            ReplicaRisk.SCALE_COVERAGE_MISMATCH,
            ReplicaRisk.SCALE_SEQUENCE_MISMATCH,
            ReplicaRisk.SCALE_CHAIN_MISMATCH,
            ReplicaRisk.SCALE_AUTHORIZATION_MISMATCH,
            ReplicaRisk.SCALE_BOUNDS_UNSAFE,
        }
        failover_bad = {
            ReplicaRisk.FAILOVER_COVERAGE_MISMATCH,
            ReplicaRisk.FAILOVER_BINDING_MISMATCH,
            ReplicaRisk.FAILOVER_FENCE_MISSING,
            ReplicaRisk.FAILOVER_GENERATION_MISMATCH,
            ReplicaRisk.FAILOVER_AUTHORIZATION_MISMATCH,
            ReplicaRisk.STALE_REPLICA_NOT_FENCED,
        }
        replay_bad = {
            ReplicaRisk.IDEMPOTENCY_BINDING_MISMATCH,
            ReplicaRisk.REQUEST_REPLAY,
            ReplicaRisk.PRIOR_REQUEST_LEDGER_MISMATCH,
        }
        lineage_bad = {ReplicaRisk.LINEAGE_MISMATCH}
        evidence_sha = digest_json({
            "manifest_id": m.manifest_id,
            "request_id": m.request_id,
            "tenant_id": m.tenant_id,
            "router_id": m.router_id,
            "router_generation": m.router_generation,
            "replica_ids": tuple(r.replica_id for r in m.replicas),
            "routing_ids": tuple(e.routing_id for e in m.routing_decisions),
            "risks": risks,
            "decision": decision,
            "schema": P10H_ASSESSMENT_SCHEMA_VERSION,
            "mode": P10H_ASSESSMENT_MODE,
        })
        return VerifiedInferenceReplicaRoutingAssessment(
            m.manifest_id,
            actual,
            m.request_id,
            m.tenant_id,
            m.session_id,
            decision,
            risks,
            m.p10g_assessment_sha256,
            m.target_model_id,
            m.target_model_revision,
            m.adapter_ids,
            m.adapter_generation,
            m.partition_ids,
            m.stream_id,
            m.router_id,
            m.router_generation,
            tuple(r.replica_id for r in m.replicas),
            tuple(e.routing_id for e in m.routing_decisions),
            ReplicaRisk.UPSTREAM_P10G_INVALID not in risks and ReplicaRisk.UPSTREAM_BINDING_MISMATCH not in risks,
            not bool(set(risks) & identity_bad),
            not bool(set(risks) & health_bad),
            not bool(set(risks) & generation_bad),
            not bool(set(risks) & scale_bad),
            not bool(set(risks) & failover_bad),
            not bool(set(risks) & replay_bad),
            not bool(set(risks) & lineage_bad),
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            P10H_ASSESSMENT_SCHEMA_VERSION,
            P10H_ASSESSMENT_MODE,
            evidence_sha,
        )
