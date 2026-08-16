from __future__ import annotations

import re

from aegis.inference.incident_response_types import *
from aegis.inference.replica_routing_types import (
    P10H_ASSESSMENT_MODE, P10H_ASSESSMENT_SCHEMA_VERSION,
    ReplicaDecision, VerifiedInferenceReplicaRoutingAssessment,
)

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def _sha(x: str) -> bool: return bool(_HEX64.fullmatch(x or ""))
def _id(x: str) -> bool: return isinstance(x, str) and 1 <= len(x) <= 160 and x.strip() == x and "\x00" not in x
def _unique(xs) -> bool:
    xs = tuple(xs); return len(xs) == len(set(xs))
def _same_sha(a: str, b: str) -> bool: return bool(a and b and a.casefold() == b.casefold())


def _upstream_ok(a: VerifiedInferenceReplicaRoutingAssessment, expected_sha: str) -> bool:
    positives = (
        a.upstream_p10g_bound, a.replica_identity_verified, a.health_and_capacity_verified,
        a.routing_generation_verified, a.autoscaling_verified, a.failover_fencing_verified,
        a.idempotency_replay_verified, a.lineage_verified,
    )
    nonclaims = (
        a.caller_declared_safety_trusted, a.production_service_mesh_integrated,
        a.production_orchestrator_integrated, a.distributed_consensus_validated,
        a.cross_zone_failover_validated, a.load_balancer_stickiness_validated,
        a.production_autoscaler_validated, a.network_partition_resistance_validated,
        a.exactly_once_delivery_validated,
    )
    return (
        a.decision == ReplicaDecision.ALLOW and not a.risks and all(positives) and not any(nonclaims)
        and a.assessment_schema_version == P10H_ASSESSMENT_SCHEMA_VERSION
        and a.assessment_mode == P10H_ASSESSMENT_MODE
        and _same_sha(a.assessment_evidence_sha256, expected_sha)
    )


class InferenceIncidentResponseAnalyzer:
    def __init__(self, policy: InferenceIncidentResponsePolicy):
        self.policy = policy; self._validate_policy()

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P10I_POLICY_VERSION: reject(IncidentRejectReason.POLICY_INVALID, "unexpected policy version")
        ids = (p.expected_manifest_id, p.expected_request_id, p.expected_tenant_id, p.expected_session_id,
               p.expected_target_model_id, p.expected_target_model_revision, p.expected_stream_id,
               p.expected_router_id, p.expected_incident_id, p.expected_compromised_replica_id)
        if not all(_id(x) for x in ids): reject(IncidentRejectReason.POLICY_INVALID, "invalid policy identifier")
        if not _sha(p.expected_manifest_sha256) or not _sha(p.expected_p10h_assessment_sha256): reject(IncidentRejectReason.POLICY_INVALID, "invalid policy digest")
        seqs = (p.expected_adapter_ids, p.expected_partition_ids, p.expected_replica_ids, p.expected_routing_ids,
                p.expected_signal_ids, p.required_signal_types, p.expected_containment_action_ids,
                p.required_containment_actions, p.expected_recovery_ids, p.required_recovery_types,
                p.expected_forensic_artifact_ids, p.required_forensic_kinds, p.required_exit_controls,
                p.required_local_runtime_gates, p.required_deferred_mastery_items)
        if any(not xs or not _unique(xs) or not all(_id(x) for x in xs) for xs in seqs): reject(IncidentRejectReason.POLICY_INVALID, "invalid policy coverage")
        if p.expected_adapter_generation < 0 or p.minimum_router_generation < 0 or min(p.max_detection_latency_seconds, p.max_containment_latency_seconds, p.max_manifest_age_seconds, p.max_future_skew_seconds) < 0:
            reject(IncidentRejectReason.POLICY_INVALID, "invalid policy bound")

    def _validate_manifest(self, m: InferenceIncidentResponseManifest) -> None:
        if m.schema_version != P10I_SCHEMA_VERSION: reject(IncidentRejectReason.MANIFEST_INVALID, "unexpected schema")
        ids = (m.manifest_id, m.request_id, m.tenant_id, m.session_id, m.target_model_id, m.target_model_revision,
               m.stream_id, m.router_id, m.incident_id, m.compromised_replica_id)
        if not all(_id(x) for x in ids): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid identifier")
        if min(m.created_at_epoch, m.detection_started_at_epoch, m.router_generation, m.adapter_generation, m.network_operations) < 0 or not _sha(m.p10h_assessment_sha256): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid manifest field")
        for xs in (m.adapter_ids, m.partition_ids, m.replica_ids, m.routing_ids):
            if not xs or not _unique(xs) or not all(_id(x) for x in xs): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid route coverage")
        if not all((m.signals, m.containment_actions, m.recovery_steps, m.forensic_artifacts)): reject(IncidentRejectReason.MANIFEST_INVALID, "empty incident evidence")
        if not _unique(x.signal_id for x in m.signals) or not _unique(x.action_id for x in m.containment_actions) or not _unique(x.recovery_id for x in m.recovery_steps) or not _unique(x.artifact_id for x in m.forensic_artifacts): reject(IncidentRejectReason.MANIFEST_INVALID, "duplicate evidence")
        for s in m.signals:
            if not all(_id(x) for x in (s.signal_id, s.signal_type, s.source_id, s.request_id, s.tenant_id, s.session_id, s.severity)) or s.sequence_no <= 0 or s.observed_at_epoch < 0 or not all(_sha(x) for x in (s.artifact_sha256, s.previous_signal_sha256)): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid signal")
        for a in m.containment_actions:
            if not all(_id(x) for x in (a.action_id, a.action_type, a.target_id)) or a.sequence_no <= 0 or a.started_at_epoch < 0 or a.completed_at_epoch < a.started_at_epoch or not all(_sha(x) for x in (a.authorization_sha256, a.result_sha256, a.previous_action_sha256)): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid containment")
        for r in m.recovery_steps:
            if not all(_id(x) for x in (r.recovery_id, r.recovery_type, r.target_id)) or r.sequence_no <= 0 or min(r.expected_generation, r.observed_generation, r.completed_at_epoch) < 0 or not all(_sha(x) for x in (r.evidence_sha256, r.previous_recovery_sha256)): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid recovery")
        for f in m.forensic_artifacts:
            if not all(_id(x) for x in (f.artifact_id, f.artifact_kind, f.source_id)) or f.collected_at_epoch < 0 or not all(_sha(x) for x in (f.content_sha256, f.previous_artifact_sha256, f.chain_of_custody_sha256)): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid forensic artifact")
        g = m.exit_gate
        for xs in (g.required_controls, g.validated_controls, g.local_runtime_gates, g.deferred_mastery_items):
            if not xs or not _unique(xs) or not all(_id(x) for x in xs): reject(IncidentRejectReason.MANIFEST_INVALID, "invalid exit gate")

    def evaluate(self, m: InferenceIncidentResponseManifest, q: InferenceIncidentResponseRequest, u: VerifiedInferenceReplicaRoutingAssessment) -> VerifiedInferenceIncidentResponseAssessment:
        self._validate_manifest(m); p = self.policy
        msha = inference_incident_response_manifest_digest(m)
        if not _same_sha(msha, p.expected_manifest_sha256): reject(IncidentRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest digest mismatch")
        if q.manifest_id != m.manifest_id or not _same_sha(q.manifest_sha256, msha): reject(IncidentRejectReason.REQUEST_INVALID, "request outer binding mismatch")
        if q.evaluated_at_epoch + p.max_future_skew_seconds < m.created_at_epoch or q.evaluated_at_epoch - m.created_at_epoch > p.max_manifest_age_seconds: reject(IncidentRejectReason.REQUEST_INVALID, "manifest time invalid")
        risks: list[IncidentRisk] = []
        def add(r, bad):
            if bad and r not in risks: risks.append(r)

        up = _upstream_ok(u, p.expected_p10h_assessment_sha256)
        add(IncidentRisk.UPSTREAM_P10H_INVALID, not up)
        add(IncidentRisk.UPSTREAM_BINDING_MISMATCH, not _same_sha(m.p10h_assessment_sha256, p.expected_p10h_assessment_sha256))
        route = (
            m.request_id == p.expected_request_id == u.request_id and m.tenant_id == p.expected_tenant_id == u.tenant_id
            and m.session_id == p.expected_session_id == u.session_id and m.target_model_id == p.expected_target_model_id == u.target_model_id
            and m.target_model_revision == p.expected_target_model_revision == u.target_model_revision and m.adapter_ids == p.expected_adapter_ids == u.adapter_ids
            and m.adapter_generation == p.expected_adapter_generation == u.adapter_generation and m.partition_ids == p.expected_partition_ids == u.partition_ids
            and m.stream_id == p.expected_stream_id == u.stream_id and m.router_id == p.expected_router_id == u.router_id
            and m.router_generation >= p.minimum_router_generation and m.router_generation == u.router_generation
            and m.replica_ids == p.expected_replica_ids == u.replica_ids and m.routing_ids == p.expected_routing_ids == u.routing_ids
        )
        add(IncidentRisk.REQUEST_ROUTE_MISMATCH, not route)
        add(IncidentRisk.INCIDENT_IDENTITY_MISMATCH, m.incident_id != p.expected_incident_id or m.compromised_replica_id != p.expected_compromised_replica_id or m.compromised_replica_id not in m.replica_ids)

        signal_ids = tuple(x.signal_id for x in m.signals); signal_types = tuple(x.signal_type for x in m.signals)
        add(IncidentRisk.SIGNAL_COVERAGE_MISMATCH, signal_ids != p.expected_signal_ids or not set(p.required_signal_types).issubset(signal_types))
        prev = incident_seed_digest(m.incident_id, m.request_id, m.tenant_id, m.session_id)
        for n, s in enumerate(m.signals, 1):
            add(IncidentRisk.SIGNAL_SEQUENCE_MISMATCH, s.sequence_no != n); add(IncidentRisk.SIGNAL_CHAIN_MISMATCH, not _same_sha(s.previous_signal_sha256, prev))
            add(IncidentRisk.SIGNAL_BINDING_MISMATCH, (s.request_id, s.tenant_id, s.session_id) != (m.request_id, m.tenant_id, m.session_id))
            add(IncidentRisk.DETECTION_LATENCY_EXCEEDED, s.observed_at_epoch < m.detection_started_at_epoch or s.observed_at_epoch - m.detection_started_at_epoch > p.max_detection_latency_seconds); prev = signal_digest(s)
        detection = not any(x in risks for x in (IncidentRisk.SIGNAL_COVERAGE_MISMATCH, IncidentRisk.SIGNAL_SEQUENCE_MISMATCH, IncidentRisk.SIGNAL_CHAIN_MISMATCH, IncidentRisk.SIGNAL_BINDING_MISMATCH, IncidentRisk.DETECTION_LATENCY_EXCEEDED))

        action_ids = tuple(x.action_id for x in m.containment_actions); action_types = tuple(x.action_type for x in m.containment_actions)
        add(IncidentRisk.CONTAINMENT_COVERAGE_MISMATCH, action_ids != p.expected_containment_action_ids or not set(p.required_containment_actions).issubset(action_types))
        prev = signal_digest(m.signals[-1]); first = min(x.observed_at_epoch for x in m.signals)
        expected_targets = {"fence_compromised_replica": m.compromised_replica_id, "advance_router_generation": m.router_id, "revoke_stream": m.stream_id}
        for n, a in enumerate(m.containment_actions, 1):
            add(IncidentRisk.CONTAINMENT_SEQUENCE_MISMATCH, a.sequence_no != n); add(IncidentRisk.CONTAINMENT_CHAIN_MISMATCH, not _same_sha(a.previous_action_sha256, prev))
            add(IncidentRisk.CONTAINMENT_AUTHORIZATION_MISMATCH, not _same_sha(a.authorization_sha256, containment_authorization_digest(m.incident_id, a.action_id, a.action_type, a.target_id)))
            add(IncidentRisk.CONTAINMENT_TARGET_MISMATCH, a.action_type in expected_targets and a.target_id != expected_targets[a.action_type])
            add(IncidentRisk.CONTAINMENT_LATENCY_EXCEEDED, a.completed_at_epoch - first > p.max_containment_latency_seconds); prev = containment_digest(a)
        containment = not any(x in risks for x in (IncidentRisk.CONTAINMENT_COVERAGE_MISMATCH, IncidentRisk.CONTAINMENT_SEQUENCE_MISMATCH, IncidentRisk.CONTAINMENT_CHAIN_MISMATCH, IncidentRisk.CONTAINMENT_AUTHORIZATION_MISMATCH, IncidentRisk.CONTAINMENT_TARGET_MISMATCH, IncidentRisk.CONTAINMENT_LATENCY_EXCEEDED))

        recovery_ids = tuple(x.recovery_id for x in m.recovery_steps); recovery_types = tuple(x.recovery_type for x in m.recovery_steps)
        add(IncidentRisk.RECOVERY_COVERAGE_MISMATCH, recovery_ids != p.expected_recovery_ids or not set(p.required_recovery_types).issubset(recovery_types))
        prev = containment_digest(m.containment_actions[-1]); generation = m.router_generation
        for n, r in enumerate(m.recovery_steps, 1):
            add(IncidentRisk.RECOVERY_SEQUENCE_MISMATCH, r.sequence_no != n); add(IncidentRisk.RECOVERY_CHAIN_MISMATCH, not _same_sha(r.previous_recovery_sha256, prev))
            add(IncidentRisk.RECOVERY_GENERATION_ROLLBACK, r.observed_generation < r.expected_generation or r.observed_generation < generation); add(IncidentRisk.RECOVERY_NOT_VERIFIED, not r.verified)
            generation = max(generation, r.observed_generation); prev = recovery_digest(r)
        recovery = not any(x in risks for x in (IncidentRisk.RECOVERY_COVERAGE_MISMATCH, IncidentRisk.RECOVERY_SEQUENCE_MISMATCH, IncidentRisk.RECOVERY_CHAIN_MISMATCH, IncidentRisk.RECOVERY_GENERATION_ROLLBACK, IncidentRisk.RECOVERY_NOT_VERIFIED))

        forensic_ids = tuple(x.artifact_id for x in m.forensic_artifacts); forensic_kinds = tuple(x.artifact_kind for x in m.forensic_artifacts)
        add(IncidentRisk.FORENSIC_COVERAGE_MISMATCH, forensic_ids != p.expected_forensic_artifact_ids or not set(p.required_forensic_kinds).issubset(forensic_kinds)); prev = recovery_digest(m.recovery_steps[-1])
        for f in m.forensic_artifacts:
            add(IncidentRisk.FORENSIC_CHAIN_MISMATCH, not _same_sha(f.previous_artifact_sha256, prev)); expected = forensic_chain_digest(f.artifact_id, f.artifact_kind, f.source_id, f.content_sha256, f.previous_artifact_sha256)
            add(IncidentRisk.FORENSIC_ARTIFACT_DIGEST_MISMATCH, not _same_sha(f.chain_of_custody_sha256, expected)); add(IncidentRisk.FORENSIC_IMMUTABILITY_UNPROVEN, not f.immutable_snapshot); prev = f.chain_of_custody_sha256
        forensics = not any(x in risks for x in (IncidentRisk.FORENSIC_COVERAGE_MISMATCH, IncidentRisk.FORENSIC_ARTIFACT_DIGEST_MISMATCH, IncidentRisk.FORENSIC_CHAIN_MISMATCH, IncidentRisk.FORENSIC_IMMUTABILITY_UNPROVEN))

        g = m.exit_gate; controls = g.required_controls == p.required_exit_controls and g.validated_controls == p.required_exit_controls
        add(IncidentRisk.EXIT_GATE_CONTROL_COVERAGE_MISMATCH, not controls or g.local_runtime_gates != p.required_local_runtime_gates)
        debt = g.deferred_mastery_items == p.required_deferred_mastery_items; add(IncidentRisk.DEFERRED_MASTERY_DEBT_MISSING, not debt)
        add(IncidentRisk.HOSTED_CI_CLAIM_UNSUPPORTED, g.hosted_ci_execution_verified); add(IncidentRisk.PRODUCTION_CLAIM_UNSUPPORTED, g.production_validation_claimed); add(IncidentRisk.PROFESSIONAL_MASTERY_CLAIM_UNSUPPORTED, g.professional_mastery_complete)
        expected_status = ExitGateStatus.PASS_WITH_DEFERRED if g.deferred_mastery_items else ExitGateStatus.PASS; gate_status = g.phase10_exit_eligible and g.status == expected_status
        add(IncidentRisk.EXIT_GATE_STATUS_MISMATCH, not gate_status); add(IncidentRisk.NETWORK_OPERATION_UNEXPECTED, m.network_operations != 0)
        exit_gate = controls and debt and gate_status and not g.hosted_ci_execution_verified and not g.production_validation_claimed and not g.professional_mastery_complete

        declared = (
            q.declared_request_id == m.request_id, q.declared_tenant_id == m.tenant_id, q.declared_session_id == m.session_id,
            q.declared_incident_id == m.incident_id, q.declared_compromised_replica_id == m.compromised_replica_id,
            q.declared_router_generation == m.router_generation, q.declared_upstream_p10h_bound == up,
            q.declared_detection_complete == detection, q.declared_containment_complete == containment,
            q.declared_recovery_complete == recovery, q.declared_forensics_complete == forensics,
            q.declared_exit_gate_safe == exit_gate, q.declared_gpu_debt_carried == debt,
            q.declared_hosted_ci_verified == g.hosted_ci_execution_verified, q.declared_production_validated == g.production_validation_claimed,
            q.declared_professional_mastery_complete == g.professional_mastery_complete,
        )
        safe = not risks
        if not all(declared) or q.declared_incident_response_safe != safe: reject(IncidentRejectReason.DECLARED_SUMMARY_MISMATCH, "caller summary disagrees with evidence")
        decision = IncidentDecision.ALLOW if safe else IncidentDecision.DENY
        evidence = digest_json({"manifest_sha256": msha, "request_id": m.request_id, "tenant_id": m.tenant_id, "session_id": m.session_id, "incident_id": m.incident_id, "router_generation": m.router_generation, "risks": tuple(x.value for x in risks), "decision": decision.value, "exit_gate_status": g.status.value, "assessment_schema_version": P10I_ASSESSMENT_SCHEMA_VERSION, "assessment_mode": P10I_ASSESSMENT_MODE})
        return VerifiedInferenceIncidentResponseAssessment(
            m.manifest_id, msha, m.request_id, m.tenant_id, m.session_id, decision, tuple(risks), m.p10h_assessment_sha256,
            m.target_model_id, m.target_model_revision, m.adapter_ids, m.adapter_generation, m.partition_ids, m.stream_id,
            m.router_id, m.router_generation, m.replica_ids, m.routing_ids, m.incident_id, m.compromised_replica_id,
            signal_ids, action_ids, recovery_ids, forensic_ids, g.status, up, detection, containment, recovery, forensics,
            exit_gate, debt, False, False, False, False, False, g.hosted_ci_execution_verified, g.production_validation_claimed,
            g.professional_mastery_complete, P10I_ASSESSMENT_SCHEMA_VERSION, P10I_ASSESSMENT_MODE, evidence,
        )
