from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Mapping

from aegis.architecture.telemetry_security import (
    TelemetryCoverageManifest,
    TelemetryCoveragePolicy,
    TelemetryCoverageRequest,
    TelemetryEventClass,
    TelemetryEventRequirement,
    TelemetryNode,
    TelemetryNodeType,
    TelemetryRoute,
    TelemetrySeverity,
    TelemetrySourceKind,
    telemetry_coverage_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus


NOW = 2_200_000_000
PLAN_ID = "aegisdesk-security-telemetry-coverage-plan"
PLAN_VERSION = "2026.08-p7g.1"

P7A_SHA = hashlib.sha256(b"p7a-for-p7g").hexdigest()
P7B_SHA = hashlib.sha256(b"p7b-for-p7g").hexdigest()
P7C_SHA = hashlib.sha256(b"p7c-for-p7g").hexdigest()
P7D_SHA = hashlib.sha256(b"p7d-for-p7g").hexdigest()
P7E_SHA = hashlib.sha256(b"p7e-for-p7g").hexdigest()
P7F_SHA = hashlib.sha256(b"p7f-for-p7g").hexdigest()
POSTURE_SHA = hashlib.sha256(b"posture-for-p7g").hexdigest()
CATALOG_SHA = hashlib.sha256(b"catalog-for-p7g").hexdigest()

CTRL_TELEMETRY_INTEGRITY = "CTRL-TELEMETRY-INTEGRITY"
CTRL_TELEMETRY_ACCESS = "CTRL-TELEMETRY-ACCESS"
CTRL_AUDIT_APPEND_ONLY = "CTRL-AUDIT-APPEND-ONLY"
CTRL_ALERT_ROUTING = "CTRL-ALERT-ROUTING"
CTRL_TELEMETRY_FAILOVER = "CTRL-TELEMETRY-FAILOVER"
CTRL_TIME_INTEGRITY = "CTRL-TIME-INTEGRITY"
ALL_CONTROLS = (
    CTRL_TELEMETRY_INTEGRITY,
    CTRL_TELEMETRY_ACCESS,
    CTRL_AUDIT_APPEND_ONLY,
    CTRL_ALERT_ROUTING,
    CTRL_TELEMETRY_FAILOVER,
    CTRL_TIME_INTEGRITY,
)

P7A_OBJECTS = ("p7a-path-external-tool", "p7a-path-model-runtime")
P7B_OBJECTS = ("p7b-path-admin-capability", "p7b-path-tool-capability")
P7C_OBJECTS = ("p7c-path-data-access", "p7c-path-data-egress")
P7D_OBJECTS = ("p7d-path-secret-access", "p7d-path-model-signing")
P7E_OBJECTS = ("p7e-path-tool-egress", "p7e-path-model-egress")
P7F_OBJECTS = (
    "scenario-idp-unavailable",
    "scenario-model-unavailable",
    "scenario-telemetry-degraded",
    "scenario-tool-unavailable",
)


def _paths(ids: tuple[str, ...]) -> tuple[SimpleNamespace, ...]:
    return tuple(SimpleNamespace(path_id=value) for value in ids)


def _upstreams() -> dict[str, object]:
    p7a = SimpleNamespace(
        assessment_evidence_sha256=P7A_SHA,
        exact_architecture_binding_verified=True,
        required_graph_coverage_verified=True,
        paths=_paths(P7A_OBJECTS),
    )
    p7b = SimpleNamespace(
        assessment_evidence_sha256=P7B_SHA,
        exact_architecture_binding_verified=True,
        exact_p7a_assessment_binding_verified=True,
        paths=_paths(P7B_OBJECTS),
    )
    p7c = SimpleNamespace(
        assessment_evidence_sha256=P7C_SHA,
        exact_architecture_binding_verified=True,
        exact_p7a_assessment_binding_verified=True,
        exact_p7b_assessment_binding_verified=True,
        exact_p6d_posture_binding_verified=True,
        paths=_paths(P7C_OBJECTS),
    )
    p7d = SimpleNamespace(
        assessment_evidence_sha256=P7D_SHA,
        exact_architecture_binding_verified=True,
        exact_p7a_assessment_binding_verified=True,
        exact_p7b_assessment_binding_verified=True,
        exact_p7c_assessment_binding_verified=True,
        exact_p6d_posture_binding_verified=True,
        paths=_paths(P7D_OBJECTS),
    )
    p7e = SimpleNamespace(
        assessment_evidence_sha256=P7E_SHA,
        exact_dependency_graph_binding_verified=True,
        exact_p7a_assessment_binding_verified=True,
        exact_p7b_assessment_binding_verified=True,
        exact_p7c_assessment_binding_verified=True,
        exact_p7d_assessment_binding_verified=True,
        exact_p6d_posture_binding_verified=True,
        destination_identity_policy_pinned=True,
        transport_auth_policy_pinned=True,
        egress_scope_policy_pinned=True,
        paths=_paths(P7E_OBJECTS),
    )
    p7f = SimpleNamespace(
        assessment_evidence_sha256=P7F_SHA,
        exact_resilience_plan_binding_verified=True,
        exact_p7e_assessment_binding_verified=True,
        exact_p6d_posture_binding_verified=True,
        failure_states_policy_pinned=True,
        fallback_routes_policy_pinned=True,
        security_degradation_derived_from_evidence=True,
        scenarios=tuple(SimpleNamespace(scenario_id=value) for value in P7F_OBJECTS),
    )
    return {"p7a": p7a, "p7b": p7b, "p7c": p7c, "p7d": p7d, "p7e": p7e, "p7f": p7f}


def _requirements() -> tuple[TelemetryEventRequirement, ...]:
    core = ("event_id", "timestamp", "actor_id", "action", "result", "correlation_id")
    return (
        TelemetryEventRequirement("req-authentication", TelemetryEventClass.AUTHENTICATION, TelemetrySeverity.HIGH, TelemetrySourceKind.P7A_ATTACK_PATH, (P7A_OBJECTS[0],), core + ("principal_id",), False, 120, "security-observability", "Authentication decisions at the external trust boundary."),
        TelemetryEventRequirement("req-authorization", TelemetryEventClass.AUTHORIZATION, TelemetrySeverity.HIGH, TelemetrySourceKind.P7B_PRIVILEGE_PATH, (P7B_OBJECTS[0],), core + ("principal_id", "capability_id"), True, 90, "security-observability", "Authorization outcomes for privileged capability paths."),
        TelemetryEventRequirement("req-privilege-change", TelemetryEventClass.PRIVILEGE_CHANGE, TelemetrySeverity.CRITICAL, TelemetrySourceKind.P7B_PRIVILEGE_PATH, (P7B_OBJECTS[0], P7B_OBJECTS[1]), core + ("principal_id", "previous_scope", "new_scope"), True, 60, "security-observability", "Privilege or capability-scope changes."),
        TelemetryEventRequirement("req-tool-execution", TelemetryEventClass.TOOL_EXECUTION, TelemetrySeverity.CRITICAL, TelemetrySourceKind.P7A_ATTACK_PATH, (P7A_OBJECTS[0],), core + ("tool_id", "arguments_digest"), True, 60, "security-observability", "Privileged tool execution and result status."),
        TelemetryEventRequirement("req-data-access", TelemetryEventClass.DATA_ACCESS, TelemetrySeverity.HIGH, TelemetrySourceKind.P7C_DATA_PATH, (P7C_OBJECTS[0],), core + ("data_id", "tenant_id"), False, 180, "security-observability", "Sensitive data access within tenant-aware paths."),
        TelemetryEventRequirement("req-data-egress", TelemetryEventClass.DATA_EGRESS, TelemetrySeverity.CRITICAL, TelemetrySourceKind.P7C_DATA_PATH, (P7C_OBJECTS[1],), core + ("data_id", "data_class", "destination"), True, 60, "security-observability", "Cross-boundary or external data egress."),
        TelemetryEventRequirement("req-secret-access", TelemetryEventClass.SECRET_ACCESS, TelemetrySeverity.CRITICAL, TelemetrySourceKind.P7D_SECRET_PATH, (P7D_OBJECTS[0],), core + ("secret_id", "surface_id"), True, 45, "security-observability", "Secret or credential access and transfer."),
        TelemetryEventRequirement("req-model-runtime", TelemetryEventClass.MODEL_RUNTIME, TelemetrySeverity.HIGH, TelemetrySourceKind.P7A_ATTACK_PATH, (P7A_OBJECTS[1],), core + ("model_release_id", "runtime_id"), False, 180, "security-observability", "Security-relevant model runtime events."),
        TelemetryEventRequirement("req-model-release", TelemetryEventClass.MODEL_RELEASE, TelemetrySeverity.CRITICAL, TelemetrySourceKind.P7D_SECRET_PATH, (P7D_OBJECTS[1],), core + ("release_id", "signing_key_id", "artifact_digest"), True, 45, "security-observability", "Model release/signing events."),
        TelemetryEventRequirement("req-dependency-egress", TelemetryEventClass.DEPENDENCY_EGRESS, TelemetrySeverity.HIGH, TelemetrySourceKind.P7E_DEPENDENCY_PATH, P7E_OBJECTS, core + ("dependency_id", "provider_id", "destination_identity"), True, 90, "security-observability", "Third-party service-egress decisions."),
        TelemetryEventRequirement("req-failover", TelemetryEventClass.FAILOVER, TelemetrySeverity.CRITICAL, TelemetrySourceKind.P7F_FAILURE_SCENARIO, P7F_OBJECTS, core + ("scenario_id", "fallback_id", "security_preserved"), True, 45, "security-observability", "Dependency failure and fallback transitions."),
        TelemetryEventRequirement("req-control-change", TelemetryEventClass.SECURITY_CONTROL_CHANGE, TelemetrySeverity.CRITICAL, TelemetrySourceKind.P6D_CONTROL, (CTRL_TELEMETRY_INTEGRITY, CTRL_TELEMETRY_FAILOVER, CTRL_ALERT_ROUTING), core + ("control_id", "previous_status", "new_status"), True, 45, "security-observability", "Security control status changes that affect detection coverage."),
    )


def _nodes() -> tuple[TelemetryNode, ...]:
    producer_ids = (
        "node-edge-producer",
        "node-identity-producer",
        "node-tool-producer",
        "node-data-producer",
        "node-secret-producer",
        "node-model-producer",
        "node-dependency-producer",
        "node-resilience-producer",
        "node-control-producer",
    )
    producers = tuple(
        TelemetryNode(node_id, TelemetryNodeType.PRODUCER, "security-observability", "workload", False, False, False, "Synthetic security event producer.")
        for node_id in producer_ids
    )
    return producers + (
        TelemetryNode("node-security-collector", TelemetryNodeType.COLLECTOR, "security-observability", "security-collection", True, False, False, "Synthetic integrity-validating collector."),
        TelemetryNode("node-security-processor", TelemetryNodeType.PROCESSOR, "security-observability", "security-processing", True, False, False, "Synthetic security event processor."),
        TelemetryNode("node-audit-sink", TelemetryNodeType.AUDIT_SINK, "security-observability", "security-audit", True, True, False, "Synthetic append-only audit sink."),
        TelemetryNode("node-alert-sink", TelemetryNodeType.ALERT_SINK, "security-observability", "security-alerting", True, False, True, "Synthetic alert sink."),
    )


def _producer_for(requirement_id: str) -> str:
    return {
        "req-authentication": "node-edge-producer",
        "req-authorization": "node-identity-producer",
        "req-privilege-change": "node-identity-producer",
        "req-tool-execution": "node-tool-producer",
        "req-data-access": "node-data-producer",
        "req-data-egress": "node-data-producer",
        "req-secret-access": "node-secret-producer",
        "req-model-runtime": "node-model-producer",
        "req-model-release": "node-model-producer",
        "req-dependency-egress": "node-dependency-producer",
        "req-failover": "node-resilience-producer",
        "req-control-change": "node-control-producer",
    }[requirement_id]


def _fallback_requirements() -> dict[str, frozenset[str]]:
    empty = frozenset()
    return {
        "req-authentication": frozenset({"scenario-idp-unavailable"}),
        "req-authorization": empty,
        "req-privilege-change": empty,
        "req-tool-execution": frozenset({"scenario-tool-unavailable"}),
        "req-data-access": empty,
        "req-data-egress": empty,
        "req-secret-access": empty,
        "req-model-runtime": frozenset({"scenario-model-unavailable"}),
        "req-model-release": empty,
        "req-dependency-egress": frozenset({"scenario-model-unavailable", "scenario-telemetry-degraded", "scenario-tool-unavailable"}),
        "req-failover": frozenset(P7F_OBJECTS),
        "req-control-change": frozenset({"scenario-telemetry-degraded"}),
    }


def _route_controls(requirement: TelemetryEventRequirement, fallback_ids: frozenset[str]) -> tuple[str, ...]:
    controls = {
        CTRL_TELEMETRY_INTEGRITY,
        CTRL_TELEMETRY_ACCESS,
        CTRL_AUDIT_APPEND_ONLY,
        CTRL_TIME_INTEGRITY,
    }
    if requirement.requires_alert:
        controls.add(CTRL_ALERT_ROUTING)
    if fallback_ids:
        controls.add(CTRL_TELEMETRY_FAILOVER)
    return tuple(sorted(controls))


def _routes(requirements: tuple[TelemetryEventRequirement, ...]) -> tuple[TelemetryRoute, ...]:
    fallback_map = _fallback_requirements()
    routes: list[TelemetryRoute] = []
    for requirement in requirements:
        node_ids = (
            _producer_for(requirement.requirement_id),
            "node-security-collector",
            "node-security-processor",
            "node-audit-sink",
        )
        if requirement.requires_alert:
            node_ids = node_ids + ("node-alert-sink",)
        routes.append(
            TelemetryRoute(
                route_id=f"route-{requirement.requirement_id.removeprefix('req-')}",
                requirement_id=requirement.requirement_id,
                node_ids=node_ids,
                owner_id="security-observability",
                observer_id="synthetic-telemetry-verifier",
                required_control_ids=_route_controls(requirement, fallback_map[requirement.requirement_id]),
                observed_at_epoch=NOW - 30,
                source_signature_valid=True,
                chain_integrity_valid=True,
                append_only_acknowledged=True,
                alert_path_operational=True,
                observed_detection_latency_seconds=min(30, requirement.max_detection_latency_seconds),
                covered_fallback_scenario_ids=tuple(sorted(fallback_map[requirement.requirement_id])),
                dropped_field_ids=(),
                description=f"Synthetic telemetry route for {requirement.requirement_id}.",
            )
        )
    return tuple(routes)


def _severity_base(value: TelemetrySeverity) -> int:
    return {
        TelemetrySeverity.LOW: 20,
        TelemetrySeverity.MEDIUM: 40,
        TelemetrySeverity.HIGH: 65,
        TelemetrySeverity.CRITICAL: 85,
    }[value]


def _derive_declared(
    requirements: tuple[TelemetryEventRequirement, ...],
    routes: tuple[TelemetryRoute, ...],
    statuses: Mapping[str, ControlStatus],
    fallback_map: Mapping[str, frozenset[str]],
) -> tuple[tuple[str, ...], int]:
    requirement_by_id = {item.requirement_id: item for item in requirements}
    scored: list[tuple[int, str]] = []
    for route in routes:
        requirement = requirement_by_id[route.requirement_id]
        reasons: list[str] = []
        if not route.source_signature_valid:
            reasons.append("source_signature_invalid")
        if not route.chain_integrity_valid:
            reasons.append("telemetry_chain_integrity_invalid")
        if not route.append_only_acknowledged:
            reasons.append("append_only_audit_not_acknowledged")
        if requirement.requires_alert and not route.alert_path_operational:
            reasons.append("alert_path_unavailable")
        if route.observed_detection_latency_seconds > requirement.max_detection_latency_seconds:
            reasons.append("detection_latency_exceeded")
        if any(statuses[control_id] == ControlStatus.EXCEPTIONED for control_id in route.required_control_ids):
            reasons.append("exceptioned_telemetry_control")
        if any(statuses[control_id] == ControlStatus.NOT_EVALUATED for control_id in route.required_control_ids):
            reasons.append("not_evaluated_telemetry_control")
        missing = fallback_map[route.requirement_id] - set(route.covered_fallback_scenario_ids)
        if missing:
            reasons.append("fallback_observability_gap")
        if route.dropped_field_ids:
            reasons.append("required_fields_dropped")
        if reasons:
            weights = {
                "source_signature_invalid": 25,
                "telemetry_chain_integrity_invalid": 30,
                "append_only_audit_not_acknowledged": 22,
                "alert_path_unavailable": 24,
                "detection_latency_exceeded": 14,
                "exceptioned_telemetry_control": 18,
                "not_evaluated_telemetry_control": 16,
                "fallback_observability_gap": 20,
                "required_fields_dropped": 12,
            }
            score = _severity_base(requirement.severity) + sum(weights[reason] for reason in reasons)
            score += max(0, len(missing) - 1) * 6
            score += max(0, len(route.dropped_field_ids) - 1) * 4
            scored.append((score, requirement.requirement_id))
    scored.sort(key=lambda value: (-value[0], value[1]))
    return tuple(requirement_id for _, requirement_id in scored), max((score for score, _ in scored), default=0)


def build_fixture(
    *,
    exceptioned_control: str | None = None,
    not_evaluated_control: str | None = None,
    route_overrides: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    upstreams = _upstreams()
    statuses = {control_id: ControlStatus.SATISFIED for control_id in ALL_CONTROLS}
    if exceptioned_control is not None:
        statuses[exceptioned_control] = ControlStatus.EXCEPTIONED
    if not_evaluated_control is not None:
        statuses[not_evaluated_control] = ControlStatus.NOT_EVALUATED
    posture = SimpleNamespace(
        exact_release_identity_verified=True,
        exact_upstream_evidence_binding_verified=True,
        control_catalog_verified=True,
        status_derived_from_evidence=True,
        posture_evidence_sha256=POSTURE_SHA,
        control_catalog_sha256=CATALOG_SHA,
        assessments=tuple(SimpleNamespace(control_id=control_id, status=statuses[control_id]) for control_id in ALL_CONTROLS),
        satisfied_control_ids=tuple(sorted(control_id for control_id, status in statuses.items() if status == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(control_id for control_id, status in statuses.items() if status == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(control_id for control_id, status in statuses.items() if status == ControlStatus.NOT_EVALUATED)),
    )

    requirements = _requirements()
    nodes = _nodes()
    routes = list(_routes(requirements))
    if route_overrides:
        routes = [
            replace(item, **dict(route_overrides[item.route_id])) if item.route_id in route_overrides else item
            for item in routes
        ]
    routes_tuple = tuple(routes)
    manifest = TelemetryCoverageManifest(
        telemetry_plan_id=PLAN_ID,
        version=PLAN_VERSION,
        p7a_assessment_evidence_sha256=P7A_SHA,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7c_assessment_evidence_sha256=P7C_SHA,
        p7d_assessment_evidence_sha256=P7D_SHA,
        p7e_assessment_evidence_sha256=P7E_SHA,
        p7f_assessment_evidence_sha256=P7F_SHA,
        posture_evidence_sha256=POSTURE_SHA,
        created_at_epoch=NOW - 60,
        requirements=requirements,
        nodes=nodes,
        routes=routes_tuple,
    )
    manifest_sha = telemetry_coverage_manifest_digest(manifest)
    requirement_by_id = {item.requirement_id: item for item in requirements}
    node_by_id = {item.node_id: item for item in nodes}
    route_by_id = {item.route_id: item for item in routes_tuple}
    fallback_map = _fallback_requirements()
    policy = TelemetryCoveragePolicy(
        expected_telemetry_plan_id=PLAN_ID,
        expected_telemetry_plan_version=PLAN_VERSION,
        expected_telemetry_plan_sha256=manifest_sha,
        expected_p7a_assessment_evidence_sha256=P7A_SHA,
        expected_p7b_assessment_evidence_sha256=P7B_SHA,
        expected_p7c_assessment_evidence_sha256=P7C_SHA,
        expected_p7d_assessment_evidence_sha256=P7D_SHA,
        expected_p7e_assessment_evidence_sha256=P7E_SHA,
        expected_p7f_assessment_evidence_sha256=P7F_SHA,
        expected_posture_evidence_sha256=POSTURE_SHA,
        expected_control_catalog_sha256=CATALOG_SHA,
        required_requirement_ids=frozenset(requirement_by_id),
        required_node_ids=frozenset(node_by_id),
        required_route_ids=frozenset(route_by_id),
        trusted_owner_ids=frozenset({"security-observability"}),
        trusted_observer_ids=frozenset({"synthetic-telemetry-verifier"}),
        expected_event_class_by_requirement={key: value.event_class for key, value in requirement_by_id.items()},
        minimum_severity_by_requirement={key: value.severity for key, value in requirement_by_id.items()},
        expected_source_kind_by_requirement={key: value.source_kind for key, value in requirement_by_id.items()},
        expected_source_object_ids_by_requirement={key: frozenset(value.source_object_ids) for key, value in requirement_by_id.items()},
        expected_required_field_ids_by_requirement={key: frozenset(value.required_field_ids) for key, value in requirement_by_id.items()},
        expected_requires_alert_by_requirement={key: value.requires_alert for key, value in requirement_by_id.items()},
        max_detection_latency_by_requirement={key: value.max_detection_latency_seconds for key, value in requirement_by_id.items()},
        required_fallback_scenario_ids_by_requirement=fallback_map,
        expected_node_type={key: value.node_type for key, value in node_by_id.items()},
        expected_node_zone={key: value.trust_zone for key, value in node_by_id.items()},
        minimum_integrity_validation_capable={key: value.node_type != TelemetryNodeType.PRODUCER for key, value in node_by_id.items()},
        minimum_append_only_capable={key: value.node_type == TelemetryNodeType.AUDIT_SINK for key, value in node_by_id.items()},
        minimum_alert_capable={key: value.node_type == TelemetryNodeType.ALERT_SINK for key, value in node_by_id.items()},
        expected_requirement_by_route={key: value.requirement_id for key, value in route_by_id.items()},
        expected_node_ids_by_route={key: value.node_ids for key, value in route_by_id.items()},
        expected_control_ids_by_route={key: frozenset(value.required_control_ids) for key, value in route_by_id.items()},
    )
    blind_spots, max_risk = _derive_declared(requirements, routes_tuple, statuses, fallback_map)
    request = TelemetryCoverageRequest(
        telemetry_plan_id=PLAN_ID,
        telemetry_plan_version=PLAN_VERSION,
        telemetry_plan_sha256=manifest_sha,
        p7a_assessment_evidence_sha256=P7A_SHA,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7c_assessment_evidence_sha256=P7C_SHA,
        p7d_assessment_evidence_sha256=P7D_SHA,
        p7e_assessment_evidence_sha256=P7E_SHA,
        p7f_assessment_evidence_sha256=P7F_SHA,
        posture_evidence_sha256=POSTURE_SHA,
        evaluated_at_epoch=NOW,
        requirement_ids=tuple(sorted(requirement_by_id)),
        declared_blind_spot_requirement_ids=blind_spots,
        declared_max_blind_spot_risk_score=max_risk,
    )
    return {
        **upstreams,
        "posture": posture,
        "manifest": manifest,
        "policy": policy,
        "request": request,
    }
