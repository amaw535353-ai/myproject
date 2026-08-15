from __future__ import annotations

import hashlib
import hmac
import json
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .attack_paths import VerifiedAttackPathAssessment
from .data_types import VerifiedDataExfiltrationAssessment
from .dependency_trust import VerifiedDependencyTrustAssessment
from .privilege_types import VerifiedPrivilegeEscalationAssessment
from .resilience_types import VerifiedResilienceSecurityAssessment
from .secrets_exposure import VerifiedSecretExposureAssessment
from .telemetry_types import (
    P7G_TELEMETRY_MANIFEST_SCHEMA_VERSION,
    TelemetryBlindSpotRejectReason,
    TelemetryCoverageManifest,
    TelemetryCoveragePolicy,
    TelemetryCoverageRequest,
    TelemetryEventRequirement,
    TelemetryNode,
    TelemetryNodeType,
    TelemetryRoute,
    TelemetrySeverity,
    TelemetrySourceKind,
    reject,
)


def is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def severity_rank(value: TelemetrySeverity) -> int:
    return {
        TelemetrySeverity.LOW: 1,
        TelemetrySeverity.MEDIUM: 2,
        TelemetrySeverity.HIGH: 3,
        TelemetrySeverity.CRITICAL: 4,
    }[value]


def canonical_telemetry_coverage_manifest_bytes(manifest: TelemetryCoverageManifest) -> bytes:
    document = {
        "created_at_epoch": manifest.created_at_epoch,
        "nodes": [
            {
                "alert_capable": item.alert_capable,
                "append_only_capable": item.append_only_capable,
                "description": item.description,
                "integrity_validation_capable": item.integrity_validation_capable,
                "node_id": item.node_id,
                "node_type": item.node_type.value,
                "owner_id": item.owner_id,
                "trust_zone": item.trust_zone,
            }
            for item in sorted(manifest.nodes, key=lambda value: value.node_id)
        ],
        "p7a_assessment_evidence_sha256": manifest.p7a_assessment_evidence_sha256.casefold(),
        "p7b_assessment_evidence_sha256": manifest.p7b_assessment_evidence_sha256.casefold(),
        "p7c_assessment_evidence_sha256": manifest.p7c_assessment_evidence_sha256.casefold(),
        "p7d_assessment_evidence_sha256": manifest.p7d_assessment_evidence_sha256.casefold(),
        "p7e_assessment_evidence_sha256": manifest.p7e_assessment_evidence_sha256.casefold(),
        "p7f_assessment_evidence_sha256": manifest.p7f_assessment_evidence_sha256.casefold(),
        "posture_evidence_sha256": manifest.posture_evidence_sha256.casefold(),
        "requirements": [
            {
                "description": item.description,
                "event_class": item.event_class.value,
                "max_detection_latency_seconds": item.max_detection_latency_seconds,
                "owner_id": item.owner_id,
                "required_field_ids": sorted(item.required_field_ids),
                "requirement_id": item.requirement_id,
                "requires_alert": item.requires_alert,
                "severity": item.severity.value,
                "source_kind": item.source_kind.value,
                "source_object_ids": sorted(item.source_object_ids),
            }
            for item in sorted(manifest.requirements, key=lambda value: value.requirement_id)
        ],
        "routes": [
            {
                "alert_path_operational": item.alert_path_operational,
                "append_only_acknowledged": item.append_only_acknowledged,
                "chain_integrity_valid": item.chain_integrity_valid,
                "covered_fallback_scenario_ids": sorted(item.covered_fallback_scenario_ids),
                "description": item.description,
                "dropped_field_ids": sorted(item.dropped_field_ids),
                "node_ids": list(item.node_ids),
                "observed_at_epoch": item.observed_at_epoch,
                "observed_detection_latency_seconds": item.observed_detection_latency_seconds,
                "observer_id": item.observer_id,
                "owner_id": item.owner_id,
                "required_control_ids": sorted(item.required_control_ids),
                "requirement_id": item.requirement_id,
                "route_id": item.route_id,
                "source_signature_valid": item.source_signature_valid,
            }
            for item in sorted(manifest.routes, key=lambda value: value.route_id)
        ],
        "schema_version": manifest.schema_version,
        "telemetry_plan_id": manifest.telemetry_plan_id,
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def telemetry_coverage_manifest_digest(manifest: TelemetryCoverageManifest) -> str:
    return hashlib.sha256(canonical_telemetry_coverage_manifest_bytes(manifest)).hexdigest()


def validate_policy(policy: TelemetryCoveragePolicy) -> None:
    hashes = (
        policy.expected_telemetry_plan_sha256,
        policy.expected_p7a_assessment_evidence_sha256,
        policy.expected_p7b_assessment_evidence_sha256,
        policy.expected_p7c_assessment_evidence_sha256,
        policy.expected_p7d_assessment_evidence_sha256,
        policy.expected_p7e_assessment_evidence_sha256,
        policy.expected_p7f_assessment_evidence_sha256,
        policy.expected_posture_evidence_sha256,
        policy.expected_control_catalog_sha256,
    )
    if (
        not policy.expected_telemetry_plan_id
        or not policy.expected_telemetry_plan_version
        or not all(is_sha256(value) for value in hashes)
        or not policy.required_requirement_ids
        or not policy.required_node_ids
        or not policy.required_route_ids
        or not policy.trusted_owner_ids
        or not policy.trusted_observer_ids
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
        or policy.max_observation_age_seconds <= 0
    ):
        reject(TelemetryBlindSpotRejectReason.POLICY_INVALID, "telemetry coverage policy metadata is invalid")

    requirement_maps = (
        policy.expected_event_class_by_requirement,
        policy.minimum_severity_by_requirement,
        policy.expected_source_kind_by_requirement,
        policy.expected_source_object_ids_by_requirement,
        policy.expected_required_field_ids_by_requirement,
        policy.expected_requires_alert_by_requirement,
        policy.max_detection_latency_by_requirement,
        policy.required_fallback_scenario_ids_by_requirement,
    )
    if any(set(mapping) != set(policy.required_requirement_ids) for mapping in requirement_maps):
        reject(TelemetryBlindSpotRejectReason.POLICY_INVALID, "requirement policy maps must exactly cover required requirements")

    node_maps = (
        policy.expected_node_type,
        policy.expected_node_zone,
        policy.minimum_integrity_validation_capable,
        policy.minimum_append_only_capable,
        policy.minimum_alert_capable,
    )
    if any(set(mapping) != set(policy.required_node_ids) for mapping in node_maps):
        reject(TelemetryBlindSpotRejectReason.POLICY_INVALID, "node policy maps must exactly cover required nodes")

    route_maps = (
        policy.expected_requirement_by_route,
        policy.expected_node_ids_by_route,
        policy.expected_control_ids_by_route,
    )
    if any(set(mapping) != set(policy.required_route_ids) for mapping in route_maps):
        reject(TelemetryBlindSpotRejectReason.POLICY_INVALID, "route policy maps must exactly cover required routes")
    requirement_route_counts = {requirement_id: 0 for requirement_id in policy.required_requirement_ids}
    for route_id, requirement_id in policy.expected_requirement_by_route.items():
        if requirement_id not in requirement_route_counts:
            reject(TelemetryBlindSpotRejectReason.POLICY_INVALID, "route references non-required telemetry requirement", route_id=route_id)
        requirement_route_counts[requirement_id] += 1
    if any(count != 1 for count in requirement_route_counts.values()):
        reject(TelemetryBlindSpotRejectReason.POLICY_INVALID, "every telemetry requirement must have exactly one policy-owned route")
    if any(value <= 0 for value in policy.max_detection_latency_by_requirement.values()):
        reject(TelemetryBlindSpotRejectReason.POLICY_INVALID, "detection-latency bounds must be positive")


def _verified(value: object, *attributes: str) -> bool:
    return all(bool(getattr(value, attribute, False)) for attribute in attributes)


def _digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def validate_upstreams(
    policy: TelemetryCoveragePolicy,
    p7a: VerifiedAttackPathAssessment,
    p7b: VerifiedPrivilegeEscalationAssessment,
    p7c: VerifiedDataExfiltrationAssessment,
    p7d: VerifiedSecretExposureAssessment,
    p7e: VerifiedDependencyTrustAssessment,
    p7f: VerifiedResilienceSecurityAssessment,
    posture: VerifiedSecurityPosture,
) -> tuple[dict[TelemetrySourceKind, frozenset[str]], dict[str, ControlStatus]]:
    if not _verified(p7a, "exact_architecture_binding_verified", "required_graph_coverage_verified"):
        reject(TelemetryBlindSpotRejectReason.P7A_ASSESSMENT_UNVERIFIED, "P7-A evidence is not fully verified")
    if _digest(p7a) != policy.expected_p7a_assessment_evidence_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.P7A_ASSESSMENT_MISMATCH, "P7-A evidence digest does not match telemetry policy")

    if not _verified(p7b, "exact_architecture_binding_verified", "exact_p7a_assessment_binding_verified"):
        reject(TelemetryBlindSpotRejectReason.P7B_ASSESSMENT_UNVERIFIED, "P7-B evidence is not fully verified")
    if _digest(p7b) != policy.expected_p7b_assessment_evidence_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.P7B_ASSESSMENT_MISMATCH, "P7-B evidence digest does not match telemetry policy")

    if not _verified(p7c, "exact_architecture_binding_verified", "exact_p7a_assessment_binding_verified", "exact_p7b_assessment_binding_verified", "exact_p6d_posture_binding_verified"):
        reject(TelemetryBlindSpotRejectReason.P7C_ASSESSMENT_UNVERIFIED, "P7-C evidence is not fully verified")
    if _digest(p7c) != policy.expected_p7c_assessment_evidence_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.P7C_ASSESSMENT_MISMATCH, "P7-C evidence digest does not match telemetry policy")

    if not _verified(p7d, "exact_architecture_binding_verified", "exact_p7a_assessment_binding_verified", "exact_p7b_assessment_binding_verified", "exact_p7c_assessment_binding_verified", "exact_p6d_posture_binding_verified"):
        reject(TelemetryBlindSpotRejectReason.P7D_ASSESSMENT_UNVERIFIED, "P7-D evidence is not fully verified")
    if _digest(p7d) != policy.expected_p7d_assessment_evidence_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.P7D_ASSESSMENT_MISMATCH, "P7-D evidence digest does not match telemetry policy")

    if not _verified(p7e, "exact_dependency_graph_binding_verified", "exact_p7a_assessment_binding_verified", "exact_p7b_assessment_binding_verified", "exact_p7c_assessment_binding_verified", "exact_p7d_assessment_binding_verified", "exact_p6d_posture_binding_verified", "destination_identity_policy_pinned", "transport_auth_policy_pinned", "egress_scope_policy_pinned"):
        reject(TelemetryBlindSpotRejectReason.P7E_ASSESSMENT_UNVERIFIED, "P7-E evidence is not fully verified")
    if _digest(p7e) != policy.expected_p7e_assessment_evidence_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.P7E_ASSESSMENT_MISMATCH, "P7-E evidence digest does not match telemetry policy")

    if not _verified(p7f, "exact_resilience_plan_binding_verified", "exact_p7e_assessment_binding_verified", "exact_p6d_posture_binding_verified", "failure_states_policy_pinned", "fallback_routes_policy_pinned", "security_degradation_derived_from_evidence"):
        reject(TelemetryBlindSpotRejectReason.P7F_ASSESSMENT_UNVERIFIED, "P7-F evidence is not fully verified")
    if _digest(p7f) != policy.expected_p7f_assessment_evidence_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.P7F_ASSESSMENT_MISMATCH, "P7-F evidence digest does not match telemetry policy")

    if (
        not bool(getattr(posture, "exact_release_identity_verified", False))
        or not bool(getattr(posture, "exact_upstream_evidence_binding_verified", False))
        or not bool(getattr(posture, "control_catalog_verified", False))
        or not bool(getattr(posture, "status_derived_from_evidence", False))
    ):
        reject(TelemetryBlindSpotRejectReason.POSTURE_UNVERIFIED, "P6-D posture evidence is not fully verified")
    if str(getattr(posture, "posture_evidence_sha256", "")).casefold() != policy.expected_posture_evidence_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.POSTURE_DIGEST_MISMATCH, "P6-D posture digest does not match telemetry policy")
    if str(getattr(posture, "control_catalog_sha256", "")).casefold() != policy.expected_control_catalog_sha256.casefold():
        reject(TelemetryBlindSpotRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog does not match telemetry policy")

    statuses: dict[str, ControlStatus] = {}
    assessments = tuple(getattr(posture, "assessments", ()))
    for assessment in assessments:
        control_id = str(getattr(assessment, "control_id", ""))
        status = getattr(assessment, "status", None)
        if not control_id or control_id in statuses or not isinstance(status, ControlStatus):
            reject(TelemetryBlindSpotRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control evidence is duplicate or malformed", control_id=control_id or None)
        statuses[control_id] = status
    if set(getattr(posture, "satisfied_control_ids", ())) != {key for key, value in statuses.items() if value == ControlStatus.SATISFIED}:
        reject(TelemetryBlindSpotRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D satisfied-control summary is inconsistent")
    if set(getattr(posture, "exceptioned_control_ids", ())) != {key for key, value in statuses.items() if value == ControlStatus.EXCEPTIONED}:
        reject(TelemetryBlindSpotRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D exception summary is inconsistent")
    if set(getattr(posture, "not_evaluated_control_ids", ())) != {key for key, value in statuses.items() if value == ControlStatus.NOT_EVALUATED}:
        reject(TelemetryBlindSpotRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D not-evaluated summary is inconsistent")

    source_objects = {
        TelemetrySourceKind.P7A_ATTACK_PATH: frozenset(str(getattr(item, "path_id", "")) for item in getattr(p7a, "paths", ()) if getattr(item, "path_id", "")),
        TelemetrySourceKind.P7B_PRIVILEGE_PATH: frozenset(str(getattr(item, "path_id", "")) for item in getattr(p7b, "paths", ()) if getattr(item, "path_id", "")),
        TelemetrySourceKind.P7C_DATA_PATH: frozenset(str(getattr(item, "path_id", "")) for item in getattr(p7c, "paths", ()) if getattr(item, "path_id", "")),
        TelemetrySourceKind.P7D_SECRET_PATH: frozenset(str(getattr(item, "path_id", "")) for item in getattr(p7d, "paths", ()) if getattr(item, "path_id", "")),
        TelemetrySourceKind.P7E_DEPENDENCY_PATH: frozenset(str(getattr(item, "path_id", "")) for item in getattr(p7e, "paths", ()) if getattr(item, "path_id", "")),
        TelemetrySourceKind.P7F_FAILURE_SCENARIO: frozenset(str(getattr(item, "scenario_id", "")) for item in getattr(p7f, "scenarios", ()) if getattr(item, "scenario_id", "")),
        TelemetrySourceKind.P6D_CONTROL: frozenset(statuses),
    }
    return source_objects, statuses


def validate_manifest(
    policy: TelemetryCoveragePolicy,
    request: TelemetryCoverageRequest,
    manifest: TelemetryCoverageManifest,
    source_objects: Mapping[TelemetrySourceKind, frozenset[str]],
    statuses: Mapping[str, ControlStatus],
) -> tuple[dict[str, TelemetryEventRequirement], dict[str, TelemetryNode], dict[str, TelemetryRoute], str]:
    if (
        manifest.schema_version != P7G_TELEMETRY_MANIFEST_SCHEMA_VERSION
        or not manifest.telemetry_plan_id
        or not manifest.version
        or not all(
            is_sha256(value)
            for value in (
                manifest.p7a_assessment_evidence_sha256,
                manifest.p7b_assessment_evidence_sha256,
                manifest.p7c_assessment_evidence_sha256,
                manifest.p7d_assessment_evidence_sha256,
                manifest.p7e_assessment_evidence_sha256,
                manifest.p7f_assessment_evidence_sha256,
                manifest.posture_evidence_sha256,
            )
        )
    ):
        reject(TelemetryBlindSpotRejectReason.MANIFEST_INVALID, "telemetry coverage manifest metadata is invalid")

    actual_sha = telemetry_coverage_manifest_digest(manifest)
    if (
        not hmac.compare_digest(actual_sha, policy.expected_telemetry_plan_sha256.casefold())
        or not hmac.compare_digest(actual_sha, request.telemetry_plan_sha256.casefold())
    ):
        reject(TelemetryBlindSpotRejectReason.MANIFEST_DIGEST_MISMATCH, "telemetry plan digest does not match request/policy")
    if manifest.telemetry_plan_id != policy.expected_telemetry_plan_id or manifest.version != policy.expected_telemetry_plan_version:
        reject(TelemetryBlindSpotRejectReason.MANIFEST_INVALID, "telemetry plan identity/version does not match policy")
    manifest_pins = (
        (manifest.p7a_assessment_evidence_sha256, policy.expected_p7a_assessment_evidence_sha256),
        (manifest.p7b_assessment_evidence_sha256, policy.expected_p7b_assessment_evidence_sha256),
        (manifest.p7c_assessment_evidence_sha256, policy.expected_p7c_assessment_evidence_sha256),
        (manifest.p7d_assessment_evidence_sha256, policy.expected_p7d_assessment_evidence_sha256),
        (manifest.p7e_assessment_evidence_sha256, policy.expected_p7e_assessment_evidence_sha256),
        (manifest.p7f_assessment_evidence_sha256, policy.expected_p7f_assessment_evidence_sha256),
        (manifest.posture_evidence_sha256, policy.expected_posture_evidence_sha256),
    )
    if any(left.casefold() != right.casefold() for left, right in manifest_pins):
        reject(TelemetryBlindSpotRejectReason.MANIFEST_INVALID, "telemetry manifest upstream evidence pins differ from policy")
    age = request.evaluated_at_epoch - manifest.created_at_epoch
    if age > policy.max_manifest_age_seconds:
        reject(TelemetryBlindSpotRejectReason.MANIFEST_STALE, "telemetry manifest is stale")
    if age < -policy.max_future_skew_seconds:
        reject(TelemetryBlindSpotRejectReason.MANIFEST_FUTURE, "telemetry manifest timestamp is too far in the future")

    requirements: dict[str, TelemetryEventRequirement] = {}
    for item in manifest.requirements:
        if item.requirement_id in requirements:
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_DUPLICATE, "duplicate telemetry requirement ID", requirement_id=item.requirement_id)
        requirements[item.requirement_id] = item
    if set(requirements) != set(policy.required_requirement_ids):
        reject(TelemetryBlindSpotRejectReason.REQUIREMENT_COVERAGE_MISMATCH, "telemetry requirement coverage differs from policy")
    for requirement_id, item in requirements.items():
        if item.owner_id not in policy.trusted_owner_ids:
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_OWNER_UNTRUSTED, "telemetry requirement owner is untrusted", requirement_id=requirement_id)
        if item.event_class != policy.expected_event_class_by_requirement[requirement_id]:
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_CLASS_DRIFT, "telemetry event class differs from policy", requirement_id=requirement_id)
        if severity_rank(item.severity) < severity_rank(policy.minimum_severity_by_requirement[requirement_id]):
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_SEVERITY_DOWNGRADE, "telemetry severity was downgraded", requirement_id=requirement_id)
        if item.source_kind != policy.expected_source_kind_by_requirement[requirement_id]:
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_SOURCE_KIND_DRIFT, "telemetry source kind differs from policy", requirement_id=requirement_id)
        if set(item.source_object_ids) != set(policy.expected_source_object_ids_by_requirement[requirement_id]):
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_SOURCE_OBJECT_DRIFT, "telemetry source-object binding differs from policy", requirement_id=requirement_id)
        if not set(item.source_object_ids).issubset(source_objects[item.source_kind]):
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_SOURCE_OBJECT_UNKNOWN, "telemetry requirement references source object absent from exact upstream evidence", requirement_id=requirement_id)
        if set(item.required_field_ids) != set(policy.expected_required_field_ids_by_requirement[requirement_id]):
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_FIELDS_DRIFT, "telemetry required fields differ from policy", requirement_id=requirement_id)
        if item.requires_alert != policy.expected_requires_alert_by_requirement[requirement_id]:
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_ALERT_DRIFT, "telemetry alert requirement differs from policy", requirement_id=requirement_id)
        if item.max_detection_latency_seconds != policy.max_detection_latency_by_requirement[requirement_id]:
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_LATENCY_DRIFT, "telemetry detection-latency objective differs from policy", requirement_id=requirement_id)

    nodes: dict[str, TelemetryNode] = {}
    for item in manifest.nodes:
        if item.node_id in nodes:
            reject(TelemetryBlindSpotRejectReason.NODE_DUPLICATE, "duplicate telemetry node ID", node_id=item.node_id)
        nodes[item.node_id] = item
    if set(nodes) != set(policy.required_node_ids):
        reject(TelemetryBlindSpotRejectReason.NODE_COVERAGE_MISMATCH, "telemetry node coverage differs from policy")
    for node_id, item in nodes.items():
        if item.owner_id not in policy.trusted_owner_ids:
            reject(TelemetryBlindSpotRejectReason.NODE_OWNER_UNTRUSTED, "telemetry node owner is untrusted", node_id=node_id)
        if item.node_type != policy.expected_node_type[node_id]:
            reject(TelemetryBlindSpotRejectReason.NODE_TYPE_DRIFT, "telemetry node type differs from policy", node_id=node_id)
        if item.trust_zone != policy.expected_node_zone[node_id]:
            reject(TelemetryBlindSpotRejectReason.NODE_ZONE_DRIFT, "telemetry node trust zone differs from policy", node_id=node_id)
        if policy.minimum_integrity_validation_capable[node_id] and not item.integrity_validation_capable:
            reject(TelemetryBlindSpotRejectReason.NODE_INTEGRITY_CAPABILITY_DRIFT, "telemetry node lost required integrity-validation capability", node_id=node_id)
        if policy.minimum_append_only_capable[node_id] and not item.append_only_capable:
            reject(TelemetryBlindSpotRejectReason.NODE_APPEND_ONLY_CAPABILITY_DRIFT, "telemetry node lost required append-only capability", node_id=node_id)
        if policy.minimum_alert_capable[node_id] and not item.alert_capable:
            reject(TelemetryBlindSpotRejectReason.NODE_ALERT_CAPABILITY_DRIFT, "telemetry node lost required alert capability", node_id=node_id)

    routes: dict[str, TelemetryRoute] = {}
    route_by_requirement: dict[str, str] = {}
    all_fallback_scenarios = source_objects[TelemetrySourceKind.P7F_FAILURE_SCENARIO]
    for item in manifest.routes:
        if item.route_id in routes:
            reject(TelemetryBlindSpotRejectReason.ROUTE_DUPLICATE, "duplicate telemetry route ID", route_id=item.route_id)
        routes[item.route_id] = item
    if set(routes) != set(policy.required_route_ids):
        reject(TelemetryBlindSpotRejectReason.ROUTE_COVERAGE_MISMATCH, "telemetry route coverage differs from policy")
    for route_id, item in routes.items():
        if item.owner_id not in policy.trusted_owner_ids:
            reject(TelemetryBlindSpotRejectReason.ROUTE_OWNER_UNTRUSTED, "telemetry route owner is untrusted", route_id=route_id)
        if item.observer_id not in policy.trusted_observer_ids:
            reject(TelemetryBlindSpotRejectReason.ROUTE_OBSERVER_UNTRUSTED, "telemetry observation is not from a trusted observer", route_id=route_id)
        if item.requirement_id != policy.expected_requirement_by_route[route_id] or item.requirement_id not in requirements:
            reject(TelemetryBlindSpotRejectReason.ROUTE_REQUIREMENT_DRIFT, "telemetry route requirement binding differs from policy", route_id=route_id)
        if item.requirement_id in route_by_requirement:
            reject(TelemetryBlindSpotRejectReason.REQUIREMENT_ROUTE_COVERAGE_MISMATCH, "telemetry requirement has more than one route", requirement_id=item.requirement_id)
        route_by_requirement[item.requirement_id] = route_id
        if tuple(item.node_ids) != tuple(policy.expected_node_ids_by_route[route_id]):
            reject(TelemetryBlindSpotRejectReason.ROUTE_NODE_DRIFT, "telemetry route node sequence differs from policy", route_id=route_id)
        if any(node_id not in nodes for node_id in item.node_ids):
            reject(TelemetryBlindSpotRejectReason.ROUTE_NODE_UNKNOWN, "telemetry route references unknown node", route_id=route_id)
        route_nodes = tuple(nodes[node_id] for node_id in item.node_ids)
        if len(route_nodes) < 4 or route_nodes[0].node_type != TelemetryNodeType.PRODUCER or route_nodes[1].node_type != TelemetryNodeType.COLLECTOR or not any(node.node_type == TelemetryNodeType.PROCESSOR for node in route_nodes) or not any(node.node_type == TelemetryNodeType.AUDIT_SINK for node in route_nodes):
            reject(TelemetryBlindSpotRejectReason.ROUTE_SHAPE_INVALID, "telemetry route must traverse producer, collector, processor, and audit sink", route_id=route_id)
        requirement = requirements[item.requirement_id]
        if requirement.requires_alert and not any(node.node_type == TelemetryNodeType.ALERT_SINK for node in route_nodes):
            reject(TelemetryBlindSpotRejectReason.ROUTE_SHAPE_INVALID, "alert-required telemetry route lacks alert sink", route_id=route_id)
        if set(item.required_control_ids) != set(policy.expected_control_ids_by_route[route_id]):
            reject(TelemetryBlindSpotRejectReason.ROUTE_CONTROL_DRIFT, "telemetry route controls differ from policy", route_id=route_id)
        for control_id in item.required_control_ids:
            if control_id not in statuses:
                reject(TelemetryBlindSpotRejectReason.ROUTE_CONTROL_UNKNOWN, "telemetry route references unknown P6-D control", route_id=route_id, control_id=control_id)
        observation_age = request.evaluated_at_epoch - item.observed_at_epoch
        if observation_age > policy.max_observation_age_seconds:
            reject(TelemetryBlindSpotRejectReason.ROUTE_OBSERVATION_STALE, "telemetry route observation is stale", route_id=route_id)
        if observation_age < -policy.max_future_skew_seconds:
            reject(TelemetryBlindSpotRejectReason.ROUTE_OBSERVATION_FUTURE, "telemetry route observation is too far in the future", route_id=route_id)
        if not set(item.covered_fallback_scenario_ids).issubset(all_fallback_scenarios):
            reject(TelemetryBlindSpotRejectReason.ROUTE_FALLBACK_SCOPE_DRIFT, "telemetry route claims coverage for an unknown P7-F scenario", route_id=route_id)
        if not set(item.dropped_field_ids).issubset(set(requirement.required_field_ids)):
            reject(TelemetryBlindSpotRejectReason.ROUTE_DROPPED_FIELD_UNKNOWN, "telemetry route dropped-field evidence references a field outside the requirement", route_id=route_id)

    if set(route_by_requirement) != set(requirements):
        reject(TelemetryBlindSpotRejectReason.REQUIREMENT_ROUTE_COVERAGE_MISMATCH, "every telemetry requirement must have exactly one route")
    return requirements, nodes, routes, actual_sha
