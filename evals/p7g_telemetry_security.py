from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from typing import Callable

from aegis.architecture.telemetry_security import (
    SecurityTelemetryIntegrityAnalyzer,
    TelemetryBlindSpotRejected,
    TelemetryEventClass,
    TelemetryNodeType,
    TelemetrySeverity,
    TelemetrySourceKind,
    canonical_telemetry_coverage_manifest_bytes,
    telemetry_coverage_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus
from aegis.vulnerable.telemetry_security import VulnerableMonitoringCoverageReporter

from .p7g_fixture import (
    CTRL_ALERT_ROUTING,
    CTRL_TELEMETRY_FAILOVER,
    CTRL_TELEMETRY_INTEGRITY,
    NOW,
    build_fixture,
)


Mutation = Callable[[dict[str, object]], dict[str, object]]


def _with(fixture: dict[str, object], key: str, value: object) -> dict[str, object]:
    changed = dict(fixture)
    changed[key] = value
    return changed


def _copy_ns(fixture: dict[str, object], key: str, **changes: object) -> dict[str, object]:
    item = copy.copy(fixture[key])
    for name, value in changes.items():
        setattr(item, name, value)
    return _with(fixture, key, item)


def _policy_map(policy: object, field: str, key: str, value: object) -> object:
    mapping = dict(getattr(policy, field))
    mapping[key] = value
    return replace(policy, **{field: mapping})


def _rebind_manifest(fixture: dict[str, object], manifest: object) -> dict[str, object]:
    digest = telemetry_coverage_manifest_digest(manifest)
    changed = dict(fixture)
    changed["manifest"] = manifest
    changed["policy"] = replace(changed["policy"], expected_telemetry_plan_sha256=digest)
    changed["request"] = replace(changed["request"], telemetry_plan_sha256=digest)
    return changed


def _replace_requirement(fixture: dict[str, object], requirement_id: str, **changes: object) -> dict[str, object]:
    manifest = fixture["manifest"]
    requirements = tuple(replace(item, **changes) if item.requirement_id == requirement_id else item for item in manifest.requirements)
    return _rebind_manifest(fixture, replace(manifest, requirements=requirements))


def _replace_node(fixture: dict[str, object], node_id: str, **changes: object) -> dict[str, object]:
    manifest = fixture["manifest"]
    nodes = tuple(replace(item, **changes) if item.node_id == node_id else item for item in manifest.nodes)
    return _rebind_manifest(fixture, replace(manifest, nodes=nodes))


def _replace_route(fixture: dict[str, object], route_id: str, **changes: object) -> dict[str, object]:
    manifest = fixture["manifest"]
    routes = tuple(replace(item, **changes) if item.route_id == route_id else item for item in manifest.routes)
    return _rebind_manifest(fixture, replace(manifest, routes=routes))


def _unknown_requirement_source(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_requirement(fixture, "req-data-egress", source_object_ids=("p7c-path-unknown",))
    policy = _policy_map(changed["policy"], "expected_source_object_ids_by_requirement", "req-data-egress", frozenset({"p7c-path-unknown"}))
    return _with(changed, "policy", policy)


def _unknown_route_control(fixture: dict[str, object]) -> dict[str, object]:
    route = next(item for item in fixture["manifest"].routes if item.route_id == "route-tool-execution")
    controls = tuple(sorted(set(route.required_control_ids) | {"CTRL-UNKNOWN"}))
    changed = _replace_route(fixture, "route-tool-execution", required_control_ids=controls)
    policy = _policy_map(changed["policy"], "expected_control_ids_by_route", "route-tool-execution", frozenset(controls))
    return _with(changed, "policy", policy)


def _remove_upstream_object(fixture: dict[str, object], key: str, object_id: str, attribute: str = "paths") -> dict[str, object]:
    upstream = copy.copy(fixture[key])
    values = tuple(item for item in getattr(upstream, attribute) if getattr(item, "path_id", getattr(item, "scenario_id", None)) != object_id)
    setattr(upstream, attribute, values)
    return _with(fixture, key, upstream)


def _duplicate_posture_control(fixture: dict[str, object]) -> dict[str, object]:
    posture = copy.copy(fixture["posture"])
    posture.assessments = posture.assessments + (posture.assessments[0],)
    return _with(fixture, "posture", posture)


def _set_posture_status(fixture: dict[str, object], control_id: str, status: ControlStatus) -> dict[str, object]:
    posture = copy.copy(fixture["posture"])
    assessments = []
    for assessment in posture.assessments:
        if assessment.control_id == control_id:
            assessments.append(type(assessment)(control_id=assessment.control_id, status=status))
        else:
            assessments.append(assessment)
    posture.assessments = tuple(assessments)
    status_map = {item.control_id: item.status for item in posture.assessments}
    posture.satisfied_control_ids = tuple(sorted(key for key, value in status_map.items() if value == ControlStatus.SATISFIED))
    posture.exceptioned_control_ids = tuple(sorted(key for key, value in status_map.items() if value == ControlStatus.EXCEPTIONED))
    posture.not_evaluated_control_ids = tuple(sorted(key for key, value in status_map.items() if value == ControlStatus.NOT_EVALUATED))
    return _with(fixture, "posture", posture)


def adversarial_cases() -> list[tuple[str, Mutation]]:
    return [
        ("request plan id substitution", lambda f: _with(f, "request", replace(f["request"], telemetry_plan_id="attacker-plan"))),
        ("request plan version substitution", lambda f: _with(f, "request", replace(f["request"], telemetry_plan_version="0"))),
        ("request plan digest substitution", lambda f: _with(f, "request", replace(f["request"], telemetry_plan_sha256="0" * 64))),
        ("request P7-A evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7a_assessment_evidence_sha256="1" * 64))),
        ("request P7-B evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7b_assessment_evidence_sha256="2" * 64))),
        ("request P7-C evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7c_assessment_evidence_sha256="3" * 64))),
        ("request P7-D evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7d_assessment_evidence_sha256="4" * 64))),
        ("request P7-E evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7e_assessment_evidence_sha256="5" * 64))),
        ("request P7-F evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7f_assessment_evidence_sha256="6" * 64))),
        ("request posture evidence substitution", lambda f: _with(f, "request", replace(f["request"], posture_evidence_sha256="7" * 64))),
        ("request requirement scope shrink", lambda f: _with(f, "request", replace(f["request"], requirement_ids=f["request"].requirement_ids[:-1]))),
        ("forged caller blind-spot summary", lambda f: _with(f, "request", replace(f["request"], declared_blind_spot_requirement_ids=("forged",)))),
        ("forged caller blind-spot risk", lambda f: _with(f, "request", replace(f["request"], declared_max_blind_spot_risk_score=999))),
        ("manifest schema substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], schema_version="attacker-schema"))),
        ("manifest plan id substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], telemetry_plan_id="attacker-plan"))),
        ("manifest version substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], version="0"))),
        ("manifest P7-C evidence substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], p7c_assessment_evidence_sha256="8" * 64))),
        ("manifest P7-F evidence substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], p7f_assessment_evidence_sha256="9" * 64))),
        ("stale telemetry manifest", lambda f: _rebind_manifest(f, replace(f["manifest"], created_at_epoch=NOW - 200_000))),
        ("future telemetry manifest", lambda f: _rebind_manifest(f, replace(f["manifest"], created_at_epoch=NOW + 1_000))),
        ("requirement deletion", lambda f: _rebind_manifest(f, replace(f["manifest"], requirements=f["manifest"].requirements[:-1]))),
        ("requirement duplication", lambda f: _rebind_manifest(f, replace(f["manifest"], requirements=f["manifest"].requirements + (f["manifest"].requirements[0],)))),
        ("requirement untrusted owner", lambda f: _replace_requirement(f, "req-secret-access", owner_id="attacker")),
        ("requirement event-class drift", lambda f: _replace_requirement(f, "req-secret-access", event_class=TelemetryEventClass.DATA_ACCESS)),
        ("requirement severity downgrade", lambda f: _replace_requirement(f, "req-secret-access", severity=TelemetrySeverity.LOW)),
        ("requirement source-kind drift", lambda f: _replace_requirement(f, "req-secret-access", source_kind=TelemetrySourceKind.P7C_DATA_PATH)),
        ("requirement source-object drift", lambda f: _replace_requirement(f, "req-secret-access", source_object_ids=("p7d-path-model-signing",))),
        ("requirement unknown source-object", _unknown_requirement_source),
        ("requirement field drift", lambda f: _replace_requirement(f, "req-secret-access", required_field_ids=("event_id",))),
        ("requirement alert drift", lambda f: _replace_requirement(f, "req-secret-access", requires_alert=False)),
        ("requirement latency drift", lambda f: _replace_requirement(f, "req-secret-access", max_detection_latency_seconds=999)),
        ("node deletion", lambda f: _rebind_manifest(f, replace(f["manifest"], nodes=f["manifest"].nodes[:-1]))),
        ("node duplication", lambda f: _rebind_manifest(f, replace(f["manifest"], nodes=f["manifest"].nodes + (f["manifest"].nodes[0],)))),
        ("node untrusted owner", lambda f: _replace_node(f, "node-security-collector", owner_id="attacker")),
        ("node type drift", lambda f: _replace_node(f, "node-security-collector", node_type=TelemetryNodeType.PRODUCER)),
        ("node trust-zone drift", lambda f: _replace_node(f, "node-security-collector", trust_zone="internet")),
        ("collector loses integrity-validation capability", lambda f: _replace_node(f, "node-security-collector", integrity_validation_capable=False)),
        ("audit sink loses append-only capability", lambda f: _replace_node(f, "node-audit-sink", append_only_capable=False)),
        ("alert sink loses alert capability", lambda f: _replace_node(f, "node-alert-sink", alert_capable=False)),
        ("route deletion", lambda f: _rebind_manifest(f, replace(f["manifest"], routes=f["manifest"].routes[:-1]))),
        ("route duplication", lambda f: _rebind_manifest(f, replace(f["manifest"], routes=f["manifest"].routes + (f["manifest"].routes[0],)))),
        ("route untrusted owner", lambda f: _replace_route(f, "route-secret-access", owner_id="attacker")),
        ("route untrusted observer", lambda f: _replace_route(f, "route-secret-access", observer_id="attacker")),
        ("route requirement drift", lambda f: _replace_route(f, "route-secret-access", requirement_id="req-data-egress")),
        ("route node-sequence drift", lambda f: _replace_route(f, "route-secret-access", node_ids=("node-secret-producer", "node-security-processor", "node-security-collector", "node-audit-sink", "node-alert-sink"))),
        ("route unknown node", lambda f: _replace_route(f, "route-secret-access", node_ids=("node-secret-producer", "node-security-collector", "node-security-processor", "node-unknown", "node-alert-sink"))),
        ("route control deletion", lambda f: _replace_route(f, "route-secret-access", required_control_ids=tuple(control for control in next(item for item in f["manifest"].routes if item.route_id == "route-secret-access").required_control_ids if control != CTRL_TELEMETRY_INTEGRITY))),
        ("route unknown control", _unknown_route_control),
        ("route observation stale", lambda f: _replace_route(f, "route-secret-access", observed_at_epoch=NOW - 10_000)),
        ("route observation future", lambda f: _replace_route(f, "route-secret-access", observed_at_epoch=NOW + 1_000)),
        ("route unknown fallback scenario", lambda f: _replace_route(f, "route-failover", covered_fallback_scenario_ids=("scenario-unknown",))),
        ("route dropped unknown field", lambda f: _replace_route(f, "route-secret-access", dropped_field_ids=("not-required",))),
        ("P7-A verification downgrade", lambda f: _copy_ns(f, "p7a", exact_architecture_binding_verified=False)),
        ("P7-A evidence digest substitution", lambda f: _copy_ns(f, "p7a", assessment_evidence_sha256="a" * 64)),
        ("P7-A required source path omitted", lambda f: _remove_upstream_object(f, "p7a", "p7a-path-external-tool")),
        ("P7-B verification downgrade", lambda f: _copy_ns(f, "p7b", exact_p7a_assessment_binding_verified=False)),
        ("P7-B evidence digest substitution", lambda f: _copy_ns(f, "p7b", assessment_evidence_sha256="b" * 64)),
        ("P7-C verification downgrade", lambda f: _copy_ns(f, "p7c", exact_p6d_posture_binding_verified=False)),
        ("P7-C evidence digest substitution", lambda f: _copy_ns(f, "p7c", assessment_evidence_sha256="c" * 64)),
        ("P7-D verification downgrade", lambda f: _copy_ns(f, "p7d", exact_p7c_assessment_binding_verified=False)),
        ("P7-D evidence digest substitution", lambda f: _copy_ns(f, "p7d", assessment_evidence_sha256="d" * 64)),
        ("P7-E verification downgrade", lambda f: _copy_ns(f, "p7e", destination_identity_policy_pinned=False)),
        ("P7-E evidence digest substitution", lambda f: _copy_ns(f, "p7e", assessment_evidence_sha256="e" * 64)),
        ("P7-F verification downgrade", lambda f: _copy_ns(f, "p7f", fallback_routes_policy_pinned=False)),
        ("P7-F evidence digest substitution", lambda f: _copy_ns(f, "p7f", assessment_evidence_sha256="f" * 64)),
        ("P7-F required scenario omitted", lambda f: _remove_upstream_object(f, "p7f", "scenario-tool-unavailable", attribute="scenarios")),
        ("posture verification downgrade", lambda f: _copy_ns(f, "posture", status_derived_from_evidence=False)),
        ("posture digest substitution", lambda f: _copy_ns(f, "posture", posture_evidence_sha256="0" * 64)),
        ("control catalog substitution", lambda f: _copy_ns(f, "posture", control_catalog_sha256="1" * 64)),
        ("posture satisfied summary forgery", lambda f: _copy_ns(f, "posture", satisfied_control_ids=())),
        ("posture duplicate control evidence", _duplicate_posture_control),
        ("caller masks active integrity-control exception", lambda f: _set_posture_status(f, CTRL_TELEMETRY_INTEGRITY, ControlStatus.EXCEPTIONED)),
        ("caller masks not-evaluated alert routing", lambda f: _set_posture_status(f, CTRL_ALERT_ROUTING, ControlStatus.NOT_EVALUATED)),
        ("caller masks invalid source signature", lambda f: _replace_route(f, "route-secret-access", source_signature_valid=False)),
        ("caller masks telemetry chain failure", lambda f: _replace_route(f, "route-model-release", chain_integrity_valid=False)),
        ("caller masks missing append-only acknowledgement", lambda f: _replace_route(f, "route-data-egress", append_only_acknowledged=False)),
        ("caller masks alert-path outage", lambda f: _replace_route(f, "route-secret-access", alert_path_operational=False)),
        ("caller masks detection latency breach", lambda f: _replace_route(f, "route-authorization", observed_detection_latency_seconds=999)),
        ("caller masks fallback observability gap", lambda f: _replace_route(f, "route-tool-execution", covered_fallback_scenario_ids=())),
        ("caller masks dropped required fields", lambda f: _replace_route(f, "route-data-egress", dropped_field_ids=("data_class",))),
    ]


def _evaluate(fixture: dict[str, object]) -> object:
    return SecurityTelemetryIntegrityAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["p7a"],
        fixture["p7b"],
        fixture["p7c"],
        fixture["p7d"],
        fixture["p7e"],
        fixture["p7f"],
        fixture["posture"],
    )


def run_evaluation() -> dict[str, object]:
    cases = adversarial_cases()
    vulnerable = VulnerableMonitoringCoverageReporter()
    vulnerable_success = 0
    hardened_success = 0
    for _, mutation in cases:
        fixture = mutation(build_fixture())
        if vulnerable.evaluate(
            declared_fully_monitored=True,
            declared_coverage_percent=100,
            declared_blind_spot_count=0,
            declared_max_blind_spot_risk_score=0,
        ).accepted:
            vulnerable_success += 1
        try:
            _evaluate(fixture)
        except TelemetryBlindSpotRejected:
            pass
        else:
            hardened_success += 1

    benign = (
        build_fixture(),
        build_fixture(exceptioned_control=CTRL_TELEMETRY_FAILOVER),
        build_fixture(route_overrides={"route-secret-access": {"alert_path_operational": False}}),
    )
    benign_accepted = 0
    for fixture in benign:
        try:
            _evaluate(fixture)
        except TelemetryBlindSpotRejected:
            continue
        benign_accepted += 1

    base = build_fixture()
    dataset_sha = hashlib.sha256(
        json.dumps([name for name, _ in cases], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    fixture_sha = hashlib.sha256(
        canonical_telemetry_coverage_manifest_bytes(base["manifest"])
        + base["policy"].expected_control_catalog_sha256.encode("ascii")
        + base["policy"].expected_p7f_assessment_evidence_sha256.encode("ascii")
    ).hexdigest()
    metrics = {
        "adversarial_cases": len(cases),
        "vulnerable_asr": f"{vulnerable_success}/{len(cases)}",
        "hardened_asr": f"{hardened_success}/{len(cases)}",
        "hardened_fpr": f"{3 - benign_accepted}/3",
        "safe_task_rate": f"{benign_accepted}/3",
        "telemetry_plan_sha256": telemetry_coverage_manifest_digest(base["manifest"]),
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
    }
    return {"metrics": metrics}


def main() -> int:
    result = run_evaluation()
    print(json.dumps(result, sort_keys=True, indent=2))
    metrics = result["metrics"]
    total = metrics["adversarial_cases"]
    return 0 if (
        metrics["vulnerable_asr"] == f"{total}/{total}"
        and metrics["hardened_asr"] == f"0/{total}"
        and metrics["hardened_fpr"] == "0/3"
        and metrics["safe_task_rate"] == "3/3"
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
