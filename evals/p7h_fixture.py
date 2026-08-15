from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Mapping

from aegis.architecture.control_plane_security import (
    AdministrativeChangeRoute,
    AdministrativeOperation,
    AdministrativePrincipal,
    AdministrativePrincipalType,
    ControlPlaneManifest,
    ControlPlanePolicy,
    ControlPlaneRequest,
    ControlPlaneResource,
    ControlPlaneResourceType,
    ControlPlaneSensitivity,
    control_plane_manifest_digest,
)

NOW = 2_200_100_000
CONTROL_PLANE_ID = "aegisdesk-security-control-plane"
CONTROL_PLANE_VERSION = "2026.08-p7h.1"

P7B_SHA = hashlib.sha256(b"p7b-for-p7h").hexdigest()
P7E_SHA = hashlib.sha256(b"p7e-for-p7h").hexdigest()
P7F_SHA = hashlib.sha256(b"p7f-for-p7h").hexdigest()
P7G_SHA = hashlib.sha256(b"p7g-for-p7h").hexdigest()
POSTURE_SHA = hashlib.sha256(b"posture-for-p7h").hexdigest()
CATALOG_SHA = hashlib.sha256(b"catalog-for-p7h").hexdigest()

CTRL_ADMIN_AUTHZ = "CTRL-ADMIN-AUTHZ"
CTRL_CHANGE_APPROVAL = "CTRL-CHANGE-APPROVAL"
CTRL_AUDIT_APPEND_ONLY = "CTRL-AUDIT-APPEND-ONLY"
CTRL_RELEASE_GATE = "CTRL-RELEASE-GATE"
CTRL_TELEMETRY_INTEGRITY = "CTRL-TELEMETRY-INTEGRITY"
CTRL_EGRESS_POLICY = "CTRL-EGRESS-POLICY"
CTRL_FALLBACK_AUTHZ = "CTRL-FALLBACK-AUTHZ"
CTRL_TRUST_STORE = "CTRL-TRUST-STORE"
CTRL_ASSURANCE_GATE = "CTRL-ASSURANCE-GATE"
CTRL_WAIVER_GOVERNANCE = "CTRL-WAIVER-GOVERNANCE"
ALL_CONTROLS = (
    CTRL_ADMIN_AUTHZ,
    CTRL_CHANGE_APPROVAL,
    CTRL_AUDIT_APPEND_ONLY,
    CTRL_RELEASE_GATE,
    CTRL_TELEMETRY_INTEGRITY,
    CTRL_EGRESS_POLICY,
    CTRL_FALLBACK_AUTHZ,
    CTRL_TRUST_STORE,
    CTRL_ASSURANCE_GATE,
    CTRL_WAIVER_GOVERNANCE,
)

REQ_CONTROL_CHANGE = "req-control-change"
REQ_PRIVILEGE_CHANGE = "req-privilege-change"
REQ_MODEL_RELEASE = "req-model-release"
REQ_DEPENDENCY_EGRESS = "req-dependency-egress"
REQ_FAILOVER = "req-failover"
TELEMETRY_REQUIREMENTS = (
    REQ_CONTROL_CHANGE,
    REQ_PRIVILEGE_CHANGE,
    REQ_MODEL_RELEASE,
    REQ_DEPENDENCY_EGRESS,
    REQ_FAILOVER,
)

P7B_PATHS = (
    "p7b-admin-authz",
    "p7b-admin-release",
    "p7b-admin-observability",
    "p7b-admin-network",
    "p7b-admin-assurance",
    "p7b-admin-breakglass",
    "p7b-target-authz-policy",
)
P7E_PATHS = ("p7e-path-model-egress", "p7e-path-tool-egress")
P7F_SCENARIOS = ("scenario-model-unavailable", "scenario-tool-unavailable")


def _path(path_id: str, *, exposed: bool = False) -> SimpleNamespace:
    return SimpleNamespace(path_id=path_id, exposed=exposed)


def _scenario(scenario_id: str, *, exposed: bool = False) -> SimpleNamespace:
    return SimpleNamespace(scenario_id=scenario_id, exposed=exposed)


def _requirement(requirement_id: str, *, blind_spot: bool = False) -> SimpleNamespace:
    return SimpleNamespace(requirement_id=requirement_id, blind_spot=blind_spot)


def make_upstreams(
    *,
    exposed_p7b_paths: frozenset[str] = frozenset(),
    exposed_p7e_paths: frozenset[str] = frozenset(),
    exposed_p7f_scenarios: frozenset[str] = frozenset(),
    blind_spot_requirements: frozenset[str] = frozenset(),
    statuses: Mapping[str, str] | None = None,
) -> dict[str, object]:
    control_statuses = dict(statuses or {control_id: "satisfied" for control_id in ALL_CONTROLS})
    p7b = SimpleNamespace(
        assessment_evidence_sha256=P7B_SHA,
        exact_identity_graph_binding_verified=True,
        privilege_amplification_derived_from_evidence=True,
        paths=tuple(_path(value, exposed=value in exposed_p7b_paths) for value in P7B_PATHS),
    )
    p7e = SimpleNamespace(
        assessment_evidence_sha256=P7E_SHA,
        exact_dependency_graph_binding_verified=True,
        risk_derived_from_evidence=True,
        paths=tuple(_path(value, exposed=value in exposed_p7e_paths) for value in P7E_PATHS),
    )
    p7f = SimpleNamespace(
        assessment_evidence_sha256=P7F_SHA,
        exact_resilience_plan_binding_verified=True,
        security_degradation_derived_from_evidence=True,
        scenarios=tuple(_scenario(value, exposed=value in exposed_p7f_scenarios) for value in P7F_SCENARIOS),
    )
    p7g = SimpleNamespace(
        assessment_evidence_sha256=P7G_SHA,
        exact_telemetry_plan_binding_verified=True,
        audit_integrity_derived_from_evidence=True,
        fallback_observability_derived_from_evidence=True,
        requirements=tuple(_requirement(value, blind_spot=value in blind_spot_requirements) for value in TELEMETRY_REQUIREMENTS),
    )
    assessments = tuple(SimpleNamespace(control_id=key, status=value) for key, value in sorted(control_statuses.items()))
    posture = SimpleNamespace(
        posture_evidence_sha256=POSTURE_SHA,
        control_catalog_sha256=CATALOG_SHA,
        exact_release_identity_verified=True,
        exact_upstream_evidence_binding_verified=True,
        control_catalog_verified=True,
        status_derived_from_evidence=True,
        assessments=assessments,
        satisfied_control_ids=tuple(sorted(key for key, value in control_statuses.items() if value == "satisfied")),
        exceptioned_control_ids=tuple(sorted(key for key, value in control_statuses.items() if value == "exceptioned")),
        not_evaluated_control_ids=tuple(sorted(key for key, value in control_statuses.items() if value == "not_evaluated")),
    )
    return {"p7b": p7b, "p7e": p7e, "p7f": p7f, "p7g": p7g, "posture": posture}


def _principals() -> tuple[AdministrativePrincipal, ...]:
    return (
        AdministrativePrincipal("admin-authz", AdministrativePrincipalType.SECURITY_ADMIN, "security-platform", ("p7b-admin-authz",), False, "Authorization policy administrator."),
        AdministrativePrincipal("admin-release", AdministrativePrincipalType.RELEASE_AUTOMATION, "release-security", ("p7b-admin-release",), False, "Release gate automation."),
        AdministrativePrincipal("admin-observability", AdministrativePrincipalType.SECURITY_ADMIN, "security-observability", ("p7b-admin-observability",), False, "Telemetry configuration administrator."),
        AdministrativePrincipal("admin-network", AdministrativePrincipalType.SECURITY_ADMIN, "security-platform", ("p7b-admin-network",), False, "Egress and fallback policy administrator."),
        AdministrativePrincipal("admin-assurance", AdministrativePrincipalType.HUMAN_ADMIN, "security-assurance", ("p7b-admin-assurance",), False, "Assurance settings administrator."),
        AdministrativePrincipal("admin-breakglass", AdministrativePrincipalType.BREAK_GLASS, "security-incident", ("p7b-admin-breakglass",), True, "Emergency trust-store administrator."),
    )


def _resources() -> tuple[ControlPlaneResource, ...]:
    return (
        ControlPlaneResource(
            "resource-authorization-policy", ControlPlaneResourceType.AUTHORIZATION_POLICY, ControlPlaneSensitivity.CRITICAL,
            "security-platform", "authz-v7", ("p7b:p7b-target-authz-policy",),
            (CTRL_ADMIN_AUTHZ, CTRL_CHANGE_APPROVAL, CTRL_AUDIT_APPEND_ONLY),
            (REQ_CONTROL_CHANGE, REQ_PRIVILEGE_CHANGE), True, False, "Authorization and capability policy."),
        ControlPlaneResource(
            "resource-model-deployment-gate", ControlPlaneResourceType.MODEL_DEPLOYMENT_GATE, ControlPlaneSensitivity.CRITICAL,
            "release-security", "release-gate-v5", (f"p7g:{REQ_MODEL_RELEASE}", f"p6d:{CTRL_RELEASE_GATE}"),
            (CTRL_ADMIN_AUTHZ, CTRL_CHANGE_APPROVAL, CTRL_AUDIT_APPEND_ONLY, CTRL_RELEASE_GATE),
            (REQ_CONTROL_CHANGE, REQ_MODEL_RELEASE), True, False, "Model release security gate."),
        ControlPlaneResource(
            "resource-telemetry-configuration", ControlPlaneResourceType.TELEMETRY_CONFIGURATION, ControlPlaneSensitivity.CRITICAL,
            "security-observability", "telemetry-v9", (f"p7g:{REQ_DEPENDENCY_EGRESS}", f"p7g:{REQ_FAILOVER}"),
            (CTRL_ADMIN_AUTHZ, CTRL_CHANGE_APPROVAL, CTRL_AUDIT_APPEND_ONLY, CTRL_TELEMETRY_INTEGRITY),
            (REQ_CONTROL_CHANGE,), True, False, "Security telemetry routing and detection configuration."),
        ControlPlaneResource(
            "resource-egress-policy", ControlPlaneResourceType.EGRESS_POLICY, ControlPlaneSensitivity.CRITICAL,
            "security-platform", "egress-v6", ("p7e:p7e-path-model-egress", "p7e:p7e-path-tool-egress"),
            (CTRL_ADMIN_AUTHZ, CTRL_CHANGE_APPROVAL, CTRL_AUDIT_APPEND_ONLY, CTRL_EGRESS_POLICY),
            (REQ_CONTROL_CHANGE, REQ_DEPENDENCY_EGRESS), True, False, "External service-egress policy."),
        ControlPlaneResource(
            "resource-fallback-policy", ControlPlaneResourceType.FALLBACK_POLICY, ControlPlaneSensitivity.HIGH,
            "security-platform", "fallback-v4", ("p7f:scenario-model-unavailable", "p7f:scenario-tool-unavailable"),
            (CTRL_ADMIN_AUTHZ, CTRL_CHANGE_APPROVAL, CTRL_AUDIT_APPEND_ONLY, CTRL_FALLBACK_AUTHZ),
            (REQ_CONTROL_CHANGE, REQ_FAILOVER), True, False, "Dependency failover and graceful-degradation policy."),
        ControlPlaneResource(
            "resource-trust-store", ControlPlaneResourceType.TRUST_STORE, ControlPlaneSensitivity.CRITICAL,
            "security-platform", "trust-v8", ("p7e:p7e-path-model-egress", f"p6d:{CTRL_TRUST_STORE}"),
            (CTRL_ADMIN_AUTHZ, CTRL_CHANGE_APPROVAL, CTRL_AUDIT_APPEND_ONLY, CTRL_TRUST_STORE),
            (REQ_CONTROL_CHANGE,), True, True, "Provider/server identity trust store."),
        ControlPlaneResource(
            "resource-assurance-settings", ControlPlaneResourceType.ASSURANCE_SETTINGS, ControlPlaneSensitivity.CRITICAL,
            "security-assurance", "assurance-v10", (f"p6d:{CTRL_ASSURANCE_GATE}", f"p6d:{CTRL_WAIVER_GOVERNANCE}"),
            (CTRL_ADMIN_AUTHZ, CTRL_CHANGE_APPROVAL, CTRL_AUDIT_APPEND_ONLY, CTRL_ASSURANCE_GATE, CTRL_WAIVER_GOVERNANCE),
            (REQ_CONTROL_CHANGE,), True, False, "Release assurance, waiver, and posture settings."),
    )


def _target(route_id: str, version: str) -> str:
    return hashlib.sha256(f"{route_id}:{version}".encode()).hexdigest()


def _route(
    route_id: str,
    principal_id: str,
    resource_id: str,
    operation: AdministrativeOperation,
    owner_id: str,
    execution_identity_id: str,
    approvals: tuple[str, ...],
    controls: tuple[str, ...],
    telemetry: tuple[str, ...],
    proposed_version: str,
    *,
    break_glass: bool = False,
    emergency_reason: str | None = None,
) -> AdministrativeChangeRoute:
    return AdministrativeChangeRoute(
        route_id=route_id,
        principal_id=principal_id,
        resource_id=resource_id,
        operation=operation,
        owner_id=owner_id,
        execution_identity_id=execution_identity_id,
        approval_principal_ids=approvals,
        required_control_ids=controls,
        telemetry_requirement_ids=telemetry,
        proposed_version=proposed_version,
        target_state_sha256=_target(route_id, proposed_version),
        break_glass=break_glass,
        emergency_reason=emergency_reason,
        verified_at_epoch=NOW - 30,
        change_ticket_id=f"CHG-{route_id.removeprefix('route-').upper()}",
        description=f"Synthetic administrative change route for {resource_id}.",
    )


def _routes(resources: tuple[ControlPlaneResource, ...]) -> tuple[AdministrativeChangeRoute, ...]:
    by_id = {item.resource_id: item for item in resources}
    return (
        _route("route-authz-update", "admin-authz", "resource-authorization-policy", AdministrativeOperation.UPDATE, "security-platform", "exec-policy-controller", ("approver-security", "approver-platform"), by_id["resource-authorization-policy"].required_control_ids, by_id["resource-authorization-policy"].required_telemetry_requirement_ids, "authz-v8"),
        _route("route-release-promote", "admin-release", "resource-model-deployment-gate", AdministrativeOperation.PROMOTE, "release-security", "exec-release-controller", ("approver-security", "approver-release"), by_id["resource-model-deployment-gate"].required_control_ids, by_id["resource-model-deployment-gate"].required_telemetry_requirement_ids, "release-gate-v6"),
        _route("route-telemetry-update", "admin-observability", "resource-telemetry-configuration", AdministrativeOperation.UPDATE, "security-observability", "exec-observability-controller", ("approver-security", "approver-observability"), by_id["resource-telemetry-configuration"].required_control_ids, by_id["resource-telemetry-configuration"].required_telemetry_requirement_ids, "telemetry-v10"),
        _route("route-egress-update", "admin-network", "resource-egress-policy", AdministrativeOperation.UPDATE, "security-platform", "exec-network-controller", ("approver-security", "approver-platform"), by_id["resource-egress-policy"].required_control_ids, by_id["resource-egress-policy"].required_telemetry_requirement_ids, "egress-v7"),
        _route("route-fallback-update", "admin-network", "resource-fallback-policy", AdministrativeOperation.UPDATE, "security-platform", "exec-network-controller", ("approver-security", "approver-platform"), by_id["resource-fallback-policy"].required_control_ids, by_id["resource-fallback-policy"].required_telemetry_requirement_ids, "fallback-v5"),
        _route("route-trust-rotate", "admin-authz", "resource-trust-store", AdministrativeOperation.ROTATE, "security-platform", "exec-trust-controller", ("approver-security", "approver-platform"), by_id["resource-trust-store"].required_control_ids, by_id["resource-trust-store"].required_telemetry_requirement_ids, "trust-v9"),
        _route("route-assurance-update", "admin-assurance", "resource-assurance-settings", AdministrativeOperation.UPDATE, "security-assurance", "exec-assurance-controller", ("approver-security", "approver-assurance"), by_id["resource-assurance-settings"].required_control_ids, by_id["resource-assurance-settings"].required_telemetry_requirement_ids, "assurance-v11"),
        _route("route-trust-breakglass", "admin-breakglass", "resource-trust-store", AdministrativeOperation.ROTATE, "security-incident", "exec-trust-controller", ("approver-security", "approver-incident"), by_id["resource-trust-store"].required_control_ids, by_id["resource-trust-store"].required_telemetry_requirement_ids, "trust-v9-emergency", break_glass=True, emergency_reason="Synthetic emergency trust-root rotation."),
    )


def build_fixture() -> dict[str, object]:
    principals = _principals()
    resources = _resources()
    routes = _routes(resources)
    manifest = ControlPlaneManifest(
        control_plane_id=CONTROL_PLANE_ID,
        version=CONTROL_PLANE_VERSION,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7e_assessment_evidence_sha256=P7E_SHA,
        p7f_assessment_evidence_sha256=P7F_SHA,
        p7g_assessment_evidence_sha256=P7G_SHA,
        posture_evidence_sha256=POSTURE_SHA,
        created_at_epoch=NOW - 300,
        principals=principals,
        resources=resources,
        routes=routes,
    )
    manifest_sha = control_plane_manifest_digest(manifest)
    policy = ControlPlanePolicy(
        expected_control_plane_id=CONTROL_PLANE_ID,
        expected_control_plane_version=CONTROL_PLANE_VERSION,
        expected_control_plane_sha256=manifest_sha,
        expected_p7b_assessment_evidence_sha256=P7B_SHA,
        expected_p7e_assessment_evidence_sha256=P7E_SHA,
        expected_p7f_assessment_evidence_sha256=P7F_SHA,
        expected_p7g_assessment_evidence_sha256=P7G_SHA,
        expected_posture_evidence_sha256=POSTURE_SHA,
        expected_control_catalog_sha256=CATALOG_SHA,
        required_principal_ids=frozenset(item.principal_id for item in principals),
        required_resource_ids=frozenset(item.resource_id for item in resources),
        required_route_ids=frozenset(item.route_id for item in routes),
        trusted_owner_ids=frozenset({"security-platform", "release-security", "security-observability", "security-assurance", "security-incident"}),
        trusted_approver_ids=frozenset({"approver-security", "approver-platform", "approver-release", "approver-observability", "approver-assurance", "approver-incident"}),
        trusted_execution_identity_ids=frozenset({"exec-policy-controller", "exec-release-controller", "exec-observability-controller", "exec-network-controller", "exec-trust-controller", "exec-assurance-controller"}),
        expected_principal_type={item.principal_id: item.principal_type for item in principals},
        expected_p7b_path_ids_by_principal={item.principal_id: frozenset(item.p7b_path_ids) for item in principals},
        expected_break_glass_capable={item.principal_id: item.break_glass_capable for item in principals},
        expected_resource_type={item.resource_id: item.resource_type for item in resources},
        minimum_sensitivity={item.resource_id: item.sensitivity for item in resources},
        expected_resource_upstream_binding_ids={item.resource_id: frozenset(item.upstream_binding_ids) for item in resources},
        expected_resource_control_ids={item.resource_id: frozenset(item.required_control_ids) for item in resources},
        expected_resource_telemetry_requirement_ids={item.resource_id: frozenset(item.required_telemetry_requirement_ids) for item in resources},
        expected_separation_of_duties={item.resource_id: item.separation_of_duties_required for item in resources},
        expected_break_glass_permitted={item.resource_id: item.break_glass_permitted for item in resources},
        expected_route_principal={item.route_id: item.principal_id for item in routes},
        expected_route_resource={item.route_id: item.resource_id for item in routes},
        expected_route_operation={item.route_id: item.operation for item in routes},
        expected_execution_identity={item.route_id: item.execution_identity_id for item in routes},
        expected_approval_principal_ids={item.route_id: frozenset(item.approval_principal_ids) for item in routes},
        expected_route_control_ids={item.route_id: frozenset(item.required_control_ids) for item in routes},
        expected_route_telemetry_requirement_ids={item.route_id: frozenset(item.telemetry_requirement_ids) for item in routes},
        expected_proposed_version={item.route_id: item.proposed_version for item in routes},
        expected_break_glass={item.route_id: item.break_glass for item in routes},
    )
    request = ControlPlaneRequest(
        control_plane_id=CONTROL_PLANE_ID,
        control_plane_version=CONTROL_PLANE_VERSION,
        control_plane_sha256=manifest_sha,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7e_assessment_evidence_sha256=P7E_SHA,
        p7f_assessment_evidence_sha256=P7F_SHA,
        p7g_assessment_evidence_sha256=P7G_SHA,
        posture_evidence_sha256=POSTURE_SHA,
        evaluated_at_epoch=NOW,
        route_ids=tuple(sorted(item.route_id for item in routes)),
        declared_exposed_route_ids=(),
        declared_max_exposed_risk_score=0,
    )
    return {"manifest": manifest, "policy": policy, "request": request, **make_upstreams()}


def replace_manifest_item(manifest: ControlPlaneManifest, collection: str, item_id: str, **changes: object) -> ControlPlaneManifest:
    values = list(getattr(manifest, collection))
    key = {"principals": "principal_id", "resources": "resource_id", "routes": "route_id"}[collection]
    for index, item in enumerate(values):
        if getattr(item, key) == item_id:
            values[index] = replace(item, **changes)
            return replace(manifest, **{collection: tuple(values)})
    raise KeyError(item_id)
