from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Mapping

from aegis.architecture.invariant_blast_radius import (
    ArchitectureInvariant,
    InvariantAssessmentRequest,
    InvariantBlastRadiusPolicy,
    InvariantCatalog,
    InvariantSeverity,
    invariant_catalog_digest,
)

NOW = 2_200_200_000
CATALOG_ID = "aegisdesk-cross-layer-security-invariants"
CATALOG_VERSION = "2026.08-p7i.1"

P7A_SHA = hashlib.sha256(b"p7a-for-p7i").hexdigest()
P7B_SHA = hashlib.sha256(b"p7b-for-p7i").hexdigest()
P7C_SHA = hashlib.sha256(b"p7c-for-p7i").hexdigest()
P7D_SHA = hashlib.sha256(b"p7d-for-p7i").hexdigest()
P7E_SHA = hashlib.sha256(b"p7e-for-p7i").hexdigest()
P7F_SHA = hashlib.sha256(b"p7f-for-p7i").hexdigest()
P7G_SHA = hashlib.sha256(b"p7g-for-p7i").hexdigest()
P7H_SHA = hashlib.sha256(b"p7h-for-p7i").hexdigest()
POSTURE_SHA = hashlib.sha256(b"p6d-for-p7i").hexdigest()
CONTROL_CATALOG_SHA = hashlib.sha256(b"p6d-catalog-for-p7i").hexdigest()

CONTROLS = (
    "CTRL-AUTHZ",
    "CTRL-TENANT-ISOLATION",
    "CTRL-DLP",
    "CTRL-SECRETS",
    "CTRL-PROVENANCE",
    "CTRL-FAILOVER",
    "CTRL-TELEMETRY",
    "CTRL-ADMIN-SOD",
    "CTRL-ASSURANCE",
)

OBJECT_IDS = {
    "p7a": ("attack-tool-to-control", "attack-user-to-data", "attack-release-to-model", "attack-admin-to-control"),
    "p7b": ("priv-tool-admin", "priv-tenant-cross", "priv-release-admin", "priv-control-admin"),
    "p7c": ("data-tenant-egress", "data-tool-egress"),
    "p7d": ("secret-tool-credential", "secret-model-signing", "secret-telemetry"),
    "p7e": ("dep-model-provider", "dep-tool-provider", "dep-telemetry"),
    "p7f": ("failover-model", "failover-tool", "failover-telemetry"),
    "p7g": ("telemetry-tool", "telemetry-egress", "telemetry-release", "telemetry-admin"),
    "p7h": ("route-authz-update", "route-release-promote", "route-telemetry-update", "route-egress-update", "route-fallback-update", "route-trust-rotate", "route-assurance-update"),
}

UPSTREAM_SPECS = {
    "p7a": (P7A_SHA, {"exact_architecture_binding_verified": True, "required_graph_coverage_verified": True}, "paths", "path_id"),
    "p7b": (P7B_SHA, {"exact_identity_graph_binding_verified": True, "privilege_amplification_derived_from_evidence": True}, "paths", "path_id"),
    "p7c": (P7C_SHA, {"exact_data_graph_binding_verified": True, "exfiltration_derived_from_evidence": True}, "paths", "path_id"),
    "p7d": (P7D_SHA, {"exact_secret_graph_binding_verified": True, "blast_radius_derived_from_evidence": True}, "paths", "path_id"),
    "p7e": (P7E_SHA, {"exact_dependency_graph_binding_verified": True, "risk_derived_from_evidence": True}, "paths", "path_id"),
    "p7f": (P7F_SHA, {"exact_resilience_plan_binding_verified": True, "security_degradation_derived_from_evidence": True}, "scenarios", "scenario_id"),
    "p7g": (P7G_SHA, {"exact_telemetry_plan_binding_verified": True, "audit_integrity_derived_from_evidence": True, "fallback_observability_derived_from_evidence": True}, "requirements", "requirement_id"),
    "p7h": (P7H_SHA, {"exact_control_plane_binding_verified": True, "path_risk_derived_from_evidence": True, "separation_of_duties_enforced": True}, "routes", "route_id"),
}


def _fact(source: str, object_id: str, unsafe: bool) -> SimpleNamespace:
    attrs: dict[str, object] = {}
    id_attr = UPSTREAM_SPECS[source][3]
    attrs[id_attr] = object_id
    if source == "p7g":
        attrs["blind_spot"] = unsafe
    elif source == "p7c":
        attrs["exposed"] = unsafe
        attrs["exfiltration_possible"] = unsafe
    else:
        attrs["exposed"] = unsafe
    return SimpleNamespace(**attrs)


def make_upstreams(
    *,
    unsafe_bindings: frozenset[str] = frozenset(),
    control_statuses: Mapping[str, str] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {}
    for source, (digest, flags, collection_attr, _id_attr) in UPSTREAM_SPECS.items():
        items = tuple(_fact(source, object_id, f"{source}:{object_id}" in unsafe_bindings) for object_id in OBJECT_IDS[source])
        result[source] = SimpleNamespace(assessment_evidence_sha256=digest, **flags, **{collection_attr: items})
    statuses = dict(control_statuses or {control_id: "satisfied" for control_id in CONTROLS})
    assessments = tuple(SimpleNamespace(control_id=key, status=value) for key, value in sorted(statuses.items()))
    result["posture"] = SimpleNamespace(
        posture_evidence_sha256=POSTURE_SHA,
        control_catalog_sha256=CONTROL_CATALOG_SHA,
        exact_release_identity_verified=True,
        exact_upstream_evidence_binding_verified=True,
        control_catalog_verified=True,
        status_derived_from_evidence=True,
        assessments=assessments,
        satisfied_control_ids=tuple(sorted(key for key, value in statuses.items() if value == "satisfied")),
        exceptioned_control_ids=tuple(sorted(key for key, value in statuses.items() if value == "exceptioned")),
        not_evaluated_control_ids=tuple(sorted(key for key, value in statuses.items() if value == "not_evaluated")),
    )
    return result


def _inv(
    invariant_id: str,
    title: str,
    severity: InvariantSeverity,
    bindings: tuple[str, ...],
    assets: tuple[str, ...],
    identities: tuple[str, ...],
    dependencies: tuple[str, ...],
    routes: tuple[str, ...],
    controls: tuple[str, ...],
) -> ArchitectureInvariant:
    return ArchitectureInvariant(
        invariant_id=invariant_id,
        title=title,
        description=f"Cross-layer invariant: {title}",
        owner_id="security-architecture",
        severity=severity,
        required_binding_ids=bindings,
        protected_asset_ids=assets,
        affected_identity_ids=identities,
        dependency_ids=dependencies,
        control_plane_route_ids=routes,
        required_control_ids=controls,
    )


def invariants() -> tuple[ArchitectureInvariant, ...]:
    return (
        _inv(
            "INV-PRIVILEGED-TOOL-AUTHZ", "Privileged tool execution remains authorized and observable", InvariantSeverity.CRITICAL,
            ("p7a:attack-tool-to-control", "p7b:priv-tool-admin", "p7d:secret-tool-credential", "p7e:dep-tool-provider", "p7g:telemetry-tool", "p7h:route-authz-update", "p6d:CTRL-AUTHZ", "p6d:CTRL-ADMIN-SOD"),
            ("asset-tool-control-plane", "asset-tool-credential"), ("identity-agent-runtime", "identity-tool-admin"), ("dependency-tool-provider",), ("route-authz-update",),
            ("CTRL-AUTHZ", "CTRL-ADMIN-SOD", "CTRL-TELEMETRY"),
        ),
        _inv(
            "INV-TENANT-DATA-CONFINEMENT", "Tenant-sensitive data cannot cross isolation or approved egress boundaries", InvariantSeverity.CRITICAL,
            ("p7a:attack-user-to-data", "p7b:priv-tenant-cross", "p7c:data-tenant-egress", "p7e:dep-model-provider", "p7g:telemetry-egress", "p7h:route-egress-update", "p6d:CTRL-TENANT-ISOLATION", "p6d:CTRL-DLP"),
            ("asset-tenant-index", "asset-user-context"), ("identity-tenant-user", "identity-agent-runtime"), ("dependency-model-provider",), ("route-egress-update",),
            ("CTRL-TENANT-ISOLATION", "CTRL-DLP", "CTRL-AUTHZ"),
        ),
        _inv(
            "INV-SECRET-TRUST-CONFINEMENT", "Secrets and trust roots cannot traverse untrusted surfaces or providers", InvariantSeverity.CRITICAL,
            ("p7d:secret-tool-credential", "p7d:secret-model-signing", "p7e:dep-tool-provider", "p7e:dep-model-provider", "p7g:telemetry-egress", "p7h:route-trust-rotate", "p6d:CTRL-SECRETS"),
            ("asset-tool-credential", "asset-model-signing-key"), ("identity-release-automation", "identity-tool-admin"), ("dependency-tool-provider", "dependency-model-provider"), ("route-trust-rotate",),
            ("CTRL-SECRETS", "CTRL-AUTHZ", "CTRL-TELEMETRY"),
        ),
        _inv(
            "INV-MODEL-RELEASE-INTEGRITY", "Model release integrity retains provenance, signing, and assurance gates", InvariantSeverity.CRITICAL,
            ("p7a:attack-release-to-model", "p7b:priv-release-admin", "p7d:secret-model-signing", "p7g:telemetry-release", "p7h:route-release-promote", "p7h:route-assurance-update", "p6d:CTRL-PROVENANCE", "p6d:CTRL-ASSURANCE"),
            ("asset-model-release", "asset-model-signing-key"), ("identity-release-automation", "identity-assurance-admin"), (), ("route-release-promote", "route-assurance-update"),
            ("CTRL-PROVENANCE", "CTRL-ASSURANCE", "CTRL-ADMIN-SOD"),
        ),
        _inv(
            "INV-FAILOVER-NON-WEAKENING", "Dependency failover cannot silently weaken authorization, data, or secret controls", InvariantSeverity.HIGH,
            ("p7e:dep-model-provider", "p7e:dep-tool-provider", "p7f:failover-model", "p7f:failover-tool", "p7g:telemetry-egress", "p7h:route-fallback-update", "p6d:CTRL-FAILOVER", "p6d:CTRL-AUTHZ"),
            ("asset-runtime-fallback",), ("identity-agent-runtime",), ("dependency-model-provider", "dependency-tool-provider"), ("route-fallback-update",),
            ("CTRL-FAILOVER", "CTRL-AUTHZ", "CTRL-DLP", "CTRL-SECRETS"),
        ),
        _inv(
            "INV-SECURITY-TELEMETRY-CONTINUITY", "Critical security activity remains observable across normal and failure paths", InvariantSeverity.CRITICAL,
            ("p7d:secret-telemetry", "p7e:dep-telemetry", "p7f:failover-telemetry", "p7g:telemetry-admin", "p7g:telemetry-egress", "p7h:route-telemetry-update", "p6d:CTRL-TELEMETRY"),
            ("asset-security-audit", "asset-alert-routing"), ("identity-observability-admin",), ("dependency-telemetry",), ("route-telemetry-update",),
            ("CTRL-TELEMETRY", "CTRL-ADMIN-SOD"),
        ),
        _inv(
            "INV-ADMIN-NON-SELF-BYPASS", "Administrative identities cannot self-authorize or disable their own security evidence", InvariantSeverity.CRITICAL,
            ("p7a:attack-admin-to-control", "p7b:priv-control-admin", "p7g:telemetry-admin", "p7h:route-authz-update", "p7h:route-telemetry-update", "p7h:route-assurance-update", "p6d:CTRL-ADMIN-SOD", "p6d:CTRL-AUTHZ"),
            ("asset-authorization-policy", "asset-telemetry-config", "asset-assurance-settings"), ("identity-security-admin", "identity-assurance-admin"), (), ("route-authz-update", "route-telemetry-update", "route-assurance-update"),
            ("CTRL-ADMIN-SOD", "CTRL-AUTHZ", "CTRL-TELEMETRY", "CTRL-ASSURANCE"),
        ),
        _inv(
            "INV-ASSURANCE-GATE-NON-BYPASS", "Release assurance cannot be bypassed by cross-layer control-plane mutation", InvariantSeverity.CRITICAL,
            ("p7a:attack-release-to-model", "p7a:attack-admin-to-control", "p7b:priv-release-admin", "p7b:priv-control-admin", "p7g:telemetry-release", "p7h:route-release-promote", "p7h:route-assurance-update", "p6d:CTRL-ASSURANCE", "p6d:CTRL-PROVENANCE"),
            ("asset-model-release", "asset-assurance-settings"), ("identity-release-automation", "identity-assurance-admin"), (), ("route-release-promote", "route-assurance-update"),
            ("CTRL-ASSURANCE", "CTRL-PROVENANCE", "CTRL-ADMIN-SOD"),
        ),
    )


def build_fixture() -> dict[str, object]:
    invs = invariants()
    catalog = InvariantCatalog(
        catalog_id=CATALOG_ID,
        version=CATALOG_VERSION,
        created_at_epoch=NOW - 300,
        p7a_assessment_evidence_sha256=P7A_SHA,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7c_assessment_evidence_sha256=P7C_SHA,
        p7d_assessment_evidence_sha256=P7D_SHA,
        p7e_assessment_evidence_sha256=P7E_SHA,
        p7f_assessment_evidence_sha256=P7F_SHA,
        p7g_assessment_evidence_sha256=P7G_SHA,
        p7h_assessment_evidence_sha256=P7H_SHA,
        posture_evidence_sha256=POSTURE_SHA,
        invariants=invs,
    )
    catalog_sha = invariant_catalog_digest(catalog)
    policy = InvariantBlastRadiusPolicy(
        expected_catalog_id=CATALOG_ID,
        expected_catalog_version=CATALOG_VERSION,
        expected_catalog_sha256=catalog_sha,
        expected_p7a_assessment_evidence_sha256=P7A_SHA,
        expected_p7b_assessment_evidence_sha256=P7B_SHA,
        expected_p7c_assessment_evidence_sha256=P7C_SHA,
        expected_p7d_assessment_evidence_sha256=P7D_SHA,
        expected_p7e_assessment_evidence_sha256=P7E_SHA,
        expected_p7f_assessment_evidence_sha256=P7F_SHA,
        expected_p7g_assessment_evidence_sha256=P7G_SHA,
        expected_p7h_assessment_evidence_sha256=P7H_SHA,
        expected_posture_evidence_sha256=POSTURE_SHA,
        expected_control_catalog_sha256=CONTROL_CATALOG_SHA,
        required_invariant_ids=frozenset(item.invariant_id for item in invs),
        trusted_owner_ids=frozenset({"security-architecture"}),
        minimum_severity_by_invariant={item.invariant_id: item.severity for item in invs},
        expected_binding_ids_by_invariant={item.invariant_id: frozenset(item.required_binding_ids) for item in invs},
        expected_asset_ids_by_invariant={item.invariant_id: frozenset(item.protected_asset_ids) for item in invs},
        expected_identity_ids_by_invariant={item.invariant_id: frozenset(item.affected_identity_ids) for item in invs},
        expected_dependency_ids_by_invariant={item.invariant_id: frozenset(item.dependency_ids) for item in invs},
        expected_route_ids_by_invariant={item.invariant_id: frozenset(item.control_plane_route_ids) for item in invs},
        expected_control_ids_by_invariant={item.invariant_id: frozenset(item.required_control_ids) for item in invs},
        min_distinct_layers_by_invariant={item.invariant_id: 4 for item in invs},
    )
    request = InvariantAssessmentRequest(
        catalog_id=CATALOG_ID,
        catalog_version=CATALOG_VERSION,
        catalog_sha256=catalog_sha,
        p7a_assessment_evidence_sha256=P7A_SHA,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7c_assessment_evidence_sha256=P7C_SHA,
        p7d_assessment_evidence_sha256=P7D_SHA,
        p7e_assessment_evidence_sha256=P7E_SHA,
        p7f_assessment_evidence_sha256=P7F_SHA,
        p7g_assessment_evidence_sha256=P7G_SHA,
        p7h_assessment_evidence_sha256=P7H_SHA,
        posture_evidence_sha256=POSTURE_SHA,
        evaluated_at_epoch=NOW,
        invariant_ids=tuple(sorted(item.invariant_id for item in invs)),
        declared_violated_invariant_ids=(),
        declared_degraded_invariant_ids=(),
        declared_cross_layer_blast_radius=0,
        declared_max_blast_radius_score=0,
    )
    return {"catalog": catalog, "policy": policy, "request": request, **make_upstreams()}


def replace_invariant(catalog: InvariantCatalog, invariant_id: str, **changes: object) -> InvariantCatalog:
    values = list(catalog.invariants)
    for index, item in enumerate(values):
        if item.invariant_id == invariant_id:
            values[index] = replace(item, **changes)
            return replace(catalog, invariants=tuple(values))
    raise KeyError(invariant_id)


def truthful_declarations(catalog: InvariantCatalog, *, unsafe_bindings: frozenset[str] = frozenset(), control_statuses: Mapping[str, str] | None = None) -> dict[str, object]:
    statuses = dict(control_statuses or {control_id: "satisfied" for control_id in CONTROLS})
    violated: list[str] = []
    degraded: list[str] = []
    all_entities: set[str] = set()
    scores: list[int] = []
    base_by_severity = {InvariantSeverity.LOW: 20, InvariantSeverity.MEDIUM: 40, InvariantSeverity.HIGH: 65, InvariantSeverity.CRITICAL: 85}
    for invariant in catalog.invariants:
        non_control_unsafe = sorted(value for value in invariant.required_binding_ids if not value.startswith("p6d:") and value in unsafe_bindings)
        degraded_controls = sorted(control_id for control_id in invariant.required_control_ids if statuses[control_id] != "satisfied")
        if non_control_unsafe:
            state = "violated"
            violated.append(invariant.invariant_id)
            violating_bindings = non_control_unsafe + [f"p6d:{value}" for value in degraded_controls if f"p6d:{value}" in invariant.required_binding_ids]
        elif degraded_controls:
            state = "degraded"
            degraded.append(invariant.invariant_id)
            violating_bindings = [f"p6d:{value}" for value in degraded_controls if f"p6d:{value}" in invariant.required_binding_ids]
        else:
            continue
        entities = {
            *(f"asset:{value}" for value in invariant.protected_asset_ids),
            *(f"identity:{value}" for value in invariant.affected_identity_ids),
            *(f"dependency:{value}" for value in invariant.dependency_ids),
            *(f"route:{value}" for value in invariant.control_plane_route_ids),
        }
        all_entities.update(entities)
        layers = {value.split(":", 1)[0] for value in violating_bindings}
        score = base_by_severity[invariant.severity] + (25 if state == "violated" else 10) + max(0, len(layers) - 1) * 8 + max(0, len(entities) - 1) * 3 + max(0, len(violating_bindings) - 1) * 4
        scores.append(score)
    return {
        "declared_violated_invariant_ids": tuple(sorted(violated)),
        "declared_degraded_invariant_ids": tuple(sorted(degraded)),
        "declared_cross_layer_blast_radius": len(all_entities),
        "declared_max_blast_radius_score": max(scores, default=0),
    }
