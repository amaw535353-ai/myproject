from __future__ import annotations

import hashlib
from types import SimpleNamespace

from aegis.architecture.attack_paths import (
    ArchitectureAsset,
    ArchitectureFlow,
    ArchitectureManifest,
    AssetSensitivity,
    AssetType,
    FlowType,
    architecture_manifest_digest,
)
from aegis.architecture.dependency_trust import (
    AuthenticationMode,
    DependencyCriticality,
    DependencyTrustManifest,
    DependencyTrustPolicy,
    DependencyTrustRequest,
    DependencyType,
    EgressDataClass,
    ExternalDependency,
    ServiceEgressRoute,
    TransportMode,
    dependency_trust_manifest_digest,
    dependency_trust_path_identifier,
)
from aegis.assurance.posture_reporting import ControlStatus


NOW = 2_000_000_000
GRAPH_ID = "aegisdesk-third-party-egress-graph"
GRAPH_VERSION = "2026.08-p7e.1"

CTRL_MODEL_EGRESS = "CTRL-MODEL-EGRESS"
CTRL_TOOL_EGRESS = "CTRL-TOOL-EGRESS"
CTRL_TELEMETRY_EGRESS = "CTRL-TELEMETRY-EGRESS"
CTRL_REGISTRY_EGRESS = "CTRL-REGISTRY-EGRESS"
CTRL_IDP_EGRESS = "CTRL-IDP-EGRESS"
ALL_CONTROLS = (
    CTRL_MODEL_EGRESS,
    CTRL_TOOL_EGRESS,
    CTRL_TELEMETRY_EGRESS,
    CTRL_REGISTRY_EGRESS,
    CTRL_IDP_EGRESS,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _upstream(evidence_sha: str, architecture_sha: str, **flags: bool) -> SimpleNamespace:
    values = {
        "assessment_evidence_sha256": evidence_sha,
        "architecture_sha256": architecture_sha,
    }
    values.update(flags)
    return SimpleNamespace(**values)


def _architecture() -> ArchitectureManifest:
    assets = (
        ArchitectureAsset("asset-external", AssetType.EXTERNAL_ACTOR, "internet", "security-architecture", AssetSensitivity.LOW, "Synthetic external caller"),
        ArchitectureAsset("asset-api", AssetType.API_GATEWAY, "edge", "platform-security", AssetSensitivity.HIGH, "API gateway"),
        ArchitectureAsset("asset-agent", AssetType.AGENT_ORCHESTRATOR, "application", "ai-platform", AssetSensitivity.HIGH, "Agent orchestrator"),
        ArchitectureAsset("asset-tool", AssetType.TOOL_GATEWAY, "privileged-tools", "tool-security", AssetSensitivity.CRITICAL, "Tool gateway"),
        ArchitectureAsset("asset-runtime", AssetType.MODEL_RUNTIME, "model-runtime", "model-security", AssetSensitivity.CRITICAL, "Model runtime"),
        ArchitectureAsset("asset-telemetry", AssetType.SECURITY_TELEMETRY, "security", "security-operations", AssetSensitivity.HIGH, "Security telemetry"),
    )
    flows = (
        ArchitectureFlow("flow-user", "asset-external", "asset-api", FlowType.USER_INPUT, "platform-security", ("CTRL-EDGE-AUTH",), "Inbound request"),
        ArchitectureFlow("flow-agent", "asset-api", "asset-agent", FlowType.AGENT_CONTROL, "ai-platform", ("CTRL-AGENT-AUTHZ",), "Agent handoff"),
        ArchitectureFlow("flow-tool", "asset-agent", "asset-tool", FlowType.TOOL_CALL, "tool-security", ("CTRL-TOOL-AUTH",), "Privileged tool call"),
        ArchitectureFlow("flow-model", "asset-agent", "asset-runtime", FlowType.INFERENCE, "model-security", ("CTRL-RUNTIME-ISOLATION",), "Model inference"),
        ArchitectureFlow("flow-telemetry", "asset-runtime", "asset-telemetry", FlowType.SECURITY_TELEMETRY, "security-operations", ("CTRL-TELEMETRY-INTEGRITY",), "Security telemetry export"),
    )
    return ArchitectureManifest(
        architecture_id="aegisdesk-ai-security-architecture",
        version="2026.08-p7e.1",
        created_at_epoch=NOW - 120,
        assets=assets,
        flows=flows,
    )


def _dependencies() -> tuple[ExternalDependency, ...]:
    return (
        ExternalDependency(
            "dep-model-provider", "provider-model-a", DependencyType.MODEL_PROVIDER, DependencyCriticality.HIGH,
            "model.vendor.example", 443, TransportMode.MTLS, AuthenticationMode.OAUTH2, "spiffe://model.vendor.example/service",
            "model-security", (EgressDataClass.INTERNAL, EgressDataClass.CONFIDENTIAL), (), (CTRL_MODEL_EGRESS,), True,
            "Synthetic hosted-model API dependency",
        ),
        ExternalDependency(
            "dep-tool-api", "provider-tool-a", DependencyType.TOOL_API, DependencyCriticality.CRITICAL,
            "tool.vendor.example", 443, TransportMode.MTLS, AuthenticationMode.SIGNED_REQUEST, "spiffe://tool.vendor.example/api",
            "tool-security", (EgressDataClass.CONFIDENTIAL, EgressDataClass.RESTRICTED), ("secret-tool-api",), (CTRL_TOOL_EGRESS,), True,
            "Synthetic privileged tool API",
        ),
        ExternalDependency(
            "dep-telemetry", "provider-telemetry-a", DependencyType.TELEMETRY_SINK, DependencyCriticality.MEDIUM,
            "telemetry.vendor.example", 443, TransportMode.TLS, AuthenticationMode.OAUTH2, "telemetry.vendor.example",
            "security-operations", (EgressDataClass.INTERNAL, EgressDataClass.CONFIDENTIAL), (), (CTRL_TELEMETRY_EGRESS,), True,
            "Synthetic external telemetry processor",
        ),
        ExternalDependency(
            "dep-registry", "provider-registry-a", DependencyType.PACKAGE_REGISTRY, DependencyCriticality.HIGH,
            "registry.vendor.example", 443, TransportMode.PRIVATE_LINK, AuthenticationMode.MTLS, "spiffe://registry.vendor.example/service",
            "model-security", (EgressDataClass.INTERNAL,), (), (CTRL_REGISTRY_EGRESS,), True,
            "Synthetic model/package registry",
        ),
        ExternalDependency(
            "dep-idp", "provider-idp-a", DependencyType.IDENTITY_PROVIDER, DependencyCriticality.CRITICAL,
            "id.vendor.example", 443, TransportMode.MTLS, AuthenticationMode.MTLS, "spiffe://id.vendor.example/oauth",
            "platform-security", (EgressDataClass.INTERNAL,), (), (CTRL_IDP_EGRESS,), True,
            "Synthetic external identity provider",
        ),
    )


def _routes() -> tuple[ServiceEgressRoute, ...]:
    return (
        ServiceEgressRoute("route-model", "asset-runtime", "dep-model-provider", "model-security", ("flow-user", "flow-agent", "flow-model"), (CTRL_MODEL_EGRESS,), "Hosted model inference"),
        ServiceEgressRoute("route-tool", "asset-tool", "dep-tool-api", "tool-security", ("flow-user", "flow-agent", "flow-tool"), (CTRL_TOOL_EGRESS,), "Privileged third-party tool call"),
        ServiceEgressRoute("route-telemetry", "asset-telemetry", "dep-telemetry", "security-operations", ("flow-user", "flow-agent", "flow-model", "flow-telemetry"), (CTRL_TELEMETRY_EGRESS,), "Telemetry export"),
        ServiceEgressRoute("route-registry", "asset-runtime", "dep-registry", "model-security", ("flow-user", "flow-agent", "flow-model"), (CTRL_REGISTRY_EGRESS,), "Registry acquisition"),
        ServiceEgressRoute("route-idp", "asset-api", "dep-idp", "platform-security", ("flow-user",), (CTRL_IDP_EGRESS,), "Identity verification"),
    )


def _risk(dependency: ExternalDependency, status: ControlStatus) -> int:
    criticality = {
        DependencyCriticality.LOW: 1,
        DependencyCriticality.MEDIUM: 2,
        DependencyCriticality.HIGH: 3,
        DependencyCriticality.CRITICAL: 4,
    }[dependency.criticality]
    data_rank = {
        EgressDataClass.PUBLIC: 1,
        EgressDataClass.INTERNAL: 2,
        EgressDataClass.CONFIDENTIAL: 3,
        EgressDataClass.RESTRICTED: 4,
        EgressDataClass.SECRET: 5,
    }
    score = criticality * 20
    if dependency.exposed_secret_ids:
        score += 24
    score += max(0, max(data_rank[value] for value in dependency.egress_data_classes) - 2) * 8
    if status == ControlStatus.EXCEPTIONED:
        score += 14
    elif status == ControlStatus.NOT_EVALUATED:
        score += 12
    return score


def build_fixture(
    *,
    exceptioned_control: str | None = None,
    not_evaluated_control: str | None = None,
) -> dict[str, object]:
    architecture = _architecture()
    architecture_sha = architecture_manifest_digest(architecture)
    p7a_sha, p7b_sha, p7c_sha, p7d_sha = (_sha("p7a-p7e"), _sha("p7b-p7e"), _sha("p7c-p7e"), _sha("p7d-p7e"))
    posture_sha, catalog_sha = _sha("p6d-posture-p7e"), _sha("p6d-catalog-p7e")

    statuses: dict[str, ControlStatus] = {control_id: ControlStatus.SATISFIED for control_id in ALL_CONTROLS}
    if exceptioned_control:
        statuses[exceptioned_control] = ControlStatus.EXCEPTIONED
    if not_evaluated_control:
        statuses[not_evaluated_control] = ControlStatus.NOT_EVALUATED
    assessments = tuple(SimpleNamespace(control_id=control_id, status=statuses[control_id]) for control_id in ALL_CONTROLS)
    posture = SimpleNamespace(
        exact_release_identity_verified=True,
        exact_upstream_evidence_binding_verified=True,
        control_catalog_verified=True,
        status_derived_from_evidence=True,
        posture_evidence_sha256=posture_sha,
        control_catalog_sha256=catalog_sha,
        assessments=assessments,
        satisfied_control_ids=tuple(sorted(key for key, value in statuses.items() if value == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(key for key, value in statuses.items() if value == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(key for key, value in statuses.items() if value == ControlStatus.NOT_EVALUATED)),
    )
    p7a = _upstream(p7a_sha, architecture_sha, exact_architecture_binding_verified=True)
    p7b = _upstream(p7b_sha, architecture_sha, exact_architecture_binding_verified=True, exact_p7a_assessment_binding_verified=True)
    p7c = _upstream(p7c_sha, architecture_sha, exact_architecture_binding_verified=True, exact_p7a_assessment_binding_verified=True, exact_p7b_assessment_binding_verified=True)
    p7d = _upstream(p7d_sha, architecture_sha, exact_architecture_binding_verified=True, exact_p7a_assessment_binding_verified=True, exact_p7b_assessment_binding_verified=True, exact_p7c_assessment_binding_verified=True)

    dependencies = _dependencies()
    routes = _routes()
    manifest = DependencyTrustManifest(GRAPH_ID, GRAPH_VERSION, architecture_sha, NOW - 60, dependencies, routes)
    graph_sha = dependency_trust_manifest_digest(manifest)
    dep_by_id = {item.dependency_id: item for item in dependencies}
    route_by_id = {item.route_id: item for item in routes}

    policy = DependencyTrustPolicy(
        expected_dependency_graph_id=GRAPH_ID,
        expected_dependency_graph_version=GRAPH_VERSION,
        expected_dependency_graph_sha256=graph_sha,
        expected_architecture_sha256=architecture_sha,
        expected_p7a_assessment_evidence_sha256=p7a_sha,
        expected_p7b_assessment_evidence_sha256=p7b_sha,
        expected_p7c_assessment_evidence_sha256=p7c_sha,
        expected_p7d_assessment_evidence_sha256=p7d_sha,
        expected_posture_evidence_sha256=posture_sha,
        expected_control_catalog_sha256=catalog_sha,
        required_dependency_ids=frozenset(dep_by_id),
        required_route_ids=frozenset(route_by_id),
        entry_source_asset_ids=frozenset({item.source_asset_id for item in routes}),
        target_dependency_ids=frozenset(dep_by_id),
        trusted_owner_ids=frozenset({"platform-security", "model-security", "tool-security", "security-operations"}),
        trusted_provider_ids=frozenset(item.provider_id for item in dependencies),
        expected_dependency_type={key: value.dependency_type for key, value in dep_by_id.items()},
        minimum_criticality={key: value.criticality for key, value in dep_by_id.items()},
        expected_endpoint_host={key: value.endpoint_host for key, value in dep_by_id.items()},
        expected_endpoint_port={key: value.endpoint_port for key, value in dep_by_id.items()},
        expected_transport_mode={key: value.transport_mode for key, value in dep_by_id.items()},
        expected_authentication_mode={key: value.authentication_mode for key, value in dep_by_id.items()},
        expected_server_identity={key: value.expected_server_identity for key, value in dep_by_id.items()},
        allowed_egress_data_classes={key: frozenset(value.egress_data_classes) for key, value in dep_by_id.items()},
        allowed_exposed_secret_ids={key: frozenset(value.exposed_secret_ids) for key, value in dep_by_id.items()},
        expected_dependency_control_ids={key: frozenset(value.required_control_ids) for key, value in dep_by_id.items()},
        expected_fail_closed={key: value.fail_closed for key, value in dep_by_id.items()},
        expected_route_source_asset={key: value.source_asset_id for key, value in route_by_id.items()},
        expected_route_dependency={key: value.dependency_id for key, value in route_by_id.items()},
        expected_route_flow_ids={key: value.via_flow_ids for key, value in route_by_id.items()},
        expected_route_control_ids={key: frozenset(value.required_control_ids) for key, value in route_by_id.items()},
    )

    exposed: list[tuple[int, str]] = []
    for route in routes:
        dependency = dep_by_id[route.dependency_id]
        status = statuses[dependency.required_control_ids[0]]
        if status != ControlStatus.SATISFIED:
            exposed.append((_risk(dependency, status), dependency_trust_path_identifier(route, dependency)))
    exposed.sort(key=lambda item: (-item[0], item[1]))
    request = DependencyTrustRequest(
        dependency_graph_id=GRAPH_ID,
        dependency_graph_version=GRAPH_VERSION,
        dependency_graph_sha256=graph_sha,
        architecture_sha256=architecture_sha,
        p7a_assessment_evidence_sha256=p7a_sha,
        p7b_assessment_evidence_sha256=p7b_sha,
        p7c_assessment_evidence_sha256=p7c_sha,
        p7d_assessment_evidence_sha256=p7d_sha,
        posture_evidence_sha256=posture_sha,
        entry_source_asset_ids=tuple(sorted(policy.entry_source_asset_ids)),
        target_dependency_ids=tuple(sorted(policy.target_dependency_ids)),
        evaluated_at_epoch=NOW,
        declared_exposed_path_ids=tuple(path_id for _, path_id in exposed),
        declared_max_exposed_risk_score=exposed[0][0] if exposed else 0,
    )
    return {
        "architecture": architecture,
        "p7a": p7a,
        "p7b": p7b,
        "p7c": p7c,
        "p7d": p7d,
        "posture": posture,
        "manifest": manifest,
        "policy": policy,
        "request": request,
    }
