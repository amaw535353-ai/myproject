from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Mapping

from aegis.agentic.delegation_security import (
    AgentCapability,
    AgentDelegationManifest,
    AgentDelegationPolicy,
    AgentDelegationRequest,
    AgentIdentity,
    AgentRole,
    DelegationRecord,
    DelegationRisk,
    TenantScope,
    agent_delegation_manifest_digest,
)

NOW = 2_200_300_000
GRAPH_ID = "aegisdesk-agent-delegation-graph"
GRAPH_VERSION = "2026.08-p8a.1"
P7B_SHA = hashlib.sha256(b"p7b-for-p8a").hexdigest()
P7H_SHA = hashlib.sha256(b"p7h-for-p8a").hexdigest()
P7I_SHA = hashlib.sha256(b"p7i-for-p8a").hexdigest()

P7B_PATH_IDS = (
    "path-orchestrator-a",
    "path-retrieval-a",
    "path-tool-broker-a",
    "path-tool-executor-a",
    "path-release-orchestrator",
    "path-release-agent",
    "path-security-agent",
    "path-observability-agent",
    "path-policy-controller",
)
P7H_ROUTE_IDS = ("route-release-promote", "route-telemetry-update", "route-authz-update")
P7I_INVARIANT_IDS = (
    "INV-PRIVILEGED-TOOL-AUTHZ",
    "INV-MODEL-RELEASE-INTEGRITY",
    "INV-SECURITY-TELEMETRY-CONTINUITY",
    "INV-ADMIN-NON-SELF-BYPASS",
)

CAP_SEARCH_READ = "search.read"
CAP_TENANT_RETRIEVE = "tenant.retrieve"
CAP_TOOL_READ = "tool.read"
CAP_TOOL_WRITE = "tool.write"
CAP_MODEL_INSPECT = "model.inspect"
CAP_MODEL_DEPLOY = "model.deploy"
CAP_TELEMETRY_READ = "telemetry.read"
CAP_TELEMETRY_CONFIGURE = "telemetry.configure"
CAP_POLICY_READ = "policy.read"
CAP_POLICY_WRITE = "policy.write"

CAPABILITY_IDS = (
    CAP_SEARCH_READ,
    CAP_TENANT_RETRIEVE,
    CAP_TOOL_READ,
    CAP_TOOL_WRITE,
    CAP_MODEL_INSPECT,
    CAP_MODEL_DEPLOY,
    CAP_TELEMETRY_READ,
    CAP_TELEMETRY_CONFIGURE,
    CAP_POLICY_READ,
    CAP_POLICY_WRITE,
)

AGENT_ORCH_A = "agent-orchestrator-a"
AGENT_RETRIEVAL_A = "agent-retrieval-a"
AGENT_TOOL_BROKER_A = "agent-tool-broker-a"
AGENT_TOOL_EXECUTOR_A = "agent-tool-executor-a"
AGENT_RELEASE_ORCH = "agent-release-orchestrator"
AGENT_RELEASE = "agent-release"
AGENT_SECURITY = "agent-security"
AGENT_OBSERVABILITY = "agent-observability"
AGENT_POLICY = "agent-policy-controller"

AGENT_IDS = (
    AGENT_ORCH_A,
    AGENT_RETRIEVAL_A,
    AGENT_TOOL_BROKER_A,
    AGENT_TOOL_EXECUTOR_A,
    AGENT_RELEASE_ORCH,
    AGENT_RELEASE,
    AGENT_SECURITY,
    AGENT_OBSERVABILITY,
    AGENT_POLICY,
)

DELEGATION_IDS = (
    "delegation-tool-root",
    "delegation-tool-child",
    "delegation-retrieval",
    "delegation-release-inspect",
    "delegation-release-deploy",
    "delegation-telemetry-configure",
    "delegation-policy-write",
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _capabilities() -> tuple[AgentCapability, ...]:
    return (
        AgentCapability(CAP_SEARCH_READ, "search", 1, TenantScope.TENANT_BOUND, False, (), (), "Read-only search."),
        AgentCapability(CAP_TENANT_RETRIEVE, "retrieval", 1, TenantScope.TENANT_BOUND, False, (), (), "Tenant-bound retrieval."),
        AgentCapability(CAP_TOOL_READ, "tool", 1, TenantScope.TENANT_BOUND, False, (), ("INV-PRIVILEGED-TOOL-AUTHZ",), "Read-only privileged-tool operation."),
        AgentCapability(CAP_TOOL_WRITE, "tool", 2, TenantScope.TENANT_BOUND, True, (), ("INV-PRIVILEGED-TOOL-AUTHZ",), "State-changing privileged-tool operation."),
        AgentCapability(CAP_MODEL_INSPECT, "model", 1, TenantScope.SYSTEM, False, (), ("INV-MODEL-RELEASE-INTEGRITY",), "Inspect model-release metadata."),
        AgentCapability(CAP_MODEL_DEPLOY, "model", 3, TenantScope.SYSTEM, True, ("route-release-promote",), ("INV-MODEL-RELEASE-INTEGRITY",), "Promote a model release."),
        AgentCapability(CAP_TELEMETRY_READ, "telemetry", 1, TenantScope.SYSTEM, False, (), ("INV-SECURITY-TELEMETRY-CONTINUITY",), "Read security telemetry."),
        AgentCapability(CAP_TELEMETRY_CONFIGURE, "telemetry", 3, TenantScope.SYSTEM, True, ("route-telemetry-update",), ("INV-SECURITY-TELEMETRY-CONTINUITY", "INV-ADMIN-NON-SELF-BYPASS"), "Modify telemetry routing/configuration."),
        AgentCapability(CAP_POLICY_READ, "policy", 1, TenantScope.SYSTEM, False, (), ("INV-ADMIN-NON-SELF-BYPASS",), "Read authorization policy."),
        AgentCapability(CAP_POLICY_WRITE, "policy", 3, TenantScope.SYSTEM, True, ("route-authz-update",), ("INV-ADMIN-NON-SELF-BYPASS",), "Modify authorization policy."),
    )


def _agents() -> tuple[AgentIdentity, ...]:
    return (
        AgentIdentity(AGENT_ORCH_A, AgentRole.ORCHESTRATOR, "tenant-a", "tenant-runtime", "agent-platform", (CAP_SEARCH_READ, CAP_TENANT_RETRIEVE, CAP_TOOL_READ, CAP_TOOL_WRITE), ("path-orchestrator-a",), (), True, 3, "Tenant A orchestrator."),
        AgentIdentity(AGENT_RETRIEVAL_A, AgentRole.RETRIEVAL_AGENT, "tenant-a", "tenant-runtime", "agent-platform", (CAP_SEARCH_READ, CAP_TENANT_RETRIEVE), ("path-retrieval-a",), (), True, 3, "Tenant A retrieval agent."),
        AgentIdentity(AGENT_TOOL_BROKER_A, AgentRole.TOOL_BROKER, "tenant-a", "tenant-runtime", "agent-platform", (CAP_TOOL_READ, CAP_TOOL_WRITE), ("path-tool-broker-a",), (), True, 3, "Tenant A tool broker."),
        AgentIdentity(AGENT_TOOL_EXECUTOR_A, AgentRole.TOOL_AGENT, "tenant-a", "tenant-runtime", "tool-security", (CAP_TOOL_READ, CAP_TOOL_WRITE), ("path-tool-executor-a",), (), True, 3, "Tenant A tool executor."),
        AgentIdentity(AGENT_RELEASE_ORCH, AgentRole.ORCHESTRATOR, "system", "release-control", "release-security", (CAP_MODEL_INSPECT, CAP_MODEL_DEPLOY), ("path-release-orchestrator",), ("route-release-promote",), True, 3, "Release delegation orchestrator."),
        AgentIdentity(AGENT_RELEASE, AgentRole.RELEASE_AGENT, "system", "release-control", "release-security", (CAP_MODEL_INSPECT, CAP_MODEL_DEPLOY), ("path-release-agent",), ("route-release-promote",), True, 3, "Release execution agent."),
        AgentIdentity(AGENT_SECURITY, AgentRole.SECURITY_AGENT, "system", "security-control", "security-platform", (CAP_TELEMETRY_READ, CAP_TELEMETRY_CONFIGURE, CAP_POLICY_READ, CAP_POLICY_WRITE), ("path-security-agent",), ("route-telemetry-update", "route-authz-update"), True, 3, "Security delegation orchestrator."),
        AgentIdentity(AGENT_OBSERVABILITY, AgentRole.OBSERVABILITY_AGENT, "system", "security-control", "security-observability", (CAP_TELEMETRY_READ, CAP_TELEMETRY_CONFIGURE), ("path-observability-agent",), ("route-telemetry-update",), True, 3, "Observability agent."),
        AgentIdentity(AGENT_POLICY, AgentRole.SECURITY_AGENT, "system", "security-control", "security-platform", (CAP_POLICY_READ, CAP_POLICY_WRITE), ("path-policy-controller",), ("route-authz-update",), True, 3, "Authorization-policy controller agent."),
    )


def _delegations() -> tuple[DelegationRecord, ...]:
    return (
        DelegationRecord("delegation-tool-root", None, "user-a", AGENT_ORCH_A, AGENT_TOOL_BROKER_A, "tool_lookup", "tenant-a", (CAP_TOOL_READ,), _hash("user-a-tool-request"), NOW - 120, NOW + 1800, "agent-platform", "Root tenant tool delegation."),
        DelegationRecord("delegation-tool-child", "delegation-tool-root", "user-a", AGENT_TOOL_BROKER_A, AGENT_TOOL_EXECUTOR_A, "tool_lookup", "tenant-a", (CAP_TOOL_READ,), _hash("user-a-tool-request"), NOW - 90, NOW + 1500, "tool-security", "Child tenant tool delegation."),
        DelegationRecord("delegation-retrieval", None, "user-a", AGENT_ORCH_A, AGENT_RETRIEVAL_A, "retrieve", "tenant-a", (CAP_SEARCH_READ, CAP_TENANT_RETRIEVE), _hash("user-a-retrieval-request"), NOW - 110, NOW + 1600, "agent-platform", "Tenant retrieval handoff."),
        DelegationRecord("delegation-release-inspect", None, "release-admin", AGENT_RELEASE_ORCH, AGENT_RELEASE, "release_inspect", "system", (CAP_MODEL_INSPECT,), _hash("release-inspect-request"), NOW - 100, NOW + 1200, "release-security", "Release inspection delegation."),
        DelegationRecord("delegation-release-deploy", None, "release-admin", AGENT_RELEASE_ORCH, AGENT_RELEASE, "model_release", "system", (CAP_MODEL_DEPLOY,), _hash("release-deploy-request"), NOW - 80, NOW + 900, "release-security", "Model deployment delegation."),
        DelegationRecord("delegation-telemetry-configure", None, "security-admin", AGENT_SECURITY, AGENT_OBSERVABILITY, "telemetry_change", "system", (CAP_TELEMETRY_CONFIGURE,), _hash("telemetry-change-request"), NOW - 70, NOW + 900, "security-observability", "Telemetry configuration delegation."),
        DelegationRecord("delegation-policy-write", None, "security-admin", AGENT_SECURITY, AGENT_POLICY, "policy_change", "system", (CAP_POLICY_WRITE,), _hash("policy-change-request"), NOW - 60, NOW + 900, "security-platform", "Authorization-policy delegation."),
    )


def make_upstreams(
    *,
    exposed_p7b_paths: frozenset[str] = frozenset(),
    exposed_p7h_routes: frozenset[str] = frozenset(),
    unsafe_p7i_invariants: frozenset[str] = frozenset(),
) -> dict[str, object]:
    p7b = SimpleNamespace(
        assessment_evidence_sha256=P7B_SHA,
        exact_identity_graph_binding_verified=True,
        privilege_amplification_derived_from_evidence=True,
        paths=tuple(SimpleNamespace(path_id=path_id, exposed=path_id in exposed_p7b_paths) for path_id in P7B_PATH_IDS),
    )
    p7h = SimpleNamespace(
        assessment_evidence_sha256=P7H_SHA,
        exact_control_plane_binding_verified=True,
        path_risk_derived_from_evidence=True,
        separation_of_duties_enforced=True,
        routes=tuple(SimpleNamespace(route_id=route_id, exposed=route_id in exposed_p7h_routes) for route_id in P7H_ROUTE_IDS),
    )
    p7i = SimpleNamespace(
        assessment_evidence_sha256=P7I_SHA,
        exact_catalog_binding_verified=True,
        blast_radius_derived_from_evidence=True,
        counterevidence_preserved=True,
        invariants=tuple(SimpleNamespace(invariant_id=invariant_id, state="violated" if invariant_id in unsafe_p7i_invariants else "holds") for invariant_id in P7I_INVARIANT_IDS),
    )
    return {"p7b": p7b, "p7h": p7h, "p7i": p7i}


def build_fixture() -> dict[str, object]:
    agents = _agents()
    capabilities = _capabilities()
    delegations = _delegations()
    manifest = AgentDelegationManifest(
        graph_id=GRAPH_ID,
        version=GRAPH_VERSION,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7h_assessment_evidence_sha256=P7H_SHA,
        p7i_assessment_evidence_sha256=P7I_SHA,
        created_at_epoch=NOW - 300,
        agents=agents,
        capabilities=capabilities,
        delegations=delegations,
    )
    graph_sha = agent_delegation_manifest_digest(manifest)
    policy = AgentDelegationPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=graph_sha,
        expected_p7b_assessment_evidence_sha256=P7B_SHA,
        expected_p7h_assessment_evidence_sha256=P7H_SHA,
        expected_p7i_assessment_evidence_sha256=P7I_SHA,
        required_agent_ids=frozenset(item.agent_id for item in agents),
        required_capability_ids=frozenset(item.capability_id for item in capabilities),
        required_delegation_ids=frozenset(item.delegation_id for item in delegations),
        trusted_owner_ids=frozenset({"agent-platform", "tool-security", "release-security", "security-platform", "security-observability"}),
        trusted_trust_domains=frozenset({"tenant-runtime", "release-control", "security-control"}),
        shared_agent_ids=frozenset({AGENT_RELEASE_ORCH, AGENT_RELEASE, AGENT_SECURITY, AGENT_OBSERVABILITY, AGENT_POLICY}),
        expected_agent_role={item.agent_id: item.role for item in agents},
        expected_agent_tenant={item.agent_id: item.tenant_id for item in agents},
        expected_agent_trust_domain={item.agent_id: item.trust_domain for item in agents},
        expected_agent_capability_ids={item.agent_id: frozenset(item.maximum_capability_ids) for item in agents},
        expected_agent_p7b_path_ids={item.agent_id: frozenset(item.p7b_path_ids) for item in agents},
        expected_agent_p7h_route_ids={item.agent_id: frozenset(item.p7h_route_ids) for item in agents},
        expected_agent_accepts_delegation={item.agent_id: item.accepts_delegation for item in agents},
        expected_agent_max_depth={item.agent_id: item.max_delegation_depth for item in agents},
        expected_capability_family={item.capability_id: item.family for item in capabilities},
        expected_capability_level={item.capability_id: item.privilege_level for item in capabilities},
        expected_capability_scope={item.capability_id: item.tenant_scope for item in capabilities},
        expected_capability_privileged={item.capability_id: item.privileged for item in capabilities},
        expected_capability_p7h_route_ids={item.capability_id: frozenset(item.required_p7h_route_ids) for item in capabilities},
        expected_capability_p7i_invariant_ids={item.capability_id: frozenset(item.required_p7i_invariant_ids) for item in capabilities},
        original_principal_tenant={"user-a": "tenant-a", "user-limited": "tenant-a", "release-admin": "system", "security-admin": "system"},
        original_principal_allowed_task_classes={
            "user-a": frozenset({"retrieve", "tool_lookup"}),
            "user-limited": frozenset({"tool_lookup"}),
            "release-admin": frozenset({"release_inspect", "model_release"}),
            "security-admin": frozenset({"telemetry_change", "policy_change"}),
        },
        original_principal_max_level_by_family={
            "user-a": {"search": 1, "retrieval": 1, "tool": 2},
            "user-limited": {"tool": 1},
            "release-admin": {"model": 3},
            "security-admin": {"telemetry": 3, "policy": 3},
        },
        max_chain_depth=3,
    )
    request = AgentDelegationRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=graph_sha,
        p7b_assessment_evidence_sha256=P7B_SHA,
        p7h_assessment_evidence_sha256=P7H_SHA,
        p7i_assessment_evidence_sha256=P7I_SHA,
        evaluated_at_epoch=NOW,
        delegation_ids=tuple(sorted(item.delegation_id for item in delegations)),
        declared_denied_delegation_ids=(),
        declared_risk_ids_by_delegation={item.delegation_id: () for item in delegations},
    )
    return {"manifest": manifest, "policy": policy, "request": request, **make_upstreams()}


def replace_manifest_item(manifest: AgentDelegationManifest, collection: str, item_id: str, **changes: object) -> AgentDelegationManifest:
    values = list(getattr(manifest, collection))
    key = {"agents": "agent_id", "capabilities": "capability_id", "delegations": "delegation_id"}[collection]
    for index, item in enumerate(values):
        if getattr(item, key) == item_id:
            values[index] = replace(item, **changes)
            return replace(manifest, **{collection: tuple(values)})
    raise KeyError(item_id)


def truthful_request_for_context(ctx: Mapping[str, object], denied: Mapping[str, tuple[DelegationRisk, ...]]) -> AgentDelegationRequest:
    request = ctx["request"]
    all_risks = {delegation_id: tuple(denied.get(delegation_id, ())) for delegation_id in request.delegation_ids}
    return replace(
        request,
        declared_denied_delegation_ids=tuple(sorted(delegation_id for delegation_id, risks in denied.items() if risks)),
        declared_risk_ids_by_delegation=all_risks,
    )
