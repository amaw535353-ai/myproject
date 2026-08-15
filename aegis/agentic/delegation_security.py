from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

P8A_DELEGATION_POLICY_VERSION = "multi-agent-delegation-authority-propagation-v1"
P8A_DELEGATION_SCHEMA_VERSION = "aegis-agent-delegation-manifest-v1"
P8A_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-delegation-security-assessment-v1"
P8A_ASSESSMENT_MODE = "deterministic-evidence-bound-agent-delegation-v1"


class AgentRole(StrEnum):
    ORCHESTRATOR = "orchestrator"
    RETRIEVAL_AGENT = "retrieval_agent"
    TOOL_BROKER = "tool_broker"
    TOOL_AGENT = "tool_agent"
    SECURITY_AGENT = "security_agent"
    RELEASE_AGENT = "release_agent"
    OBSERVABILITY_AGENT = "observability_agent"


class TenantScope(StrEnum):
    TENANT_BOUND = "tenant_bound"
    SYSTEM = "system"


class DelegationDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class DelegationRisk(StrEnum):
    SCOPE_AMPLIFICATION = "scope_amplification"
    CROSS_TENANT = "cross_tenant"
    CONFUSED_DEPUTY = "confused_deputy"
    CAPABILITY_LAUNDERING = "capability_laundering"
    CHAIN_TOO_DEEP = "chain_too_deep"
    CHAIN_DISCONTINUITY = "chain_discontinuity"
    IDENTITY_CONTINUITY = "identity_continuity"
    PROVENANCE_MISMATCH = "provenance_mismatch"
    EXPIRED = "expired"
    UPSTREAM_PRIVILEGE_EXPOSED = "upstream_privilege_exposed"
    CONTROL_PLANE_ROUTE_EXPOSED = "control_plane_route_exposed"
    ARCHITECTURE_INVARIANT_UNSAFE = "architecture_invariant_unsafe"
    TASK_NOT_AUTHORIZED = "task_not_authorized"
    UNTRUSTED_AGENT = "untrusted_agent"


class DelegationRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    P7B_UNVERIFIED = "p7b_unverified"
    P7B_DIGEST_MISMATCH = "p7b_digest_mismatch"
    P7H_UNVERIFIED = "p7h_unverified"
    P7H_DIGEST_MISMATCH = "p7h_digest_mismatch"
    P7I_UNVERIFIED = "p7i_unverified"
    P7I_DIGEST_MISMATCH = "p7i_digest_mismatch"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    AGENT_DUPLICATE = "agent_duplicate"
    AGENT_COVERAGE_MISMATCH = "agent_coverage_mismatch"
    AGENT_OWNER_UNTRUSTED = "agent_owner_untrusted"
    AGENT_ROLE_DRIFT = "agent_role_drift"
    AGENT_TENANT_DRIFT = "agent_tenant_drift"
    AGENT_TRUST_DOMAIN_DRIFT = "agent_trust_domain_drift"
    AGENT_CAPABILITY_DRIFT = "agent_capability_drift"
    AGENT_PRIVILEGE_PATH_DRIFT = "agent_privilege_path_drift"
    AGENT_PRIVILEGE_PATH_UNKNOWN = "agent_privilege_path_unknown"
    AGENT_CONTROL_ROUTE_DRIFT = "agent_control_route_drift"
    AGENT_CONTROL_ROUTE_UNKNOWN = "agent_control_route_unknown"
    AGENT_DELEGATION_FLAG_DRIFT = "agent_delegation_flag_drift"
    AGENT_DEPTH_DRIFT = "agent_depth_drift"
    CAPABILITY_DUPLICATE = "capability_duplicate"
    CAPABILITY_COVERAGE_MISMATCH = "capability_coverage_mismatch"
    CAPABILITY_FAMILY_DRIFT = "capability_family_drift"
    CAPABILITY_LEVEL_DRIFT = "capability_level_drift"
    CAPABILITY_SCOPE_DRIFT = "capability_scope_drift"
    CAPABILITY_PRIVILEGE_DRIFT = "capability_privilege_drift"
    CAPABILITY_ROUTE_DRIFT = "capability_route_drift"
    CAPABILITY_INVARIANT_DRIFT = "capability_invariant_drift"
    CAPABILITY_REFERENCE_UNKNOWN = "capability_reference_unknown"
    DELEGATION_DUPLICATE = "delegation_duplicate"
    DELEGATION_COVERAGE_MISMATCH = "delegation_coverage_mismatch"
    DELEGATION_OWNER_UNTRUSTED = "delegation_owner_untrusted"
    DELEGATION_REFERENCE_UNKNOWN = "delegation_reference_unknown"
    DELEGATION_CAPABILITY_UNKNOWN = "delegation_capability_unknown"
    DELEGATION_PARENT_UNKNOWN = "delegation_parent_unknown"
    DELEGATION_CYCLE = "delegation_cycle"
    DELEGATION_TIME_INVALID = "delegation_time_invalid"
    DELEGATION_PROVENANCE_INVALID = "delegation_provenance_invalid"
    ORIGINAL_PRINCIPAL_UNKNOWN = "original_principal_unknown"
    DECLARED_DECISION_MISMATCH = "declared_decision_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class DelegationSecurityRejected(ValueError):
    def __init__(
        self,
        reason: DelegationRejectReason,
        message: str,
        *,
        agent_id: str | None = None,
        capability_id: str | None = None,
        delegation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.agent_id = agent_id
        self.capability_id = capability_id
        self.delegation_id = delegation_id


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    role: AgentRole
    tenant_id: str
    trust_domain: str
    owner_id: str
    maximum_capability_ids: tuple[str, ...]
    p7b_path_ids: tuple[str, ...]
    p7h_route_ids: tuple[str, ...]
    accepts_delegation: bool
    max_delegation_depth: int
    description: str


@dataclass(frozen=True)
class AgentCapability:
    capability_id: str
    family: str
    privilege_level: int
    tenant_scope: TenantScope
    privileged: bool
    required_p7h_route_ids: tuple[str, ...]
    required_p7i_invariant_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class DelegationRecord:
    delegation_id: str
    parent_delegation_id: str | None
    original_principal_id: str
    delegator_agent_id: str
    delegatee_agent_id: str
    task_class: str
    tenant_id: str
    requested_capability_ids: tuple[str, ...]
    original_request_sha256: str
    issued_at_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentDelegationManifest:
    graph_id: str
    version: str
    p7b_assessment_evidence_sha256: str
    p7h_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    created_at_epoch: int
    agents: tuple[AgentIdentity, ...]
    capabilities: tuple[AgentCapability, ...]
    delegations: tuple[DelegationRecord, ...]
    schema_version: str = P8A_DELEGATION_SCHEMA_VERSION


@dataclass(frozen=True)
class AgentDelegationRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p7b_assessment_evidence_sha256: str
    p7h_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    delegation_ids: tuple[str, ...]
    declared_denied_delegation_ids: tuple[str, ...]
    declared_risk_ids_by_delegation: Mapping[str, tuple[DelegationRisk, ...]]


@dataclass(frozen=True)
class AgentDelegationPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p7b_assessment_evidence_sha256: str
    expected_p7h_assessment_evidence_sha256: str
    expected_p7i_assessment_evidence_sha256: str
    required_agent_ids: frozenset[str]
    required_capability_ids: frozenset[str]
    required_delegation_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    trusted_trust_domains: frozenset[str]
    shared_agent_ids: frozenset[str]
    expected_agent_role: Mapping[str, AgentRole]
    expected_agent_tenant: Mapping[str, str]
    expected_agent_trust_domain: Mapping[str, str]
    expected_agent_capability_ids: Mapping[str, frozenset[str]]
    expected_agent_p7b_path_ids: Mapping[str, frozenset[str]]
    expected_agent_p7h_route_ids: Mapping[str, frozenset[str]]
    expected_agent_accepts_delegation: Mapping[str, bool]
    expected_agent_max_depth: Mapping[str, int]
    expected_capability_family: Mapping[str, str]
    expected_capability_level: Mapping[str, int]
    expected_capability_scope: Mapping[str, TenantScope]
    expected_capability_privileged: Mapping[str, bool]
    expected_capability_p7h_route_ids: Mapping[str, frozenset[str]]
    expected_capability_p7i_invariant_ids: Mapping[str, frozenset[str]]
    original_principal_tenant: Mapping[str, str]
    original_principal_allowed_task_classes: Mapping[str, frozenset[str]]
    original_principal_max_level_by_family: Mapping[str, Mapping[str, int]]
    max_chain_depth: int = 4
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class DelegationSecurityFact:
    delegation_id: str
    parent_delegation_id: str | None
    original_principal_id: str
    delegator_agent_id: str
    delegatee_agent_id: str
    task_class: str
    tenant_id: str
    chain_depth: int
    requested_capability_ids: tuple[str, ...]
    requested_families: tuple[str, ...]
    decision: DelegationDecision
    risks: tuple[DelegationRisk, ...]
    effective_delegator_capability_ids: tuple[str, ...]
    delegatee_maximum_capability_ids: tuple[str, ...]
    p7b_path_ids: tuple[str, ...]
    p7h_route_ids: tuple[str, ...]
    p7i_invariant_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedAgentDelegationAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p7b_assessment_evidence_sha256: str
    p7h_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    delegation_count: int
    allowed_delegation_count: int
    denied_delegation_count: int
    cross_tenant_denial_count: int
    confused_deputy_denial_count: int
    capability_laundering_denial_count: int
    scope_amplification_denial_count: int
    prioritized_denied_delegation_ids: tuple[str, ...]
    delegations: tuple[DelegationSecurityFact, ...]
    assessment_evidence_sha256: str
    exact_delegation_graph_binding_verified: bool = True
    exact_p7b_assessment_binding_verified: bool = True
    exact_p7h_assessment_binding_verified: bool = True
    exact_p7i_assessment_binding_verified: bool = True
    agent_identity_continuity_verified: bool = True
    tenant_continuity_verified: bool = True
    authority_non_amplification_verified: bool = True
    capability_laundering_detection_enabled: bool = True
    confused_deputy_detection_enabled: bool = True
    caller_declared_delegation_authorization_trusted: bool = False
    production_agent_identity_attestation: bool = False
    production_multi_agent_protocol_enforcement: bool = False
    production_iam_enforcement: bool = False
    cryptographic_delegation_tokens: bool = False
    exhaustive_agent_behavior_coverage: bool = False
    formal_delegation_proof: bool = False
    network_operations: int = 0
    schema_version: str = P8A_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8A_DELEGATION_POLICY_VERSION
    assessment_mode: str = P8A_ASSESSMENT_MODE


def _reject(reason: DelegationRejectReason, message: str, **context: str | None) -> None:
    raise DelegationSecurityRejected(reason, message, **context)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _assessment_digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _verified(value: object, *flags: str) -> bool:
    return all(bool(getattr(value, flag, False)) for flag in flags)


def canonical_agent_delegation_manifest_bytes(manifest: AgentDelegationManifest) -> bytes:
    document = {
        "agents": [
            {
                "accepts_delegation": item.accepts_delegation,
                "agent_id": item.agent_id,
                "description": item.description,
                "max_delegation_depth": item.max_delegation_depth,
                "maximum_capability_ids": sorted(item.maximum_capability_ids),
                "owner_id": item.owner_id,
                "p7b_path_ids": sorted(item.p7b_path_ids),
                "p7h_route_ids": sorted(item.p7h_route_ids),
                "role": item.role.value,
                "tenant_id": item.tenant_id,
                "trust_domain": item.trust_domain,
            }
            for item in sorted(manifest.agents, key=lambda value: value.agent_id)
        ],
        "capabilities": [
            {
                "capability_id": item.capability_id,
                "description": item.description,
                "family": item.family,
                "privilege_level": item.privilege_level,
                "privileged": item.privileged,
                "required_p7h_route_ids": sorted(item.required_p7h_route_ids),
                "required_p7i_invariant_ids": sorted(item.required_p7i_invariant_ids),
                "tenant_scope": item.tenant_scope.value,
            }
            for item in sorted(manifest.capabilities, key=lambda value: value.capability_id)
        ],
        "created_at_epoch": manifest.created_at_epoch,
        "delegations": [
            {
                "delegatee_agent_id": item.delegatee_agent_id,
                "delegation_id": item.delegation_id,
                "delegator_agent_id": item.delegator_agent_id,
                "description": item.description,
                "expires_at_epoch": item.expires_at_epoch,
                "issued_at_epoch": item.issued_at_epoch,
                "original_principal_id": item.original_principal_id,
                "original_request_sha256": item.original_request_sha256.casefold(),
                "owner_id": item.owner_id,
                "parent_delegation_id": item.parent_delegation_id,
                "requested_capability_ids": sorted(item.requested_capability_ids),
                "task_class": item.task_class,
                "tenant_id": item.tenant_id,
            }
            for item in sorted(manifest.delegations, key=lambda value: value.delegation_id)
        ],
        "graph_id": manifest.graph_id,
        "p7b_assessment_evidence_sha256": manifest.p7b_assessment_evidence_sha256.casefold(),
        "p7h_assessment_evidence_sha256": manifest.p7h_assessment_evidence_sha256.casefold(),
        "p7i_assessment_evidence_sha256": manifest.p7i_assessment_evidence_sha256.casefold(),
        "schema_version": manifest.schema_version,
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def agent_delegation_manifest_digest(manifest: AgentDelegationManifest) -> str:
    return hashlib.sha256(canonical_agent_delegation_manifest_bytes(manifest)).hexdigest()


def _validate_policy(policy: AgentDelegationPolicy) -> None:
    hashes = (
        policy.expected_graph_sha256,
        policy.expected_p7b_assessment_evidence_sha256,
        policy.expected_p7h_assessment_evidence_sha256,
        policy.expected_p7i_assessment_evidence_sha256,
    )
    if (
        not policy.expected_graph_id
        or not policy.expected_graph_version
        or not all(_is_sha256(value) for value in hashes)
        or not policy.required_agent_ids
        or not policy.required_capability_ids
        or not policy.required_delegation_ids
        or not policy.trusted_owner_ids
        or not policy.trusted_trust_domains
        or policy.max_chain_depth <= 0
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
    ):
        _reject(DelegationRejectReason.POLICY_INVALID, "delegation policy metadata is invalid")

    agent_maps = (
        policy.expected_agent_role,
        policy.expected_agent_tenant,
        policy.expected_agent_trust_domain,
        policy.expected_agent_capability_ids,
        policy.expected_agent_p7b_path_ids,
        policy.expected_agent_p7h_route_ids,
        policy.expected_agent_accepts_delegation,
        policy.expected_agent_max_depth,
    )
    if any(set(mapping) != set(policy.required_agent_ids) for mapping in agent_maps):
        _reject(DelegationRejectReason.POLICY_INVALID, "agent policy maps must exactly cover required agents")

    capability_maps = (
        policy.expected_capability_family,
        policy.expected_capability_level,
        policy.expected_capability_scope,
        policy.expected_capability_privileged,
        policy.expected_capability_p7h_route_ids,
        policy.expected_capability_p7i_invariant_ids,
    )
    if any(set(mapping) != set(policy.required_capability_ids) for mapping in capability_maps):
        _reject(DelegationRejectReason.POLICY_INVALID, "capability policy maps must exactly cover required capabilities")
    if any(value <= 0 for value in policy.expected_capability_level.values()):
        _reject(DelegationRejectReason.POLICY_INVALID, "capability privilege levels must be positive")
    if any(value <= 0 or value > policy.max_chain_depth for value in policy.expected_agent_max_depth.values()):
        _reject(DelegationRejectReason.POLICY_INVALID, "agent delegation depth is outside the global policy bound")

    principal_ids = set(policy.original_principal_tenant)
    if not principal_ids or set(policy.original_principal_allowed_task_classes) != principal_ids or set(policy.original_principal_max_level_by_family) != principal_ids:
        _reject(DelegationRejectReason.POLICY_INVALID, "original-principal policy maps must have identical coverage")
    if any(not tasks for tasks in policy.original_principal_allowed_task_classes.values()):
        _reject(DelegationRejectReason.POLICY_INVALID, "every original principal must have at least one allowed task class")
    if any(not family_levels or any(level <= 0 for level in family_levels.values()) for family_levels in policy.original_principal_max_level_by_family.values()):
        _reject(DelegationRejectReason.POLICY_INVALID, "original-principal authority maps are invalid")


def _unique_inventory(items: tuple[object, ...], attribute: str, reason: DelegationRejectReason) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in items:
        object_id = str(getattr(item, attribute, ""))
        if not object_id or object_id in result:
            _reject(reason, "upstream evidence contains duplicate or empty identifiers")
        result[object_id] = item
    if not result:
        _reject(reason, "upstream evidence inventory is empty")
    return result


def _validate_upstreams(policy: AgentDelegationPolicy, p7b: object, p7h: object, p7i: object) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    if not _verified(p7b, "exact_identity_graph_binding_verified", "privilege_amplification_derived_from_evidence"):
        _reject(DelegationRejectReason.P7B_UNVERIFIED, "P7-B privilege evidence is not fully verified")
    if _assessment_digest(p7b) != policy.expected_p7b_assessment_evidence_sha256.casefold():
        _reject(DelegationRejectReason.P7B_DIGEST_MISMATCH, "P7-B evidence digest does not match delegation policy")

    if not _verified(p7h, "exact_control_plane_binding_verified", "path_risk_derived_from_evidence", "separation_of_duties_enforced"):
        _reject(DelegationRejectReason.P7H_UNVERIFIED, "P7-H control-plane evidence is not fully verified")
    if _assessment_digest(p7h) != policy.expected_p7h_assessment_evidence_sha256.casefold():
        _reject(DelegationRejectReason.P7H_DIGEST_MISMATCH, "P7-H evidence digest does not match delegation policy")

    if not _verified(p7i, "exact_catalog_binding_verified", "blast_radius_derived_from_evidence", "counterevidence_preserved"):
        _reject(DelegationRejectReason.P7I_UNVERIFIED, "P7-I invariant evidence is not fully verified")
    if _assessment_digest(p7i) != policy.expected_p7i_assessment_evidence_sha256.casefold():
        _reject(DelegationRejectReason.P7I_DIGEST_MISMATCH, "P7-I evidence digest does not match delegation policy")

    p7b_paths = _unique_inventory(tuple(getattr(p7b, "paths", ())), "path_id", DelegationRejectReason.P7B_UNVERIFIED)
    p7h_routes = _unique_inventory(tuple(getattr(p7h, "routes", ())), "route_id", DelegationRejectReason.P7H_UNVERIFIED)
    p7i_invariants = _unique_inventory(tuple(getattr(p7i, "invariants", ())), "invariant_id", DelegationRejectReason.P7I_UNVERIFIED)
    return p7b_paths, p7h_routes, p7i_invariants


def _validate_manifest(
    policy: AgentDelegationPolicy,
    request: AgentDelegationRequest,
    manifest: AgentDelegationManifest,
    p7b_paths: Mapping[str, object],
    p7h_routes: Mapping[str, object],
    p7i_invariants: Mapping[str, object],
) -> tuple[dict[str, AgentIdentity], dict[str, AgentCapability], dict[str, DelegationRecord], str]:
    if (
        manifest.schema_version != P8A_DELEGATION_SCHEMA_VERSION
        or manifest.graph_id != policy.expected_graph_id
        or manifest.version != policy.expected_graph_version
        or not manifest.agents
        or not manifest.capabilities
        or not manifest.delegations
    ):
        _reject(DelegationRejectReason.MANIFEST_INVALID, "delegation manifest metadata is invalid")
    pins = (
        (manifest.p7b_assessment_evidence_sha256, policy.expected_p7b_assessment_evidence_sha256),
        (manifest.p7h_assessment_evidence_sha256, policy.expected_p7h_assessment_evidence_sha256),
        (manifest.p7i_assessment_evidence_sha256, policy.expected_p7i_assessment_evidence_sha256),
    )
    if any(left.casefold() != right.casefold() for left, right in pins):
        _reject(DelegationRejectReason.MANIFEST_INVALID, "delegation manifest upstream evidence pins are invalid")
    if manifest.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        _reject(DelegationRejectReason.MANIFEST_FUTURE, "delegation manifest is future-dated")
    if request.evaluated_at_epoch - manifest.created_at_epoch > policy.max_manifest_age_seconds:
        _reject(DelegationRejectReason.MANIFEST_STALE, "delegation manifest is stale")
    actual_sha = agent_delegation_manifest_digest(manifest)
    if not hmac.compare_digest(actual_sha, policy.expected_graph_sha256.casefold()) or not hmac.compare_digest(actual_sha, request.graph_sha256.casefold()):
        _reject(DelegationRejectReason.MANIFEST_DIGEST_MISMATCH, "delegation manifest digest does not match request/policy")

    agents: dict[str, AgentIdentity] = {}
    for agent in manifest.agents:
        if not agent.agent_id or agent.agent_id in agents:
            _reject(DelegationRejectReason.AGENT_DUPLICATE, "agent is duplicate or empty", agent_id=agent.agent_id or None)
        agents[agent.agent_id] = agent
    if set(agents) != set(policy.required_agent_ids):
        _reject(DelegationRejectReason.AGENT_COVERAGE_MISMATCH, "agent coverage differs from policy")
    for agent_id, agent in agents.items():
        if agent.owner_id not in policy.trusted_owner_ids or agent.trust_domain not in policy.trusted_trust_domains:
            _reject(DelegationRejectReason.AGENT_OWNER_UNTRUSTED, "agent owner/trust domain is untrusted", agent_id=agent_id)
        if agent.role != policy.expected_agent_role[agent_id]:
            _reject(DelegationRejectReason.AGENT_ROLE_DRIFT, "agent role differs from policy", agent_id=agent_id)
        if agent.tenant_id != policy.expected_agent_tenant[agent_id]:
            _reject(DelegationRejectReason.AGENT_TENANT_DRIFT, "agent tenant differs from policy", agent_id=agent_id)
        if agent.trust_domain != policy.expected_agent_trust_domain[agent_id]:
            _reject(DelegationRejectReason.AGENT_TRUST_DOMAIN_DRIFT, "agent trust domain differs from policy", agent_id=agent_id)
        if set(agent.maximum_capability_ids) != set(policy.expected_agent_capability_ids[agent_id]) or len(set(agent.maximum_capability_ids)) != len(agent.maximum_capability_ids):
            _reject(DelegationRejectReason.AGENT_CAPABILITY_DRIFT, "agent maximum capabilities differ from policy", agent_id=agent_id)
        if set(agent.p7b_path_ids) != set(policy.expected_agent_p7b_path_ids[agent_id]) or len(set(agent.p7b_path_ids)) != len(agent.p7b_path_ids):
            _reject(DelegationRejectReason.AGENT_PRIVILEGE_PATH_DRIFT, "agent P7-B privilege paths differ from policy", agent_id=agent_id)
        if any(path_id not in p7b_paths for path_id in agent.p7b_path_ids):
            _reject(DelegationRejectReason.AGENT_PRIVILEGE_PATH_UNKNOWN, "agent references unknown P7-B path", agent_id=agent_id)
        if set(agent.p7h_route_ids) != set(policy.expected_agent_p7h_route_ids[agent_id]) or len(set(agent.p7h_route_ids)) != len(agent.p7h_route_ids):
            _reject(DelegationRejectReason.AGENT_CONTROL_ROUTE_DRIFT, "agent P7-H routes differ from policy", agent_id=agent_id)
        if any(route_id not in p7h_routes for route_id in agent.p7h_route_ids):
            _reject(DelegationRejectReason.AGENT_CONTROL_ROUTE_UNKNOWN, "agent references unknown P7-H route", agent_id=agent_id)
        if agent.accepts_delegation != policy.expected_agent_accepts_delegation[agent_id]:
            _reject(DelegationRejectReason.AGENT_DELEGATION_FLAG_DRIFT, "agent delegation acceptance differs from policy", agent_id=agent_id)
        if agent.max_delegation_depth != policy.expected_agent_max_depth[agent_id] or agent.max_delegation_depth <= 0 or agent.max_delegation_depth > policy.max_chain_depth:
            _reject(DelegationRejectReason.AGENT_DEPTH_DRIFT, "agent delegation depth differs from policy", agent_id=agent_id)

    capabilities: dict[str, AgentCapability] = {}
    for capability in manifest.capabilities:
        if not capability.capability_id or capability.capability_id in capabilities:
            _reject(DelegationRejectReason.CAPABILITY_DUPLICATE, "capability is duplicate or empty", capability_id=capability.capability_id or None)
        capabilities[capability.capability_id] = capability
    if set(capabilities) != set(policy.required_capability_ids):
        _reject(DelegationRejectReason.CAPABILITY_COVERAGE_MISMATCH, "capability coverage differs from policy")
    for capability_id, capability in capabilities.items():
        if capability.family != policy.expected_capability_family[capability_id]:
            _reject(DelegationRejectReason.CAPABILITY_FAMILY_DRIFT, "capability family differs from policy", capability_id=capability_id)
        if capability.privilege_level != policy.expected_capability_level[capability_id] or capability.privilege_level <= 0:
            _reject(DelegationRejectReason.CAPABILITY_LEVEL_DRIFT, "capability privilege level differs from policy", capability_id=capability_id)
        if capability.tenant_scope != policy.expected_capability_scope[capability_id]:
            _reject(DelegationRejectReason.CAPABILITY_SCOPE_DRIFT, "capability tenant scope differs from policy", capability_id=capability_id)
        if capability.privileged != policy.expected_capability_privileged[capability_id]:
            _reject(DelegationRejectReason.CAPABILITY_PRIVILEGE_DRIFT, "capability privilege flag differs from policy", capability_id=capability_id)
        if set(capability.required_p7h_route_ids) != set(policy.expected_capability_p7h_route_ids[capability_id]):
            _reject(DelegationRejectReason.CAPABILITY_ROUTE_DRIFT, "capability control-plane routes differ from policy", capability_id=capability_id)
        if set(capability.required_p7i_invariant_ids) != set(policy.expected_capability_p7i_invariant_ids[capability_id]):
            _reject(DelegationRejectReason.CAPABILITY_INVARIANT_DRIFT, "capability invariants differ from policy", capability_id=capability_id)
        if any(route_id not in p7h_routes for route_id in capability.required_p7h_route_ids) or any(invariant_id not in p7i_invariants for invariant_id in capability.required_p7i_invariant_ids):
            _reject(DelegationRejectReason.CAPABILITY_REFERENCE_UNKNOWN, "capability references unknown P7-H/P7-I evidence", capability_id=capability_id)
    for agent_id, agent in agents.items():
        if any(capability_id not in capabilities for capability_id in agent.maximum_capability_ids):
            _reject(DelegationRejectReason.AGENT_CAPABILITY_DRIFT, "agent references unknown capability", agent_id=agent_id)

    delegations: dict[str, DelegationRecord] = {}
    for delegation in manifest.delegations:
        if not delegation.delegation_id or delegation.delegation_id in delegations:
            _reject(DelegationRejectReason.DELEGATION_DUPLICATE, "delegation is duplicate or empty", delegation_id=delegation.delegation_id or None)
        delegations[delegation.delegation_id] = delegation
    if set(delegations) != set(policy.required_delegation_ids):
        _reject(DelegationRejectReason.DELEGATION_COVERAGE_MISMATCH, "delegation coverage differs from policy")
    for delegation_id, delegation in delegations.items():
        if delegation.owner_id not in policy.trusted_owner_ids:
            _reject(DelegationRejectReason.DELEGATION_OWNER_UNTRUSTED, "delegation owner is untrusted", delegation_id=delegation_id)
        if delegation.delegator_agent_id not in agents or delegation.delegatee_agent_id not in agents:
            _reject(DelegationRejectReason.DELEGATION_REFERENCE_UNKNOWN, "delegation references unknown agent", delegation_id=delegation_id)
        if delegation.original_principal_id not in policy.original_principal_tenant:
            _reject(DelegationRejectReason.ORIGINAL_PRINCIPAL_UNKNOWN, "delegation references unknown original principal", delegation_id=delegation_id)
        if not delegation.requested_capability_ids or len(set(delegation.requested_capability_ids)) != len(delegation.requested_capability_ids) or any(capability_id not in capabilities for capability_id in delegation.requested_capability_ids):
            _reject(DelegationRejectReason.DELEGATION_CAPABILITY_UNKNOWN, "delegation capabilities are empty, duplicate, or unknown", delegation_id=delegation_id)
        if delegation.parent_delegation_id is not None and delegation.parent_delegation_id not in delegations:
            _reject(DelegationRejectReason.DELEGATION_PARENT_UNKNOWN, "delegation parent is unknown", delegation_id=delegation_id)
        if not _is_sha256(delegation.original_request_sha256):
            _reject(DelegationRejectReason.DELEGATION_PROVENANCE_INVALID, "delegation original request digest is invalid", delegation_id=delegation_id)
        if delegation.issued_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds or delegation.expires_at_epoch <= delegation.issued_at_epoch:
            _reject(DelegationRejectReason.DELEGATION_TIME_INVALID, "delegation timestamps are invalid", delegation_id=delegation_id)

    for delegation_id in delegations:
        seen: set[str] = set()
        current: str | None = delegation_id
        while current is not None:
            if current in seen:
                _reject(DelegationRejectReason.DELEGATION_CYCLE, "delegation graph contains a cycle", delegation_id=delegation_id)
            seen.add(current)
            current = delegations[current].parent_delegation_id
            if len(seen) > policy.max_chain_depth + 1:
                break
    return agents, capabilities, delegations, actual_sha


def _unsafe_p7b(path: object) -> bool:
    return bool(getattr(path, "exposed", False))


def _unsafe_p7h(route: object) -> bool:
    return bool(getattr(route, "exposed", False))


def _unsafe_p7i(invariant: object) -> bool:
    state = str(getattr(getattr(invariant, "state", "holds"), "value", getattr(invariant, "state", "holds"))).casefold()
    return state in {"degraded", "violated"}


def _max_level_by_family(capability_ids: set[str], capabilities: Mapping[str, AgentCapability]) -> dict[str, int]:
    result: dict[str, int] = {}
    for capability_id in capability_ids:
        capability = capabilities[capability_id]
        result[capability.family] = max(result.get(capability.family, 0), capability.privilege_level)
    return result


def _risk_priority(risk: DelegationRisk) -> int:
    return {
        DelegationRisk.CROSS_TENANT: 100,
        DelegationRisk.CONFUSED_DEPUTY: 95,
        DelegationRisk.CAPABILITY_LAUNDERING: 90,
        DelegationRisk.SCOPE_AMPLIFICATION: 85,
        DelegationRisk.UPSTREAM_PRIVILEGE_EXPOSED: 80,
        DelegationRisk.CONTROL_PLANE_ROUTE_EXPOSED: 78,
        DelegationRisk.ARCHITECTURE_INVARIANT_UNSAFE: 76,
        DelegationRisk.IDENTITY_CONTINUITY: 74,
        DelegationRisk.PROVENANCE_MISMATCH: 72,
        DelegationRisk.CHAIN_DISCONTINUITY: 70,
        DelegationRisk.CHAIN_TOO_DEEP: 68,
        DelegationRisk.TASK_NOT_AUTHORIZED: 65,
        DelegationRisk.UNTRUSTED_AGENT: 60,
        DelegationRisk.EXPIRED: 50,
    }[risk]


class MultiAgentDelegationSecurityAnalyzer:
    def __init__(self, policy: AgentDelegationPolicy) -> None:
        _validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: AgentDelegationRequest,
        manifest: AgentDelegationManifest,
        p7b_assessment: object,
        p7h_assessment: object,
        p7i_assessment: object,
    ) -> VerifiedAgentDelegationAssessment:
        request_pins = (
            request.graph_sha256,
            request.p7b_assessment_evidence_sha256,
            request.p7h_assessment_evidence_sha256,
            request.p7i_assessment_evidence_sha256,
        )
        expected_pins = (
            self.policy.expected_graph_sha256,
            self.policy.expected_p7b_assessment_evidence_sha256,
            self.policy.expected_p7h_assessment_evidence_sha256,
            self.policy.expected_p7i_assessment_evidence_sha256,
        )
        if (
            request.graph_id != self.policy.expected_graph_id
            or request.graph_version != self.policy.expected_graph_version
            or not all(_is_sha256(value) for value in request_pins)
            or any(left.casefold() != right.casefold() for left, right in zip(request_pins, expected_pins))
            or set(request.delegation_ids) != set(self.policy.required_delegation_ids)
            or len(set(request.delegation_ids)) != len(request.delegation_ids)
        ):
            _reject(DelegationRejectReason.REQUEST_INVALID, "delegation request identity/evidence/scope is invalid")

        p7b_paths, p7h_routes, p7i_invariants = _validate_upstreams(self.policy, p7b_assessment, p7h_assessment, p7i_assessment)
        agents, capabilities, delegations, graph_sha = _validate_manifest(self.policy, request, manifest, p7b_paths, p7h_routes, p7i_invariants)

        facts: list[DelegationSecurityFact] = []
        effective_capabilities: dict[str, set[str]] = {}
        depths: dict[str, int] = {}

        def evaluate_record(delegation_id: str, stack: tuple[str, ...] = ()) -> None:
            if delegation_id in effective_capabilities:
                return
            if delegation_id in stack:
                _reject(DelegationRejectReason.DELEGATION_CYCLE, "delegation cycle detected during evaluation", delegation_id=delegation_id)
            record = delegations[delegation_id]
            risks: list[DelegationRisk] = []
            delegator = agents[record.delegator_agent_id]
            delegatee = agents[record.delegatee_agent_id]
            requested = set(record.requested_capability_ids)

            parent: DelegationRecord | None = None
            parent_effective: set[str] | None = None
            parent_depth = 0
            if record.parent_delegation_id is not None:
                evaluate_record(record.parent_delegation_id, stack + (delegation_id,))
                parent = delegations[record.parent_delegation_id]
                parent_effective = effective_capabilities[record.parent_delegation_id]
                parent_depth = depths[record.parent_delegation_id]
            depth = parent_depth + 1
            depths[delegation_id] = depth

            if depth > self.policy.max_chain_depth or depth > delegator.max_delegation_depth or depth > delegatee.max_delegation_depth:
                risks.append(DelegationRisk.CHAIN_TOO_DEEP)
            if not delegatee.accepts_delegation:
                risks.append(DelegationRisk.UNTRUSTED_AGENT)

            principal_tenant = self.policy.original_principal_tenant[record.original_principal_id]
            if record.tenant_id != principal_tenant:
                risks.append(DelegationRisk.CROSS_TENANT)
            if delegator.tenant_id not in {record.tenant_id, "system"} or delegatee.tenant_id not in {record.tenant_id, "system"}:
                risks.append(DelegationRisk.CROSS_TENANT)
            if (delegator.agent_id in self.policy.shared_agent_ids or delegatee.agent_id in self.policy.shared_agent_ids) and record.tenant_id != "system":
                if any(capabilities[capability_id].tenant_scope == TenantScope.TENANT_BOUND for capability_id in requested):
                    risks.append(DelegationRisk.CROSS_TENANT)

            if record.task_class not in self.policy.original_principal_allowed_task_classes[record.original_principal_id]:
                risks.append(DelegationRisk.TASK_NOT_AUTHORIZED)

            if parent is not None:
                if parent.delegatee_agent_id != record.delegator_agent_id:
                    risks.append(DelegationRisk.CHAIN_DISCONTINUITY)
                if parent.original_principal_id != record.original_principal_id or parent.tenant_id != record.tenant_id:
                    risks.append(DelegationRisk.IDENTITY_CONTINUITY)
                if parent.original_request_sha256.casefold() != record.original_request_sha256.casefold():
                    risks.append(DelegationRisk.PROVENANCE_MISMATCH)
                if record.issued_at_epoch < parent.issued_at_epoch or record.expires_at_epoch > parent.expires_at_epoch:
                    risks.append(DelegationRisk.PROVENANCE_MISMATCH)
            if record.expires_at_epoch <= request.evaluated_at_epoch:
                risks.append(DelegationRisk.EXPIRED)

            principal_levels = self.policy.original_principal_max_level_by_family[record.original_principal_id]
            for capability_id in requested:
                capability = capabilities[capability_id]
                if capability.family not in principal_levels or capability.privilege_level > principal_levels[capability.family]:
                    risks.append(DelegationRisk.CONFUSED_DEPUTY)

            delegator_max = set(delegator.maximum_capability_ids)
            delegatee_max = set(delegatee.maximum_capability_ids)
            if not requested.issubset(delegatee_max):
                risks.append(DelegationRisk.SCOPE_AMPLIFICATION)
            if parent_effective is None:
                if not requested.issubset(delegator_max):
                    risks.append(DelegationRisk.SCOPE_AMPLIFICATION)
            else:
                parent_levels = _max_level_by_family(parent_effective, capabilities)
                for capability_id in requested:
                    capability = capabilities[capability_id]
                    if capability.family not in parent_levels or capability.privilege_level > parent_levels[capability.family]:
                        risks.append(DelegationRisk.CAPABILITY_LAUNDERING)
                if not requested.issubset(delegator_max):
                    risks.append(DelegationRisk.SCOPE_AMPLIFICATION)

            required_p7b = set(delegator.p7b_path_ids) | set(delegatee.p7b_path_ids)
            if any(_unsafe_p7b(p7b_paths[path_id]) for path_id in required_p7b):
                risks.append(DelegationRisk.UPSTREAM_PRIVILEGE_EXPOSED)

            required_routes: set[str] = set()
            required_invariants: set[str] = set()
            for capability_id in requested:
                capability = capabilities[capability_id]
                required_routes.update(capability.required_p7h_route_ids)
                required_invariants.update(capability.required_p7i_invariant_ids)
                if capability.privileged and not capability.required_p7i_invariant_ids:
                    risks.append(DelegationRisk.ARCHITECTURE_INVARIANT_UNSAFE)
            if not required_routes.issubset(set(delegator.p7h_route_ids) | set(delegatee.p7h_route_ids)):
                risks.append(DelegationRisk.SCOPE_AMPLIFICATION)
            if any(_unsafe_p7h(p7h_routes[route_id]) for route_id in required_routes):
                risks.append(DelegationRisk.CONTROL_PLANE_ROUTE_EXPOSED)
            if any(_unsafe_p7i(p7i_invariants[invariant_id]) for invariant_id in required_invariants):
                risks.append(DelegationRisk.ARCHITECTURE_INVARIANT_UNSAFE)

            unique_risks = tuple(sorted(set(risks), key=lambda value: (-_risk_priority(value), value.value)))
            decision = DelegationDecision.DENY if unique_risks else DelegationDecision.ALLOW
            effective = requested if decision == DelegationDecision.ALLOW else set()
            effective_capabilities[delegation_id] = effective
            facts.append(
                DelegationSecurityFact(
                    delegation_id=delegation_id,
                    parent_delegation_id=record.parent_delegation_id,
                    original_principal_id=record.original_principal_id,
                    delegator_agent_id=record.delegator_agent_id,
                    delegatee_agent_id=record.delegatee_agent_id,
                    task_class=record.task_class,
                    tenant_id=record.tenant_id,
                    chain_depth=depth,
                    requested_capability_ids=tuple(sorted(requested)),
                    requested_families=tuple(sorted({capabilities[capability_id].family for capability_id in requested})),
                    decision=decision,
                    risks=unique_risks,
                    effective_delegator_capability_ids=tuple(sorted(parent_effective if parent_effective is not None else delegator_max)),
                    delegatee_maximum_capability_ids=tuple(sorted(delegatee_max)),
                    p7b_path_ids=tuple(sorted(required_p7b)),
                    p7h_route_ids=tuple(sorted(required_routes)),
                    p7i_invariant_ids=tuple(sorted(required_invariants)),
                )
            )

        for delegation_id in sorted(delegations):
            evaluate_record(delegation_id)

        by_id = {fact.delegation_id: fact for fact in facts}
        ordered_facts = tuple(by_id[delegation_id] for delegation_id in sorted(by_id))
        denied = tuple(fact.delegation_id for fact in ordered_facts if fact.decision == DelegationDecision.DENY)
        if set(request.declared_denied_delegation_ids) != set(denied):
            _reject(DelegationRejectReason.DECLARED_DECISION_MISMATCH, "caller-declared denied delegations differ from derived evidence")
        if set(request.declared_risk_ids_by_delegation) != set(request.delegation_ids):
            _reject(DelegationRejectReason.DECLARED_RISK_MISMATCH, "caller risk map must exactly cover delegation IDs")
        for fact in ordered_facts:
            declared = tuple(request.declared_risk_ids_by_delegation[fact.delegation_id])
            if set(declared) != set(fact.risks) or len(set(declared)) != len(declared):
                _reject(DelegationRejectReason.DECLARED_RISK_MISMATCH, "caller-declared delegation risks differ from derived evidence", delegation_id=fact.delegation_id)

        prioritized = tuple(
            fact.delegation_id
            for fact in sorted(
                (fact for fact in ordered_facts if fact.decision == DelegationDecision.DENY),
                key=lambda value: (-(max((_risk_priority(risk) for risk in value.risks), default=0)), value.delegation_id),
            )
        )
        evidence_document = {
            "delegations": [asdict(fact) for fact in ordered_facts],
            "graph_sha256": graph_sha,
            "p7b_assessment_evidence_sha256": _assessment_digest(p7b_assessment),
            "p7h_assessment_evidence_sha256": _assessment_digest(p7h_assessment),
            "p7i_assessment_evidence_sha256": _assessment_digest(p7i_assessment),
            "prioritized_denied_delegation_ids": list(prioritized),
        }
        assessment_sha = hashlib.sha256(json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
        return VerifiedAgentDelegationAssessment(
            graph_id=manifest.graph_id,
            graph_version=manifest.version,
            graph_sha256=graph_sha,
            p7b_assessment_evidence_sha256=_assessment_digest(p7b_assessment),
            p7h_assessment_evidence_sha256=_assessment_digest(p7h_assessment),
            p7i_assessment_evidence_sha256=_assessment_digest(p7i_assessment),
            delegation_count=len(ordered_facts),
            allowed_delegation_count=len(ordered_facts) - len(denied),
            denied_delegation_count=len(denied),
            cross_tenant_denial_count=sum(DelegationRisk.CROSS_TENANT in fact.risks for fact in ordered_facts),
            confused_deputy_denial_count=sum(DelegationRisk.CONFUSED_DEPUTY in fact.risks for fact in ordered_facts),
            capability_laundering_denial_count=sum(DelegationRisk.CAPABILITY_LAUNDERING in fact.risks for fact in ordered_facts),
            scope_amplification_denial_count=sum(DelegationRisk.SCOPE_AMPLIFICATION in fact.risks for fact in ordered_facts),
            prioritized_denied_delegation_ids=prioritized,
            delegations=ordered_facts,
            assessment_evidence_sha256=assessment_sha,
        )
