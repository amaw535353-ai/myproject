from __future__ import annotations

import hmac
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus
from .attack_paths import ArchitectureFlow
from .privilege_types import *
from .privilege_core import (
    _is_sha256, _reject, _sensitivity_rank, _tier_rank, identity_capability_manifest_digest
)

def _validate_identity_manifest(
    manifest: IdentityCapabilityManifest,
    *,
    architecture_assets: Mapping[str, object],
    architecture_flows: Mapping[str, ArchitectureFlow],
    controls: Mapping[str, ControlStatus],
    request: PrivilegePathRequest,
    policy: PrivilegePathPolicy,
) -> tuple[
    dict[str, IdentityPrincipal],
    dict[str, Capability],
    dict[str, PrivilegeTransition],
    str,
]:
    if (
        manifest.schema_version != P7B_IDENTITY_SCHEMA_VERSION
        or not manifest.identity_graph_id
        or not manifest.version
        or not _is_sha256(manifest.architecture_sha256)
        or manifest.created_at_epoch <= 0
        or not manifest.principals
        or not manifest.capabilities
        or not manifest.transitions
    ):
        _reject(PrivilegePathRejectReason.IDENTITY_MANIFEST_INVALID, "identity/capability manifest metadata is invalid")
    digest = identity_capability_manifest_digest(manifest)
    if (
        manifest.identity_graph_id != policy.expected_identity_graph_id
        or manifest.version != policy.expected_identity_graph_version
        or request.identity_graph_id != manifest.identity_graph_id
        or request.identity_graph_version != manifest.version
        or not hmac.compare_digest(digest, policy.expected_identity_graph_sha256.casefold())
        or not hmac.compare_digest(request.identity_graph_sha256.casefold(), digest)
        or not hmac.compare_digest(manifest.architecture_sha256.casefold(), policy.expected_architecture_sha256.casefold())
    ):
        _reject(PrivilegePathRejectReason.IDENTITY_MANIFEST_DIGEST_MISMATCH, "identity graph is not exactly policy/request/architecture bound")
    if manifest.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        _reject(PrivilegePathRejectReason.IDENTITY_MANIFEST_FUTURE, "identity graph is future-dated")
    if request.evaluated_at_epoch - manifest.created_at_epoch > policy.max_manifest_age_seconds:
        _reject(PrivilegePathRejectReason.IDENTITY_MANIFEST_STALE, "identity graph is older than policy permits")

    principals: dict[str, IdentityPrincipal] = {}
    for principal in manifest.principals:
        if (
            not principal.principal_id
            or not isinstance(principal.principal_type, PrincipalType)
            or not principal.home_asset_id
            or not principal.owner_id
            or not isinstance(principal.privilege_tier, PrivilegeTier)
            or not isinstance(principal.privilege_scope, PrivilegeScope)
            or len(set(principal.native_capability_ids)) != len(principal.native_capability_ids)
            or any(not item for item in principal.native_capability_ids)
            or not principal.description
        ):
            _reject(PrivilegePathRejectReason.IDENTITY_MANIFEST_INVALID, "identity graph contains an invalid principal", principal_id=principal.principal_id or None)
        if principal.principal_id in principals:
            _reject(PrivilegePathRejectReason.PRINCIPAL_DUPLICATE, "identity graph contains duplicate principal IDs", principal_id=principal.principal_id)
        if principal.owner_id not in policy.trusted_owner_ids:
            _reject(PrivilegePathRejectReason.PRINCIPAL_OWNER_UNTRUSTED, "principal owner is not trusted", principal_id=principal.principal_id)
        if principal.home_asset_id not in architecture_assets:
            _reject(PrivilegePathRejectReason.PRINCIPAL_ASSET_INVALID, "principal home asset is absent from P7-A architecture", principal_id=principal.principal_id)
        principals[principal.principal_id] = principal

    missing_principals = policy.required_principal_ids - set(principals)
    if missing_principals:
        _reject(PrivilegePathRejectReason.PRINCIPAL_REQUIRED_MISSING, "required principal is missing", principal_id=sorted(missing_principals)[0])
    for principal_id in policy.required_principal_ids:
        principal = principals[principal_id]
        if principal.home_asset_id != policy.expected_home_asset_by_principal[principal_id]:
            _reject(PrivilegePathRejectReason.PRINCIPAL_ASSET_INVALID, "principal home asset differs from policy", principal_id=principal_id)
        if principal.principal_type != policy.expected_type_by_principal[principal_id]:
            _reject(PrivilegePathRejectReason.PRINCIPAL_TYPE_DRIFT, "principal type differs from policy", principal_id=principal_id)
        if principal.privilege_tier != policy.expected_tier_by_principal[principal_id]:
            _reject(PrivilegePathRejectReason.PRINCIPAL_TIER_DRIFT, "principal privilege tier differs from policy", principal_id=principal_id)
        if principal.privilege_scope != policy.expected_scope_by_principal[principal_id]:
            _reject(PrivilegePathRejectReason.PRINCIPAL_SCOPE_DRIFT, "principal privilege scope differs from policy", principal_id=principal_id)
        if frozenset(principal.native_capability_ids) != frozenset(policy.expected_native_capabilities_by_principal[principal_id]):
            _reject(PrivilegePathRejectReason.PRINCIPAL_CAPABILITY_DRIFT, "principal native capabilities differ from policy", principal_id=principal_id)

    capabilities: dict[str, Capability] = {}
    for capability in manifest.capabilities:
        if (
            not capability.capability_id
            or not capability.target_asset_id
            or not capability.owner_id
            or not isinstance(capability.sensitivity, CapabilitySensitivity)
            or not isinstance(capability.minimum_privilege_tier, PrivilegeTier)
            or not capability.description
        ):
            _reject(PrivilegePathRejectReason.IDENTITY_MANIFEST_INVALID, "identity graph contains an invalid capability", capability_id=capability.capability_id or None)
        if capability.capability_id in capabilities:
            _reject(PrivilegePathRejectReason.CAPABILITY_DUPLICATE, "identity graph contains duplicate capability IDs", capability_id=capability.capability_id)
        if capability.owner_id not in policy.trusted_owner_ids:
            _reject(PrivilegePathRejectReason.CAPABILITY_OWNER_UNTRUSTED, "capability owner is not trusted", capability_id=capability.capability_id)
        if capability.target_asset_id not in architecture_assets:
            _reject(PrivilegePathRejectReason.CAPABILITY_TARGET_INVALID, "capability target is absent from P7-A architecture", capability_id=capability.capability_id)
        capabilities[capability.capability_id] = capability

    missing_capabilities = policy.required_capability_ids - set(capabilities)
    if missing_capabilities:
        _reject(PrivilegePathRejectReason.CAPABILITY_REQUIRED_MISSING, "required capability is missing", capability_id=sorted(missing_capabilities)[0])
    for capability_id in policy.required_capability_ids:
        capability = capabilities[capability_id]
        if capability.target_asset_id != policy.expected_target_asset_by_capability[capability_id]:
            _reject(PrivilegePathRejectReason.CAPABILITY_TARGET_INVALID, "capability target differs from policy", capability_id=capability_id)
        if _sensitivity_rank(capability.sensitivity) < _sensitivity_rank(policy.minimum_sensitivity_by_capability[capability_id]):
            _reject(PrivilegePathRejectReason.CAPABILITY_SENSITIVITY_DOWNGRADE, "capability sensitivity is below policy minimum", capability_id=capability_id)
        if _tier_rank(capability.minimum_privilege_tier) < _tier_rank(policy.minimum_tier_by_capability[capability_id]):
            _reject(PrivilegePathRejectReason.CAPABILITY_TIER_DOWNGRADE, "capability minimum tier is below policy minimum", capability_id=capability_id)

    for principal in principals.values():
        for capability_id in principal.native_capability_ids:
            capability = capabilities.get(capability_id)
            if capability is None:
                _reject(PrivilegePathRejectReason.PRINCIPAL_CAPABILITY_DRIFT, "principal references an unknown native capability", principal_id=principal.principal_id, capability_id=capability_id)
            if _tier_rank(principal.privilege_tier) < _tier_rank(capability.minimum_privilege_tier):
                _reject(PrivilegePathRejectReason.PRINCIPAL_CAPABILITY_DRIFT, "principal tier is below a declared native capability minimum", principal_id=principal.principal_id, capability_id=capability_id)

    transitions: dict[str, PrivilegeTransition] = {}
    for edge in manifest.transitions:
        if (
            not edge.edge_id
            or not edge.source_principal_id
            or not edge.target_principal_id
            or not isinstance(edge.delegation_type, DelegationType)
            or not edge.owner_id
            or not edge.via_flow_ids
            or len(set(edge.via_flow_ids)) != len(edge.via_flow_ids)
            or any(not item for item in edge.via_flow_ids)
            or len(set(edge.required_control_ids)) != len(edge.required_control_ids)
            or any(not item for item in edge.required_control_ids)
            or len(set(edge.granted_capability_ids)) != len(edge.granted_capability_ids)
            or any(not item for item in edge.granted_capability_ids)
            or not edge.description
        ):
            _reject(PrivilegePathRejectReason.IDENTITY_MANIFEST_INVALID, "identity graph contains an invalid privilege transition", edge_id=edge.edge_id or None)
        if edge.edge_id in transitions:
            _reject(PrivilegePathRejectReason.EDGE_DUPLICATE, "identity graph contains duplicate transition IDs", edge_id=edge.edge_id)
        if edge.owner_id not in policy.trusted_owner_ids:
            _reject(PrivilegePathRejectReason.EDGE_OWNER_UNTRUSTED, "transition owner is not trusted", edge_id=edge.edge_id)
        if edge.source_principal_id not in principals or edge.target_principal_id not in principals:
            _reject(PrivilegePathRejectReason.EDGE_REFERENCE_INVALID, "transition references an unknown principal", edge_id=edge.edge_id)
        if edge.source_principal_id == edge.target_principal_id:
            _reject(PrivilegePathRejectReason.EDGE_SELF_LOOP, "privilege transition may not self-loop", edge_id=edge.edge_id)
        for capability_id in edge.granted_capability_ids:
            capability = capabilities.get(capability_id)
            if capability is None:
                _reject(PrivilegePathRejectReason.EDGE_REFERENCE_INVALID, "transition grants an unknown capability", edge_id=edge.edge_id, capability_id=capability_id)
            target = principals[edge.target_principal_id]
            if _tier_rank(target.privilege_tier) < _tier_rank(capability.minimum_privilege_tier):
                _reject(PrivilegePathRejectReason.EDGE_REFERENCE_INVALID, "transition target tier is below granted capability minimum", edge_id=edge.edge_id, capability_id=capability_id)
        transitions[edge.edge_id] = edge

    missing_edges = policy.required_transition_ids - set(transitions)
    if missing_edges:
        _reject(PrivilegePathRejectReason.EDGE_REQUIRED_MISSING, "required privilege transition is missing", edge_id=sorted(missing_edges)[0])

    for edge_id in policy.required_transition_ids:
        edge = transitions[edge_id]
        expected_endpoints = policy.expected_transition_endpoints[edge_id]
        if (edge.source_principal_id, edge.target_principal_id) != tuple(expected_endpoints):
            _reject(PrivilegePathRejectReason.EDGE_ENDPOINT_DRIFT, "transition endpoints differ from policy", edge_id=edge_id)
        if tuple(edge.via_flow_ids) != tuple(policy.expected_flow_ids_by_transition[edge_id]):
            _reject(PrivilegePathRejectReason.EDGE_FLOW_DRIFT, "transition architecture route differs from policy", edge_id=edge_id)
        if frozenset(edge.required_control_ids) != frozenset(policy.expected_control_ids_by_transition[edge_id]):
            _reject(PrivilegePathRejectReason.EDGE_CONTROL_DRIFT, "transition control mapping differs from policy", edge_id=edge_id)
        if frozenset(edge.granted_capability_ids) != frozenset(policy.expected_granted_capability_ids_by_transition[edge_id]):
            _reject(PrivilegePathRejectReason.EDGE_GRANT_DRIFT, "transition capability grants differ from policy", edge_id=edge_id)

    for edge in transitions.values():
        source_home = principals[edge.source_principal_id].home_asset_id
        target_home = principals[edge.target_principal_id].home_asset_id
        current_asset = source_home
        route_controls: set[str] = set()
        for flow_id in edge.via_flow_ids:
            flow = architecture_flows.get(flow_id)
            if flow is None or flow.source_asset_id != current_asset:
                _reject(PrivilegePathRejectReason.EDGE_FLOW_INVALID, "transition route is not contiguous in P7-A architecture", edge_id=edge.edge_id)
            current_asset = flow.target_asset_id
            route_controls.update(flow.required_control_ids)
        if current_asset != target_home:
            _reject(PrivilegePathRejectReason.EDGE_FLOW_INVALID, "transition route does not terminate at target principal home asset", edge_id=edge.edge_id)
        for control_id in edge.required_control_ids:
            if control_id not in controls:
                _reject(PrivilegePathRejectReason.EDGE_CONTROL_UNKNOWN, "transition references control absent from P6-D posture", edge_id=edge.edge_id, control_id=control_id)
            if control_id not in route_controls:
                _reject(PrivilegePathRejectReason.EDGE_CONTROL_NOT_ON_ROUTE, "transition control is not mapped to its exact P7-A route", edge_id=edge.edge_id, control_id=control_id)

    return principals, capabilities, transitions, digest
