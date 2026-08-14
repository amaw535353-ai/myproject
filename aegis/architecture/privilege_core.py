from __future__ import annotations

import hashlib
import hmac
import json
from typing import Mapping

from aegis.assurance.posture_reporting import (
    P6D_POSTURE_EVIDENCE_SCHEMA_VERSION,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)
from .attack_paths import (
    P7A_ARCHITECTURE_SCHEMA_VERSION,
    P7A_ASSESSMENT_SCHEMA_VERSION,
    ArchitectureFlow,
    ArchitectureManifest,
    VerifiedAttackPathAssessment,
)
from .privilege_types import *

def _reject(
    reason: PrivilegePathRejectReason,
    message: str,
    *,
    principal_id: str | None = None,
    capability_id: str | None = None,
    edge_id: str | None = None,
    control_id: str | None = None,
) -> None:
    raise PrivilegePathRejected(
        reason,
        message,
        principal_id=principal_id,
        capability_id=capability_id,
        edge_id=edge_id,
        control_id=control_id,
    )


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _tier_rank(value: PrivilegeTier) -> int:
    return {
        PrivilegeTier.UNTRUSTED: 0,
        PrivilegeTier.TENANT: 1,
        PrivilegeTier.SERVICE: 2,
        PrivilegeTier.PRIVILEGED: 3,
        PrivilegeTier.SECURITY: 4,
    }[value]


def _scope_rank(value: PrivilegeScope) -> int:
    return {
        PrivilegeScope.PUBLIC: 0,
        PrivilegeScope.TENANT: 1,
        PrivilegeScope.WORKLOAD: 2,
        PrivilegeScope.SECURITY: 3,
    }[value]


def _sensitivity_rank(value: CapabilitySensitivity) -> int:
    return {
        CapabilitySensitivity.LOW: 1,
        CapabilitySensitivity.MEDIUM: 2,
        CapabilitySensitivity.HIGH: 3,
        CapabilitySensitivity.CRITICAL: 4,
    }[value]


def _canonical_principal(principal: IdentityPrincipal) -> dict[str, object]:
    return {
        "description": principal.description,
        "home_asset_id": principal.home_asset_id,
        "native_capability_ids": sorted(principal.native_capability_ids),
        "owner_id": principal.owner_id,
        "principal_id": principal.principal_id,
        "principal_type": principal.principal_type.value
        if isinstance(principal.principal_type, PrincipalType)
        else str(principal.principal_type),
        "privilege_scope": principal.privilege_scope.value
        if isinstance(principal.privilege_scope, PrivilegeScope)
        else str(principal.privilege_scope),
        "privilege_tier": principal.privilege_tier.value
        if isinstance(principal.privilege_tier, PrivilegeTier)
        else str(principal.privilege_tier),
    }


def _canonical_capability(capability: Capability) -> dict[str, object]:
    return {
        "capability_id": capability.capability_id,
        "description": capability.description,
        "minimum_privilege_tier": capability.minimum_privilege_tier.value
        if isinstance(capability.minimum_privilege_tier, PrivilegeTier)
        else str(capability.minimum_privilege_tier),
        "owner_id": capability.owner_id,
        "sensitivity": capability.sensitivity.value
        if isinstance(capability.sensitivity, CapabilitySensitivity)
        else str(capability.sensitivity),
        "target_asset_id": capability.target_asset_id,
    }


def _canonical_transition(transition: PrivilegeTransition) -> dict[str, object]:
    return {
        "delegation_type": transition.delegation_type.value
        if isinstance(transition.delegation_type, DelegationType)
        else str(transition.delegation_type),
        "description": transition.description,
        "edge_id": transition.edge_id,
        "granted_capability_ids": sorted(transition.granted_capability_ids),
        "owner_id": transition.owner_id,
        "required_control_ids": sorted(transition.required_control_ids),
        "source_principal_id": transition.source_principal_id,
        "target_principal_id": transition.target_principal_id,
        "via_flow_ids": list(transition.via_flow_ids),
    }


def canonical_identity_capability_manifest_bytes(manifest: IdentityCapabilityManifest) -> bytes:
    document = {
        "architecture_sha256": manifest.architecture_sha256.casefold(),
        "capabilities": [
            _canonical_capability(item)
            for item in sorted(manifest.capabilities, key=lambda item: item.capability_id)
        ],
        "created_at_epoch": manifest.created_at_epoch,
        "identity_graph_id": manifest.identity_graph_id,
        "principals": [
            _canonical_principal(item)
            for item in sorted(manifest.principals, key=lambda item: item.principal_id)
        ],
        "schema_version": manifest.schema_version,
        "transitions": [
            _canonical_transition(item)
            for item in sorted(manifest.transitions, key=lambda item: item.edge_id)
        ],
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def identity_capability_manifest_digest(manifest: IdentityCapabilityManifest) -> str:
    return hashlib.sha256(canonical_identity_capability_manifest_bytes(manifest)).hexdigest()


def privilege_path_identifier(
    entry_principal_id: str,
    target_capability_id: str,
    principal_ids: tuple[str, ...],
    transition_ids: tuple[str, ...],
) -> str:
    document = {
        "entry_principal_id": entry_principal_id,
        "principal_ids": list(principal_ids),
        "target_capability_id": target_capability_id,
        "transition_ids": list(transition_ids),
    }
    digest = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"privpath-{digest[:20]}"


def _validate_policy(policy: PrivilegePathPolicy) -> None:
    if (
        not policy.expected_identity_graph_id
        or not policy.expected_identity_graph_version
        or not _is_sha256(policy.expected_identity_graph_sha256)
        or not _is_sha256(policy.expected_architecture_sha256)
        or not _is_sha256(policy.expected_p7a_assessment_evidence_sha256)
        or not _is_sha256(policy.expected_posture_evidence_sha256)
        or not _is_sha256(policy.expected_control_catalog_sha256)
        or not policy.required_principal_ids
        or not policy.required_capability_ids
        or not policy.required_transition_ids
        or not policy.entry_principal_ids
        or not policy.target_capability_ids
        or not policy.trusted_owner_ids
        or not policy.entry_principal_ids.issubset(policy.required_principal_ids)
        or not policy.target_capability_ids.issubset(policy.required_capability_ids)
        or policy.max_manifest_age_seconds < 0
        or policy.max_future_skew_seconds < 0
        or policy.max_path_hops <= 0
        or policy.max_paths <= 0
    ):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "privilege-path policy metadata is invalid")

    principal_maps = (
        policy.expected_home_asset_by_principal,
        policy.expected_type_by_principal,
        policy.expected_tier_by_principal,
        policy.expected_scope_by_principal,
        policy.expected_native_capabilities_by_principal,
    )
    if any(not policy.required_principal_ids.issubset(set(mapping)) for mapping in principal_maps):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "required principals lack complete policy pins")
    capability_maps = (
        policy.expected_target_asset_by_capability,
        policy.minimum_sensitivity_by_capability,
        policy.minimum_tier_by_capability,
    )
    if any(not policy.required_capability_ids.issubset(set(mapping)) for mapping in capability_maps):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "required capabilities lack complete policy pins")
    edge_maps = (
        policy.expected_transition_endpoints,
        policy.expected_flow_ids_by_transition,
        policy.expected_control_ids_by_transition,
        policy.expected_granted_capability_ids_by_transition,
    )
    if any(not policy.required_transition_ids.issubset(set(mapping)) for mapping in edge_maps):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "required transitions lack complete policy pins")

    if any(not isinstance(value, PrincipalType) for value in policy.expected_type_by_principal.values()):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "principal type policy pins are invalid")
    if any(not isinstance(value, PrivilegeTier) for value in policy.expected_tier_by_principal.values()):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "principal tier policy pins are invalid")
    if any(not isinstance(value, PrivilegeScope) for value in policy.expected_scope_by_principal.values()):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "principal scope policy pins are invalid")
    if any(not isinstance(value, CapabilitySensitivity) for value in policy.minimum_sensitivity_by_capability.values()):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "capability sensitivity policy pins are invalid")
    if any(not isinstance(value, PrivilegeTier) for value in policy.minimum_tier_by_capability.values()):
        _reject(PrivilegePathRejectReason.POLICY_INVALID, "capability tier policy pins are invalid")
    for edge_id, endpoints in policy.expected_transition_endpoints.items():
        if (
            not edge_id
            or len(endpoints) != 2
            or not endpoints[0]
            or not endpoints[1]
            or endpoints[0] == endpoints[1]
        ):
            _reject(PrivilegePathRejectReason.POLICY_INVALID, "transition endpoint policy pin is invalid")
    for edge_id, flow_ids in policy.expected_flow_ids_by_transition.items():
        if not edge_id or not flow_ids or len(set(flow_ids)) != len(flow_ids) or any(not item for item in flow_ids):
            _reject(PrivilegePathRejectReason.POLICY_INVALID, "transition route policy pin is invalid")
    for mapping in (
        policy.expected_control_ids_by_transition,
        policy.expected_granted_capability_ids_by_transition,
        policy.expected_native_capabilities_by_principal,
    ):
        if any(any(not item for item in values) for values in mapping.values()):
            _reject(PrivilegePathRejectReason.POLICY_INVALID, "policy contains an empty capability/control identifier")


def _validate_request(request: PrivilegePathRequest, policy: PrivilegePathPolicy) -> None:
    if (
        not request.identity_graph_id
        or not request.identity_graph_version
        or not _is_sha256(request.identity_graph_sha256)
        or not _is_sha256(request.architecture_sha256)
        or not _is_sha256(request.p7a_assessment_evidence_sha256)
        or not _is_sha256(request.posture_evidence_sha256)
        or not request.entry_principal_ids
        or not request.target_capability_ids
        or request.evaluated_at_epoch <= 0
        or request.declared_max_exposed_risk_score < 0
        or len(set(request.entry_principal_ids)) != len(request.entry_principal_ids)
        or len(set(request.target_capability_ids)) != len(request.target_capability_ids)
        or len(set(request.declared_exposed_path_ids)) != len(request.declared_exposed_path_ids)
    ):
        _reject(PrivilegePathRejectReason.REQUEST_INVALID, "privilege-path request metadata is invalid")
    if set(request.entry_principal_ids) != set(policy.entry_principal_ids):
        _reject(PrivilegePathRejectReason.ATTESTED_ENTRY_SCOPE_MISMATCH, "entry principals differ from policy")
    if set(request.target_capability_ids) != set(policy.target_capability_ids):
        _reject(PrivilegePathRejectReason.TARGET_CAPABILITY_SCOPE_MISMATCH, "target capabilities differ from policy")
