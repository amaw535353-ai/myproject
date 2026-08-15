from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

P7H_CONTROL_PLANE_POLICY_VERSION = "security-control-plane-administrative-change-paths-v1"
P7H_CONTROL_PLANE_MANIFEST_SCHEMA_VERSION = "aegis-security-control-plane-manifest-v1"
P7H_ASSESSMENT_SCHEMA_VERSION = "aegis-control-plane-change-path-assessment-v1"
P7H_ASSESSMENT_MODE = "deterministic-evidence-bound-control-plane-change-analysis-v1"


class AdministrativePrincipalType(StrEnum):
    HUMAN_ADMIN = "human_admin"
    SECURITY_ADMIN = "security_admin"
    RELEASE_AUTOMATION = "release_automation"
    SERVICE_CONTROLLER = "service_controller"
    BREAK_GLASS = "break_glass"


class ControlPlaneResourceType(StrEnum):
    AUTHORIZATION_POLICY = "authorization_policy"
    MODEL_DEPLOYMENT_GATE = "model_deployment_gate"
    TELEMETRY_CONFIGURATION = "telemetry_configuration"
    EGRESS_POLICY = "egress_policy"
    FALLBACK_POLICY = "fallback_policy"
    TRUST_STORE = "trust_store"
    ASSURANCE_SETTINGS = "assurance_settings"


class ControlPlaneSensitivity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AdministrativeOperation(StrEnum):
    UPDATE = "update"
    DISABLE = "disable"
    DELETE = "delete"
    ROTATE = "rotate"
    PROMOTE = "promote"
    ROLLBACK = "rollback"


class ControlPlaneRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    P7B_ASSESSMENT_UNVERIFIED = "p7b_assessment_unverified"
    P7B_ASSESSMENT_MISMATCH = "p7b_assessment_mismatch"
    P7E_ASSESSMENT_UNVERIFIED = "p7e_assessment_unverified"
    P7E_ASSESSMENT_MISMATCH = "p7e_assessment_mismatch"
    P7F_ASSESSMENT_UNVERIFIED = "p7f_assessment_unverified"
    P7F_ASSESSMENT_MISMATCH = "p7f_assessment_mismatch"
    P7G_ASSESSMENT_UNVERIFIED = "p7g_assessment_unverified"
    P7G_ASSESSMENT_MISMATCH = "p7g_assessment_mismatch"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    PRINCIPAL_DUPLICATE = "principal_duplicate"
    PRINCIPAL_COVERAGE_MISMATCH = "principal_coverage_mismatch"
    PRINCIPAL_OWNER_UNTRUSTED = "principal_owner_untrusted"
    PRINCIPAL_TYPE_DRIFT = "principal_type_drift"
    PRINCIPAL_PATH_DRIFT = "principal_path_drift"
    PRINCIPAL_PATH_UNKNOWN = "principal_path_unknown"
    PRINCIPAL_BREAK_GLASS_DRIFT = "principal_break_glass_drift"
    RESOURCE_DUPLICATE = "resource_duplicate"
    RESOURCE_COVERAGE_MISMATCH = "resource_coverage_mismatch"
    RESOURCE_OWNER_UNTRUSTED = "resource_owner_untrusted"
    RESOURCE_TYPE_DRIFT = "resource_type_drift"
    RESOURCE_SENSITIVITY_DOWNGRADE = "resource_sensitivity_downgrade"
    RESOURCE_BINDING_DRIFT = "resource_binding_drift"
    RESOURCE_BINDING_UNKNOWN = "resource_binding_unknown"
    RESOURCE_CONTROL_DRIFT = "resource_control_drift"
    RESOURCE_CONTROL_UNKNOWN = "resource_control_unknown"
    RESOURCE_TELEMETRY_DRIFT = "resource_telemetry_drift"
    RESOURCE_TELEMETRY_UNKNOWN = "resource_telemetry_unknown"
    RESOURCE_SEPARATION_OF_DUTIES_DRIFT = "resource_separation_of_duties_drift"
    RESOURCE_BREAK_GLASS_DRIFT = "resource_break_glass_drift"
    ROUTE_DUPLICATE = "route_duplicate"
    ROUTE_COVERAGE_MISMATCH = "route_coverage_mismatch"
    ROUTE_OWNER_UNTRUSTED = "route_owner_untrusted"
    ROUTE_REFERENCE_INVALID = "route_reference_invalid"
    ROUTE_PRINCIPAL_DRIFT = "route_principal_drift"
    ROUTE_RESOURCE_DRIFT = "route_resource_drift"
    ROUTE_OPERATION_DRIFT = "route_operation_drift"
    ROUTE_EXECUTION_IDENTITY_UNTRUSTED = "route_execution_identity_untrusted"
    ROUTE_EXECUTION_IDENTITY_DRIFT = "route_execution_identity_drift"
    ROUTE_APPROVAL_DRIFT = "route_approval_drift"
    ROUTE_APPROVER_UNTRUSTED = "route_approver_untrusted"
    ROUTE_SELF_APPROVAL = "route_self_approval"
    ROUTE_CONTROL_DRIFT = "route_control_drift"
    ROUTE_CONTROL_UNKNOWN = "route_control_unknown"
    ROUTE_TELEMETRY_DRIFT = "route_telemetry_drift"
    ROUTE_TELEMETRY_UNKNOWN = "route_telemetry_unknown"
    ROUTE_VERSION_DRIFT = "route_version_drift"
    ROUTE_TARGET_DIGEST_INVALID = "route_target_digest_invalid"
    ROUTE_BREAK_GLASS_DRIFT = "route_break_glass_drift"
    ROUTE_BREAK_GLASS_INVALID = "route_break_glass_invalid"
    ROUTE_TICKET_INVALID = "route_ticket_invalid"
    ROUTE_OBSERVATION_STALE = "route_observation_stale"
    ROUTE_OBSERVATION_FUTURE = "route_observation_future"
    DECLARED_PATH_MISMATCH = "declared_path_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class ControlPlaneRejected(ValueError):
    def __init__(
        self,
        reason: ControlPlaneRejectReason,
        message: str,
        *,
        principal_id: str | None = None,
        resource_id: str | None = None,
        route_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.principal_id = principal_id
        self.resource_id = resource_id
        self.route_id = route_id
        self.control_id = control_id


@dataclass(frozen=True)
class AdministrativePrincipal:
    principal_id: str
    principal_type: AdministrativePrincipalType
    owner_id: str
    p7b_path_ids: tuple[str, ...]
    break_glass_capable: bool
    description: str


@dataclass(frozen=True)
class ControlPlaneResource:
    resource_id: str
    resource_type: ControlPlaneResourceType
    sensitivity: ControlPlaneSensitivity
    owner_id: str
    current_version: str
    upstream_binding_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    required_telemetry_requirement_ids: tuple[str, ...]
    separation_of_duties_required: bool
    break_glass_permitted: bool
    description: str


@dataclass(frozen=True)
class AdministrativeChangeRoute:
    route_id: str
    principal_id: str
    resource_id: str
    operation: AdministrativeOperation
    owner_id: str
    execution_identity_id: str
    approval_principal_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    telemetry_requirement_ids: tuple[str, ...]
    proposed_version: str
    target_state_sha256: str
    break_glass: bool
    emergency_reason: str | None
    verified_at_epoch: int
    change_ticket_id: str
    description: str


@dataclass(frozen=True)
class ControlPlaneManifest:
    control_plane_id: str
    version: str
    p7b_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    p7g_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    created_at_epoch: int
    principals: tuple[AdministrativePrincipal, ...]
    resources: tuple[ControlPlaneResource, ...]
    routes: tuple[AdministrativeChangeRoute, ...]
    schema_version: str = P7H_CONTROL_PLANE_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class ControlPlaneRequest:
    control_plane_id: str
    control_plane_version: str
    control_plane_sha256: str
    p7b_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    p7g_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    evaluated_at_epoch: int
    route_ids: tuple[str, ...]
    declared_exposed_route_ids: tuple[str, ...]
    declared_max_exposed_risk_score: int


@dataclass(frozen=True)
class ControlPlanePolicy:
    expected_control_plane_id: str
    expected_control_plane_version: str
    expected_control_plane_sha256: str
    expected_p7b_assessment_evidence_sha256: str
    expected_p7e_assessment_evidence_sha256: str
    expected_p7f_assessment_evidence_sha256: str
    expected_p7g_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_principal_ids: frozenset[str]
    required_resource_ids: frozenset[str]
    required_route_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    trusted_approver_ids: frozenset[str]
    trusted_execution_identity_ids: frozenset[str]
    expected_principal_type: Mapping[str, AdministrativePrincipalType]
    expected_p7b_path_ids_by_principal: Mapping[str, frozenset[str]]
    expected_break_glass_capable: Mapping[str, bool]
    expected_resource_type: Mapping[str, ControlPlaneResourceType]
    minimum_sensitivity: Mapping[str, ControlPlaneSensitivity]
    expected_resource_upstream_binding_ids: Mapping[str, frozenset[str]]
    expected_resource_control_ids: Mapping[str, frozenset[str]]
    expected_resource_telemetry_requirement_ids: Mapping[str, frozenset[str]]
    expected_separation_of_duties: Mapping[str, bool]
    expected_break_glass_permitted: Mapping[str, bool]
    expected_route_principal: Mapping[str, str]
    expected_route_resource: Mapping[str, str]
    expected_route_operation: Mapping[str, AdministrativeOperation]
    expected_execution_identity: Mapping[str, str]
    expected_approval_principal_ids: Mapping[str, frozenset[str]]
    expected_route_control_ids: Mapping[str, frozenset[str]]
    expected_route_telemetry_requirement_ids: Mapping[str, frozenset[str]]
    expected_proposed_version: Mapping[str, str]
    expected_break_glass: Mapping[str, bool]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30
    max_route_observation_age_seconds: int = 3_600


@dataclass(frozen=True)
class ControlPlaneChangePathFact:
    route_id: str
    principal_id: str
    resource_id: str
    resource_type: ControlPlaneResourceType
    resource_sensitivity: ControlPlaneSensitivity
    operation: AdministrativeOperation
    approval_principal_ids: tuple[str, ...]
    execution_identity_id: str
    p7b_path_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    telemetry_requirement_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    blind_spot_telemetry_requirement_ids: tuple[str, ...]
    exposed_upstream_binding_ids: tuple[str, ...]
    self_authorization_mutation: bool
    self_audit_mutation: bool
    break_glass: bool
    exposed: bool
    risk_score: int
    exposure_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedControlPlaneAssessment:
    control_plane_id: str
    control_plane_version: str
    control_plane_sha256: str
    p7b_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    p7g_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    route_count: int
    exposed_route_count: int
    controlled_route_count: int
    critical_resource_exposed_route_count: int
    self_authorization_mutation_count: int
    self_audit_mutation_count: int
    break_glass_route_count: int
    max_exposed_risk_score: int
    prioritized_exposed_route_ids: tuple[str, ...]
    routes: tuple[ControlPlaneChangePathFact, ...]
    assessment_evidence_sha256: str
    exact_control_plane_binding_verified: bool = True
    exact_p7b_assessment_binding_verified: bool = True
    exact_p7e_assessment_binding_verified: bool = True
    exact_p7f_assessment_binding_verified: bool = True
    exact_p7g_assessment_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    administrative_identity_paths_policy_pinned: bool = True
    control_plane_resources_policy_pinned: bool = True
    separation_of_duties_enforced: bool = True
    independent_change_telemetry_required: bool = True
    path_risk_derived_from_evidence: bool = True
    caller_admin_approval_trusted: bool = False
    production_iam_change_enforcement: bool = False
    production_change_ticket_validation: bool = False
    production_control_plane_operations: bool = False
    cryptographic_human_approval: bool = False
    rollback_resistant_configuration_history: bool = False
    formal_authorization_proof: bool = False
    network_operations: int = 0
    schema_version: str = P7H_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7H_CONTROL_PLANE_POLICY_VERSION
    assessment_mode: str = P7H_ASSESSMENT_MODE


def _reject(reason: ControlPlaneRejectReason, message: str, **context: str | None) -> None:
    raise ControlPlaneRejected(reason, message, **context)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _severity_rank(value: ControlPlaneSensitivity) -> int:
    return {
        ControlPlaneSensitivity.LOW: 1,
        ControlPlaneSensitivity.MEDIUM: 2,
        ControlPlaneSensitivity.HIGH: 3,
        ControlPlaneSensitivity.CRITICAL: 4,
    }[value]


def _status_value(value: object) -> str:
    raw = getattr(value, "value", value)
    return str(raw).casefold()


def _assessment_digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _verified(value: object, *attributes: str) -> bool:
    return all(bool(getattr(value, attribute, False)) for attribute in attributes)


def canonical_control_plane_manifest_bytes(manifest: ControlPlaneManifest) -> bytes:
    document = {
        "control_plane_id": manifest.control_plane_id,
        "created_at_epoch": manifest.created_at_epoch,
        "p7b_assessment_evidence_sha256": manifest.p7b_assessment_evidence_sha256.casefold(),
        "p7e_assessment_evidence_sha256": manifest.p7e_assessment_evidence_sha256.casefold(),
        "p7f_assessment_evidence_sha256": manifest.p7f_assessment_evidence_sha256.casefold(),
        "p7g_assessment_evidence_sha256": manifest.p7g_assessment_evidence_sha256.casefold(),
        "posture_evidence_sha256": manifest.posture_evidence_sha256.casefold(),
        "principals": [
            {
                "break_glass_capable": item.break_glass_capable,
                "description": item.description,
                "owner_id": item.owner_id,
                "p7b_path_ids": sorted(item.p7b_path_ids),
                "principal_id": item.principal_id,
                "principal_type": item.principal_type.value,
            }
            for item in sorted(manifest.principals, key=lambda value: value.principal_id)
        ],
        "resources": [
            {
                "break_glass_permitted": item.break_glass_permitted,
                "current_version": item.current_version,
                "description": item.description,
                "owner_id": item.owner_id,
                "required_control_ids": sorted(item.required_control_ids),
                "required_telemetry_requirement_ids": sorted(item.required_telemetry_requirement_ids),
                "resource_id": item.resource_id,
                "resource_type": item.resource_type.value,
                "sensitivity": item.sensitivity.value,
                "separation_of_duties_required": item.separation_of_duties_required,
                "upstream_binding_ids": sorted(item.upstream_binding_ids),
            }
            for item in sorted(manifest.resources, key=lambda value: value.resource_id)
        ],
        "routes": [
            {
                "approval_principal_ids": sorted(item.approval_principal_ids),
                "break_glass": item.break_glass,
                "change_ticket_id": item.change_ticket_id,
                "description": item.description,
                "emergency_reason": item.emergency_reason,
                "execution_identity_id": item.execution_identity_id,
                "operation": item.operation.value,
                "owner_id": item.owner_id,
                "principal_id": item.principal_id,
                "proposed_version": item.proposed_version,
                "required_control_ids": sorted(item.required_control_ids),
                "resource_id": item.resource_id,
                "route_id": item.route_id,
                "target_state_sha256": item.target_state_sha256.casefold(),
                "telemetry_requirement_ids": sorted(item.telemetry_requirement_ids),
                "verified_at_epoch": item.verified_at_epoch,
            }
            for item in sorted(manifest.routes, key=lambda value: value.route_id)
        ],
        "schema_version": manifest.schema_version,
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def control_plane_manifest_digest(manifest: ControlPlaneManifest) -> str:
    return hashlib.sha256(canonical_control_plane_manifest_bytes(manifest)).hexdigest()


def _validate_policy(policy: ControlPlanePolicy) -> None:
    hashes = (
        policy.expected_control_plane_sha256,
        policy.expected_p7b_assessment_evidence_sha256,
        policy.expected_p7e_assessment_evidence_sha256,
        policy.expected_p7f_assessment_evidence_sha256,
        policy.expected_p7g_assessment_evidence_sha256,
        policy.expected_posture_evidence_sha256,
        policy.expected_control_catalog_sha256,
    )
    if (
        not policy.expected_control_plane_id
        or not policy.expected_control_plane_version
        or not all(_is_sha256(value) for value in hashes)
        or not policy.required_principal_ids
        or not policy.required_resource_ids
        or not policy.required_route_ids
        or not policy.trusted_owner_ids
        or not policy.trusted_approver_ids
        or not policy.trusted_execution_identity_ids
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
        or policy.max_route_observation_age_seconds <= 0
    ):
        _reject(ControlPlaneRejectReason.POLICY_INVALID, "control-plane policy metadata is invalid")

    principal_maps = (
        policy.expected_principal_type,
        policy.expected_p7b_path_ids_by_principal,
        policy.expected_break_glass_capable,
    )
    if any(set(mapping) != set(policy.required_principal_ids) for mapping in principal_maps):
        _reject(ControlPlaneRejectReason.POLICY_INVALID, "principal policy maps must exactly cover required principals")

    resource_maps = (
        policy.expected_resource_type,
        policy.minimum_sensitivity,
        policy.expected_resource_upstream_binding_ids,
        policy.expected_resource_control_ids,
        policy.expected_resource_telemetry_requirement_ids,
        policy.expected_separation_of_duties,
        policy.expected_break_glass_permitted,
    )
    if any(set(mapping) != set(policy.required_resource_ids) for mapping in resource_maps):
        _reject(ControlPlaneRejectReason.POLICY_INVALID, "resource policy maps must exactly cover required resources")

    route_maps = (
        policy.expected_route_principal,
        policy.expected_route_resource,
        policy.expected_route_operation,
        policy.expected_execution_identity,
        policy.expected_approval_principal_ids,
        policy.expected_route_control_ids,
        policy.expected_route_telemetry_requirement_ids,
        policy.expected_proposed_version,
        policy.expected_break_glass,
    )
    if any(set(mapping) != set(policy.required_route_ids) for mapping in route_maps):
        _reject(ControlPlaneRejectReason.POLICY_INVALID, "route policy maps must exactly cover required routes")

    for route_id in policy.required_route_ids:
        principal_id = policy.expected_route_principal[route_id]
        resource_id = policy.expected_route_resource[route_id]
        if principal_id not in policy.required_principal_ids or resource_id not in policy.required_resource_ids:
            _reject(ControlPlaneRejectReason.POLICY_INVALID, "route policy references unknown principal/resource", route_id=route_id)
        approvals = policy.expected_approval_principal_ids[route_id]
        if not approvals or not approvals.issubset(policy.trusted_approver_ids) or principal_id in approvals:
            _reject(ControlPlaneRejectReason.POLICY_INVALID, "route policy approvals violate separation of duties", route_id=route_id)
        if policy.expected_execution_identity[route_id] not in policy.trusted_execution_identity_ids:
            _reject(ControlPlaneRejectReason.POLICY_INVALID, "route policy execution identity is untrusted", route_id=route_id)


def _validate_upstreams(
    policy: ControlPlanePolicy,
    p7b: object,
    p7e: object,
    p7f: object,
    p7g: object,
    posture: object,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object], dict[str, str]]:
    if not _verified(p7b, "exact_identity_graph_binding_verified", "privilege_amplification_derived_from_evidence"):
        _reject(ControlPlaneRejectReason.P7B_ASSESSMENT_UNVERIFIED, "P7-B privilege evidence is not fully verified")
    if _assessment_digest(p7b) != policy.expected_p7b_assessment_evidence_sha256.casefold():
        _reject(ControlPlaneRejectReason.P7B_ASSESSMENT_MISMATCH, "P7-B evidence digest does not match policy")

    if not _verified(p7e, "exact_dependency_graph_binding_verified", "risk_derived_from_evidence"):
        _reject(ControlPlaneRejectReason.P7E_ASSESSMENT_UNVERIFIED, "P7-E dependency evidence is not fully verified")
    if _assessment_digest(p7e) != policy.expected_p7e_assessment_evidence_sha256.casefold():
        _reject(ControlPlaneRejectReason.P7E_ASSESSMENT_MISMATCH, "P7-E evidence digest does not match policy")

    if not _verified(p7f, "exact_resilience_plan_binding_verified", "security_degradation_derived_from_evidence"):
        _reject(ControlPlaneRejectReason.P7F_ASSESSMENT_UNVERIFIED, "P7-F resilience evidence is not fully verified")
    if _assessment_digest(p7f) != policy.expected_p7f_assessment_evidence_sha256.casefold():
        _reject(ControlPlaneRejectReason.P7F_ASSESSMENT_MISMATCH, "P7-F evidence digest does not match policy")

    if not _verified(p7g, "exact_telemetry_plan_binding_verified", "audit_integrity_derived_from_evidence", "fallback_observability_derived_from_evidence"):
        _reject(ControlPlaneRejectReason.P7G_ASSESSMENT_UNVERIFIED, "P7-G telemetry evidence is not fully verified")
    if _assessment_digest(p7g) != policy.expected_p7g_assessment_evidence_sha256.casefold():
        _reject(ControlPlaneRejectReason.P7G_ASSESSMENT_MISMATCH, "P7-G evidence digest does not match policy")

    if not _verified(posture, "exact_release_identity_verified", "exact_upstream_evidence_binding_verified", "control_catalog_verified", "status_derived_from_evidence"):
        _reject(ControlPlaneRejectReason.POSTURE_UNVERIFIED, "P6-D posture evidence is not fully verified")
    if str(getattr(posture, "posture_evidence_sha256", "")).casefold() != policy.expected_posture_evidence_sha256.casefold():
        _reject(ControlPlaneRejectReason.POSTURE_DIGEST_MISMATCH, "P6-D posture digest does not match policy")
    if str(getattr(posture, "control_catalog_sha256", "")).casefold() != policy.expected_control_catalog_sha256.casefold():
        _reject(ControlPlaneRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog does not match policy")

    statuses: dict[str, str] = {}
    for assessment in tuple(getattr(posture, "assessments", ())):
        control_id = str(getattr(assessment, "control_id", ""))
        status = _status_value(getattr(assessment, "status", ""))
        if not control_id or control_id in statuses or status not in {"satisfied", "exceptioned", "not_evaluated"}:
            _reject(ControlPlaneRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control evidence is duplicate or malformed", control_id=control_id or None)
        statuses[control_id] = status
    if set(getattr(posture, "satisfied_control_ids", ())) != {key for key, value in statuses.items() if value == "satisfied"}:
        _reject(ControlPlaneRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D satisfied-control summary is inconsistent")
    if set(getattr(posture, "exceptioned_control_ids", ())) != {key for key, value in statuses.items() if value == "exceptioned"}:
        _reject(ControlPlaneRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D exception summary is inconsistent")
    if set(getattr(posture, "not_evaluated_control_ids", ())) != {key for key, value in statuses.items() if value == "not_evaluated"}:
        _reject(ControlPlaneRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D not-evaluated summary is inconsistent")

    def unique(items: tuple[object, ...], attribute: str, reason: ControlPlaneRejectReason) -> dict[str, object]:
        result: dict[str, object] = {}
        for item in items:
            object_id = str(getattr(item, attribute, ""))
            if not object_id or object_id in result:
                _reject(reason, "upstream assessment contains duplicate or empty object identifiers")
            result[object_id] = item
        return result

    p7b_paths = unique(tuple(getattr(p7b, "paths", ())), "path_id", ControlPlaneRejectReason.P7B_ASSESSMENT_UNVERIFIED)
    p7e_paths = unique(tuple(getattr(p7e, "paths", ())), "path_id", ControlPlaneRejectReason.P7E_ASSESSMENT_UNVERIFIED)
    p7f_scenarios = unique(tuple(getattr(p7f, "scenarios", ())), "scenario_id", ControlPlaneRejectReason.P7F_ASSESSMENT_UNVERIFIED)
    p7g_requirements = unique(tuple(getattr(p7g, "requirements", ())), "requirement_id", ControlPlaneRejectReason.P7G_ASSESSMENT_UNVERIFIED)
    return p7b_paths, p7e_paths, p7f_scenarios, p7g_requirements, statuses


def _binding_exists(
    binding_id: str,
    p7b_paths: Mapping[str, object],
    p7e_paths: Mapping[str, object],
    p7f_scenarios: Mapping[str, object],
    p7g_requirements: Mapping[str, object],
    statuses: Mapping[str, str],
) -> bool:
    if ":" not in binding_id:
        return False
    source, object_id = binding_id.split(":", 1)
    return {
        "p7b": object_id in p7b_paths,
        "p7e": object_id in p7e_paths,
        "p7f": object_id in p7f_scenarios,
        "p7g": object_id in p7g_requirements,
        "p6d": object_id in statuses,
    }.get(source, False)


def _binding_exposed(
    binding_id: str,
    p7b_paths: Mapping[str, object],
    p7e_paths: Mapping[str, object],
    p7f_scenarios: Mapping[str, object],
    p7g_requirements: Mapping[str, object],
    statuses: Mapping[str, str],
) -> bool:
    source, object_id = binding_id.split(":", 1)
    if source == "p7b":
        return bool(getattr(p7b_paths[object_id], "exposed", False))
    if source == "p7e":
        return bool(getattr(p7e_paths[object_id], "exposed", False))
    if source == "p7f":
        return bool(getattr(p7f_scenarios[object_id], "exposed", False))
    if source == "p7g":
        return bool(getattr(p7g_requirements[object_id], "blind_spot", False))
    if source == "p6d":
        return statuses[object_id] != "satisfied"
    return True


def _validate_manifest(
    policy: ControlPlanePolicy,
    request: ControlPlaneRequest,
    manifest: ControlPlaneManifest,
    p7b_paths: Mapping[str, object],
    p7e_paths: Mapping[str, object],
    p7f_scenarios: Mapping[str, object],
    p7g_requirements: Mapping[str, object],
    statuses: Mapping[str, str],
) -> tuple[dict[str, AdministrativePrincipal], dict[str, ControlPlaneResource], dict[str, AdministrativeChangeRoute], str]:
    if (
        manifest.schema_version != P7H_CONTROL_PLANE_MANIFEST_SCHEMA_VERSION
        or manifest.control_plane_id != policy.expected_control_plane_id
        or manifest.version != policy.expected_control_plane_version
        or not manifest.principals
        or not manifest.resources
        or not manifest.routes
    ):
        _reject(ControlPlaneRejectReason.MANIFEST_INVALID, "control-plane manifest metadata is invalid")

    expected_upstream = (
        (manifest.p7b_assessment_evidence_sha256, policy.expected_p7b_assessment_evidence_sha256),
        (manifest.p7e_assessment_evidence_sha256, policy.expected_p7e_assessment_evidence_sha256),
        (manifest.p7f_assessment_evidence_sha256, policy.expected_p7f_assessment_evidence_sha256),
        (manifest.p7g_assessment_evidence_sha256, policy.expected_p7g_assessment_evidence_sha256),
        (manifest.posture_evidence_sha256, policy.expected_posture_evidence_sha256),
    )
    if any(left.casefold() != right.casefold() for left, right in expected_upstream):
        _reject(ControlPlaneRejectReason.MANIFEST_INVALID, "control-plane manifest upstream evidence binding is invalid")
    if manifest.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        _reject(ControlPlaneRejectReason.MANIFEST_FUTURE, "control-plane manifest is future-dated")
    if request.evaluated_at_epoch - manifest.created_at_epoch > policy.max_manifest_age_seconds:
        _reject(ControlPlaneRejectReason.MANIFEST_STALE, "control-plane manifest is stale")

    actual_sha = control_plane_manifest_digest(manifest)
    if not hmac.compare_digest(actual_sha, policy.expected_control_plane_sha256.casefold()) or not hmac.compare_digest(actual_sha, request.control_plane_sha256.casefold()):
        _reject(ControlPlaneRejectReason.MANIFEST_DIGEST_MISMATCH, "control-plane manifest digest does not match request/policy")

    principals: dict[str, AdministrativePrincipal] = {}
    for principal in manifest.principals:
        if not principal.principal_id or principal.principal_id in principals:
            _reject(ControlPlaneRejectReason.PRINCIPAL_DUPLICATE, "principal is duplicate or empty", principal_id=principal.principal_id or None)
        principals[principal.principal_id] = principal
    if set(principals) != set(policy.required_principal_ids):
        _reject(ControlPlaneRejectReason.PRINCIPAL_COVERAGE_MISMATCH, "principal coverage differs from policy")
    for principal_id, principal in principals.items():
        if principal.owner_id not in policy.trusted_owner_ids:
            _reject(ControlPlaneRejectReason.PRINCIPAL_OWNER_UNTRUSTED, "principal owner is untrusted", principal_id=principal_id)
        if principal.principal_type != policy.expected_principal_type[principal_id]:
            _reject(ControlPlaneRejectReason.PRINCIPAL_TYPE_DRIFT, "principal type differs from policy", principal_id=principal_id)
        if set(principal.p7b_path_ids) != set(policy.expected_p7b_path_ids_by_principal[principal_id]) or len(set(principal.p7b_path_ids)) != len(principal.p7b_path_ids):
            _reject(ControlPlaneRejectReason.PRINCIPAL_PATH_DRIFT, "principal privilege-path binding differs from policy", principal_id=principal_id)
        if any(path_id not in p7b_paths for path_id in principal.p7b_path_ids):
            _reject(ControlPlaneRejectReason.PRINCIPAL_PATH_UNKNOWN, "principal references unknown P7-B path", principal_id=principal_id)
        if principal.break_glass_capable != policy.expected_break_glass_capable[principal_id]:
            _reject(ControlPlaneRejectReason.PRINCIPAL_BREAK_GLASS_DRIFT, "principal break-glass capability differs from policy", principal_id=principal_id)

    resources: dict[str, ControlPlaneResource] = {}
    for resource in manifest.resources:
        if not resource.resource_id or resource.resource_id in resources:
            _reject(ControlPlaneRejectReason.RESOURCE_DUPLICATE, "resource is duplicate or empty", resource_id=resource.resource_id or None)
        resources[resource.resource_id] = resource
    if set(resources) != set(policy.required_resource_ids):
        _reject(ControlPlaneRejectReason.RESOURCE_COVERAGE_MISMATCH, "resource coverage differs from policy")
    for resource_id, resource in resources.items():
        if resource.owner_id not in policy.trusted_owner_ids:
            _reject(ControlPlaneRejectReason.RESOURCE_OWNER_UNTRUSTED, "resource owner is untrusted", resource_id=resource_id)
        if resource.resource_type != policy.expected_resource_type[resource_id]:
            _reject(ControlPlaneRejectReason.RESOURCE_TYPE_DRIFT, "resource type differs from policy", resource_id=resource_id)
        if _severity_rank(resource.sensitivity) < _severity_rank(policy.minimum_sensitivity[resource_id]):
            _reject(ControlPlaneRejectReason.RESOURCE_SENSITIVITY_DOWNGRADE, "resource sensitivity is below policy floor", resource_id=resource_id)
        if not resource.current_version:
            _reject(ControlPlaneRejectReason.MANIFEST_INVALID, "resource version is empty", resource_id=resource_id)
        if set(resource.upstream_binding_ids) != set(policy.expected_resource_upstream_binding_ids[resource_id]) or len(set(resource.upstream_binding_ids)) != len(resource.upstream_binding_ids):
            _reject(ControlPlaneRejectReason.RESOURCE_BINDING_DRIFT, "resource upstream bindings differ from policy", resource_id=resource_id)
        if any(not _binding_exists(value, p7b_paths, p7e_paths, p7f_scenarios, p7g_requirements, statuses) for value in resource.upstream_binding_ids):
            _reject(ControlPlaneRejectReason.RESOURCE_BINDING_UNKNOWN, "resource references unknown upstream evidence", resource_id=resource_id)
        if set(resource.required_control_ids) != set(policy.expected_resource_control_ids[resource_id]) or len(set(resource.required_control_ids)) != len(resource.required_control_ids):
            _reject(ControlPlaneRejectReason.RESOURCE_CONTROL_DRIFT, "resource control requirements differ from policy", resource_id=resource_id)
        if any(control_id not in statuses for control_id in resource.required_control_ids):
            _reject(ControlPlaneRejectReason.RESOURCE_CONTROL_UNKNOWN, "resource references unknown control", resource_id=resource_id)
        if set(resource.required_telemetry_requirement_ids) != set(policy.expected_resource_telemetry_requirement_ids[resource_id]) or len(set(resource.required_telemetry_requirement_ids)) != len(resource.required_telemetry_requirement_ids):
            _reject(ControlPlaneRejectReason.RESOURCE_TELEMETRY_DRIFT, "resource telemetry requirements differ from policy", resource_id=resource_id)
        if any(requirement_id not in p7g_requirements for requirement_id in resource.required_telemetry_requirement_ids):
            _reject(ControlPlaneRejectReason.RESOURCE_TELEMETRY_UNKNOWN, "resource references unknown telemetry requirement", resource_id=resource_id)
        if resource.separation_of_duties_required != policy.expected_separation_of_duties[resource_id]:
            _reject(ControlPlaneRejectReason.RESOURCE_SEPARATION_OF_DUTIES_DRIFT, "resource separation-of-duties setting differs from policy", resource_id=resource_id)
        if resource.break_glass_permitted != policy.expected_break_glass_permitted[resource_id]:
            _reject(ControlPlaneRejectReason.RESOURCE_BREAK_GLASS_DRIFT, "resource break-glass setting differs from policy", resource_id=resource_id)

    routes: dict[str, AdministrativeChangeRoute] = {}
    for route in manifest.routes:
        if not route.route_id or route.route_id in routes:
            _reject(ControlPlaneRejectReason.ROUTE_DUPLICATE, "route is duplicate or empty", route_id=route.route_id or None)
        routes[route.route_id] = route
    if set(routes) != set(policy.required_route_ids):
        _reject(ControlPlaneRejectReason.ROUTE_COVERAGE_MISMATCH, "route coverage differs from policy")
    for route_id, route in routes.items():
        if route.owner_id not in policy.trusted_owner_ids:
            _reject(ControlPlaneRejectReason.ROUTE_OWNER_UNTRUSTED, "route owner is untrusted", route_id=route_id)
        if route.principal_id not in principals or route.resource_id not in resources:
            _reject(ControlPlaneRejectReason.ROUTE_REFERENCE_INVALID, "route references unknown principal/resource", route_id=route_id)
        if route.principal_id != policy.expected_route_principal[route_id]:
            _reject(ControlPlaneRejectReason.ROUTE_PRINCIPAL_DRIFT, "route principal differs from policy", route_id=route_id)
        if route.resource_id != policy.expected_route_resource[route_id]:
            _reject(ControlPlaneRejectReason.ROUTE_RESOURCE_DRIFT, "route resource differs from policy", route_id=route_id)
        if route.operation != policy.expected_route_operation[route_id]:
            _reject(ControlPlaneRejectReason.ROUTE_OPERATION_DRIFT, "route operation differs from policy", route_id=route_id)
        if route.execution_identity_id not in policy.trusted_execution_identity_ids:
            _reject(ControlPlaneRejectReason.ROUTE_EXECUTION_IDENTITY_UNTRUSTED, "route execution identity is untrusted", route_id=route_id)
        if route.execution_identity_id != policy.expected_execution_identity[route_id]:
            _reject(ControlPlaneRejectReason.ROUTE_EXECUTION_IDENTITY_DRIFT, "route execution identity differs from policy", route_id=route_id)
        if set(route.approval_principal_ids) != set(policy.expected_approval_principal_ids[route_id]) or len(set(route.approval_principal_ids)) != len(route.approval_principal_ids):
            _reject(ControlPlaneRejectReason.ROUTE_APPROVAL_DRIFT, "route approvals differ from policy", route_id=route_id)
        if any(value not in policy.trusted_approver_ids for value in route.approval_principal_ids):
            _reject(ControlPlaneRejectReason.ROUTE_APPROVER_UNTRUSTED, "route includes untrusted approver", route_id=route_id)
        if resources[route.resource_id].separation_of_duties_required and route.principal_id in route.approval_principal_ids:
            _reject(ControlPlaneRejectReason.ROUTE_SELF_APPROVAL, "route principal cannot approve its own change", route_id=route_id)
        if set(route.required_control_ids) != set(policy.expected_route_control_ids[route_id]) or len(set(route.required_control_ids)) != len(route.required_control_ids):
            _reject(ControlPlaneRejectReason.ROUTE_CONTROL_DRIFT, "route controls differ from policy", route_id=route_id)
        if any(control_id not in statuses for control_id in route.required_control_ids):
            _reject(ControlPlaneRejectReason.ROUTE_CONTROL_UNKNOWN, "route references unknown control", route_id=route_id)
        if set(route.telemetry_requirement_ids) != set(policy.expected_route_telemetry_requirement_ids[route_id]) or len(set(route.telemetry_requirement_ids)) != len(route.telemetry_requirement_ids):
            _reject(ControlPlaneRejectReason.ROUTE_TELEMETRY_DRIFT, "route telemetry differs from policy", route_id=route_id)
        if any(requirement_id not in p7g_requirements for requirement_id in route.telemetry_requirement_ids):
            _reject(ControlPlaneRejectReason.ROUTE_TELEMETRY_UNKNOWN, "route references unknown telemetry requirement", route_id=route_id)
        resource = resources[route.resource_id]
        if not set(resource.required_control_ids).issubset(route.required_control_ids):
            _reject(ControlPlaneRejectReason.ROUTE_CONTROL_DRIFT, "route omits resource-required controls", route_id=route_id)
        if not set(resource.required_telemetry_requirement_ids).issubset(route.telemetry_requirement_ids):
            _reject(ControlPlaneRejectReason.ROUTE_TELEMETRY_DRIFT, "route omits resource-required telemetry", route_id=route_id)
        if route.proposed_version != policy.expected_proposed_version[route_id] or route.proposed_version == resource.current_version:
            _reject(ControlPlaneRejectReason.ROUTE_VERSION_DRIFT, "route proposed version differs from policy/current state", route_id=route_id)
        if not _is_sha256(route.target_state_sha256):
            _reject(ControlPlaneRejectReason.ROUTE_TARGET_DIGEST_INVALID, "route target state digest is invalid", route_id=route_id)
        if route.break_glass != policy.expected_break_glass[route_id]:
            _reject(ControlPlaneRejectReason.ROUTE_BREAK_GLASS_DRIFT, "route break-glass setting differs from policy", route_id=route_id)
        principal = principals[route.principal_id]
        if route.break_glass:
            if not principal.break_glass_capable or not resource.break_glass_permitted or not route.emergency_reason:
                _reject(ControlPlaneRejectReason.ROUTE_BREAK_GLASS_INVALID, "break-glass route lacks capability/resource permission/emergency reason", route_id=route_id)
        elif route.emergency_reason is not None:
            _reject(ControlPlaneRejectReason.ROUTE_BREAK_GLASS_INVALID, "non-break-glass route cannot carry emergency reason", route_id=route_id)
        if not route.change_ticket_id:
            _reject(ControlPlaneRejectReason.ROUTE_TICKET_INVALID, "route change ticket identifier is empty", route_id=route_id)
        if route.verified_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
            _reject(ControlPlaneRejectReason.ROUTE_OBSERVATION_FUTURE, "route verification is future-dated", route_id=route_id)
        if request.evaluated_at_epoch - route.verified_at_epoch > policy.max_route_observation_age_seconds:
            _reject(ControlPlaneRejectReason.ROUTE_OBSERVATION_STALE, "route verification is stale", route_id=route_id)

    return principals, resources, routes, actual_sha


def _risk_score(sensitivity: ControlPlaneSensitivity, reasons: tuple[str, ...]) -> int:
    score = {
        ControlPlaneSensitivity.LOW: 20,
        ControlPlaneSensitivity.MEDIUM: 40,
        ControlPlaneSensitivity.HIGH: 65,
        ControlPlaneSensitivity.CRITICAL: 85,
    }[sensitivity]
    weights = {
        "admin_privilege_path_exposed": 28,
        "resource_upstream_exposed": 24,
        "exceptioned_control": 18,
        "not_evaluated_control": 16,
        "change_telemetry_blind_spot": 26,
        "self_authorization_mutation": 32,
        "self_audit_mutation": 35,
        "critical_destructive_operation": 30,
    }
    return score + sum(weights.get(reason, 0) for reason in reasons)


class SecurityControlPlaneChangeAnalyzer:
    def __init__(self, policy: ControlPlanePolicy) -> None:
        _validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: ControlPlaneRequest,
        manifest: ControlPlaneManifest,
        p7b_assessment: object,
        p7e_assessment: object,
        p7f_assessment: object,
        p7g_assessment: object,
        posture: object,
    ) -> VerifiedControlPlaneAssessment:
        request_hashes = (
            request.control_plane_sha256,
            request.p7b_assessment_evidence_sha256,
            request.p7e_assessment_evidence_sha256,
            request.p7f_assessment_evidence_sha256,
            request.p7g_assessment_evidence_sha256,
            request.posture_evidence_sha256,
        )
        expected_hashes = (
            self.policy.expected_control_plane_sha256,
            self.policy.expected_p7b_assessment_evidence_sha256,
            self.policy.expected_p7e_assessment_evidence_sha256,
            self.policy.expected_p7f_assessment_evidence_sha256,
            self.policy.expected_p7g_assessment_evidence_sha256,
            self.policy.expected_posture_evidence_sha256,
        )
        if (
            request.control_plane_id != self.policy.expected_control_plane_id
            or request.control_plane_version != self.policy.expected_control_plane_version
            or not all(_is_sha256(value) for value in request_hashes)
            or any(left.casefold() != right.casefold() for left, right in zip(request_hashes, expected_hashes))
            or set(request.route_ids) != set(self.policy.required_route_ids)
            or len(set(request.route_ids)) != len(request.route_ids)
        ):
            _reject(ControlPlaneRejectReason.REQUEST_INVALID, "control-plane request identity/evidence/scope is invalid")

        p7b_paths, p7e_paths, p7f_scenarios, p7g_requirements, statuses = _validate_upstreams(
            self.policy,
            p7b_assessment,
            p7e_assessment,
            p7f_assessment,
            p7g_assessment,
            posture,
        )
        principals, resources, routes, manifest_sha = _validate_manifest(
            self.policy,
            request,
            manifest,
            p7b_paths,
            p7e_paths,
            p7f_scenarios,
            p7g_requirements,
            statuses,
        )

        facts: list[ControlPlaneChangePathFact] = []
        for route_id in sorted(routes):
            route = routes[route_id]
            principal = principals[route.principal_id]
            resource = resources[route.resource_id]
            exceptioned = tuple(sorted(control_id for control_id in route.required_control_ids if statuses[control_id] == "exceptioned"))
            not_evaluated = tuple(sorted(control_id for control_id in route.required_control_ids if statuses[control_id] == "not_evaluated"))
            satisfied = tuple(sorted(control_id for control_id in route.required_control_ids if statuses[control_id] == "satisfied"))
            blind_spot_telemetry = tuple(sorted(requirement_id for requirement_id in route.telemetry_requirement_ids if bool(getattr(p7g_requirements[requirement_id], "blind_spot", False))))
            exposed_bindings = tuple(sorted(binding_id for binding_id in resource.upstream_binding_ids if _binding_exposed(binding_id, p7b_paths, p7e_paths, p7f_scenarios, p7g_requirements, statuses)))
            admin_path_exposed = any(bool(getattr(p7b_paths[path_id], "exposed", False)) for path_id in principal.p7b_path_ids)
            self_authorization_mutation = (
                resource.resource_type == ControlPlaneResourceType.AUTHORIZATION_POLICY
                and bool({f"p7b:{path_id}" for path_id in principal.p7b_path_ids} & set(resource.upstream_binding_ids))
            )
            self_audit_mutation = (
                resource.resource_type == ControlPlaneResourceType.TELEMETRY_CONFIGURATION
                and bool({f"p7g:{requirement_id}" for requirement_id in route.telemetry_requirement_ids} & set(resource.upstream_binding_ids))
            )

            reasons: list[str] = []
            if admin_path_exposed:
                reasons.append("admin_privilege_path_exposed")
            if exposed_bindings:
                reasons.append("resource_upstream_exposed")
            if exceptioned:
                reasons.append("exceptioned_control")
            if not_evaluated:
                reasons.append("not_evaluated_control")
            if blind_spot_telemetry:
                reasons.append("change_telemetry_blind_spot")
            if self_authorization_mutation:
                reasons.append("self_authorization_mutation")
            if self_audit_mutation:
                reasons.append("self_audit_mutation")
            if resource.sensitivity == ControlPlaneSensitivity.CRITICAL and route.operation in {AdministrativeOperation.DISABLE, AdministrativeOperation.DELETE}:
                reasons.append("critical_destructive_operation")

            exposed = bool(reasons)
            risk = _risk_score(resource.sensitivity, tuple(reasons)) if exposed else 0
            facts.append(
                ControlPlaneChangePathFact(
                    route_id=route_id,
                    principal_id=route.principal_id,
                    resource_id=route.resource_id,
                    resource_type=resource.resource_type,
                    resource_sensitivity=resource.sensitivity,
                    operation=route.operation,
                    approval_principal_ids=tuple(sorted(route.approval_principal_ids)),
                    execution_identity_id=route.execution_identity_id,
                    p7b_path_ids=tuple(sorted(principal.p7b_path_ids)),
                    required_control_ids=tuple(sorted(route.required_control_ids)),
                    telemetry_requirement_ids=tuple(sorted(route.telemetry_requirement_ids)),
                    exceptioned_control_ids=exceptioned,
                    not_evaluated_control_ids=not_evaluated,
                    blind_spot_telemetry_requirement_ids=blind_spot_telemetry,
                    exposed_upstream_binding_ids=exposed_bindings,
                    self_authorization_mutation=self_authorization_mutation,
                    self_audit_mutation=self_audit_mutation,
                    break_glass=route.break_glass,
                    exposed=exposed,
                    risk_score=risk,
                    exposure_reasons=tuple(reasons),
                    mitigating_control_ids=satisfied,
                )
            )

        exposed_facts = [item for item in facts if item.exposed]
        prioritized = tuple(item.route_id for item in sorted(exposed_facts, key=lambda value: (-value.risk_score, value.route_id)))
        max_risk = max((item.risk_score for item in exposed_facts), default=0)
        if set(request.declared_exposed_route_ids) != set(prioritized):
            _reject(ControlPlaneRejectReason.DECLARED_PATH_MISMATCH, "caller-declared exposed administrative routes differ from evidence")
        if request.declared_max_exposed_risk_score != max_risk:
            _reject(ControlPlaneRejectReason.DECLARED_RISK_MISMATCH, "caller-declared administrative risk differs from evidence")

        evidence_document = {
            "control_catalog_sha256": str(getattr(posture, "control_catalog_sha256", "")).casefold(),
            "control_plane_sha256": manifest_sha,
            "p7b_assessment_evidence_sha256": _assessment_digest(p7b_assessment),
            "p7e_assessment_evidence_sha256": _assessment_digest(p7e_assessment),
            "p7f_assessment_evidence_sha256": _assessment_digest(p7f_assessment),
            "p7g_assessment_evidence_sha256": _assessment_digest(p7g_assessment),
            "posture_evidence_sha256": str(getattr(posture, "posture_evidence_sha256", "")).casefold(),
            "prioritized_exposed_route_ids": list(prioritized),
            "routes": [asdict(item) for item in facts],
        }
        assessment_sha = hashlib.sha256(json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
        return VerifiedControlPlaneAssessment(
            control_plane_id=manifest.control_plane_id,
            control_plane_version=manifest.version,
            control_plane_sha256=manifest_sha,
            p7b_assessment_evidence_sha256=_assessment_digest(p7b_assessment),
            p7e_assessment_evidence_sha256=_assessment_digest(p7e_assessment),
            p7f_assessment_evidence_sha256=_assessment_digest(p7f_assessment),
            p7g_assessment_evidence_sha256=_assessment_digest(p7g_assessment),
            posture_evidence_sha256=str(getattr(posture, "posture_evidence_sha256", "")).casefold(),
            control_catalog_sha256=str(getattr(posture, "control_catalog_sha256", "")).casefold(),
            route_count=len(facts),
            exposed_route_count=len(exposed_facts),
            controlled_route_count=len(facts) - len(exposed_facts),
            critical_resource_exposed_route_count=sum(item.resource_sensitivity == ControlPlaneSensitivity.CRITICAL for item in exposed_facts),
            self_authorization_mutation_count=sum(item.self_authorization_mutation for item in facts),
            self_audit_mutation_count=sum(item.self_audit_mutation for item in facts),
            break_glass_route_count=sum(item.break_glass for item in facts),
            max_exposed_risk_score=max_risk,
            prioritized_exposed_route_ids=prioritized,
            routes=tuple(facts),
            assessment_evidence_sha256=assessment_sha,
        )
