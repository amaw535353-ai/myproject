from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .attack_paths import ArchitectureManifest, VerifiedAttackPathAssessment, architecture_manifest_digest
from .data_types import VerifiedDataExfiltrationAssessment
from .privilege_types import VerifiedPrivilegeEscalationAssessment
from .secrets_exposure import VerifiedSecretExposureAssessment


P7E_DEPENDENCY_POLICY_VERSION = "external-dependency-service-egress-trust-path-v1"
P7E_DEPENDENCY_MANIFEST_SCHEMA_VERSION = "aegis-external-dependency-trust-manifest-v1"
P7E_ASSESSMENT_SCHEMA_VERSION = "aegis-third-party-trust-path-assessment-v1"
P7E_ASSESSMENT_MODE = "deterministic-evidence-bound-third-party-egress-analysis-v1"


class DependencyType(StrEnum):
    MODEL_PROVIDER = "model_provider"
    TOOL_API = "tool_api"
    IDENTITY_PROVIDER = "identity_provider"
    TELEMETRY_SINK = "telemetry_sink"
    PACKAGE_REGISTRY = "package_registry"
    SECURITY_SERVICE = "security_service"


class DependencyCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TransportMode(StrEnum):
    TLS = "tls"
    MTLS = "mtls"
    PRIVATE_LINK = "private_link"
    PLAINTEXT = "plaintext"


class AuthenticationMode(StrEnum):
    NONE = "none"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    SIGNED_REQUEST = "signed_request"


class EgressDataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class DependencyTrustRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    ARCHITECTURE_INVALID = "architecture_invalid"
    ARCHITECTURE_DIGEST_MISMATCH = "architecture_digest_mismatch"
    P7A_ASSESSMENT_UNVERIFIED = "p7a_assessment_unverified"
    P7A_ASSESSMENT_MISMATCH = "p7a_assessment_mismatch"
    P7B_ASSESSMENT_UNVERIFIED = "p7b_assessment_unverified"
    P7B_ASSESSMENT_MISMATCH = "p7b_assessment_mismatch"
    P7C_ASSESSMENT_UNVERIFIED = "p7c_assessment_unverified"
    P7C_ASSESSMENT_MISMATCH = "p7c_assessment_mismatch"
    P7D_ASSESSMENT_UNVERIFIED = "p7d_assessment_unverified"
    P7D_ASSESSMENT_MISMATCH = "p7d_assessment_mismatch"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    DEPENDENCY_DUPLICATE = "dependency_duplicate"
    DEPENDENCY_COVERAGE_MISMATCH = "dependency_coverage_mismatch"
    DEPENDENCY_OWNER_UNTRUSTED = "dependency_owner_untrusted"
    PROVIDER_UNTRUSTED = "provider_untrusted"
    DEPENDENCY_TYPE_DRIFT = "dependency_type_drift"
    CRITICALITY_DOWNGRADE = "criticality_downgrade"
    ENDPOINT_DRIFT = "endpoint_drift"
    PORT_DRIFT = "port_drift"
    TRANSPORT_DRIFT = "transport_drift"
    AUTHENTICATION_DRIFT = "authentication_drift"
    SERVER_IDENTITY_DRIFT = "server_identity_drift"
    DATA_CLASS_SCOPE_MISMATCH = "data_class_scope_mismatch"
    SECRET_SCOPE_MISMATCH = "secret_scope_mismatch"
    DEPENDENCY_CONTROL_DRIFT = "dependency_control_drift"
    DEPENDENCY_CONTROL_UNKNOWN = "dependency_control_unknown"
    FAIL_CLOSED_DRIFT = "fail_closed_drift"
    ROUTE_DUPLICATE = "route_duplicate"
    ROUTE_COVERAGE_MISMATCH = "route_coverage_mismatch"
    ROUTE_OWNER_UNTRUSTED = "route_owner_untrusted"
    ROUTE_REFERENCE_INVALID = "route_reference_invalid"
    ROUTE_SOURCE_DRIFT = "route_source_drift"
    ROUTE_DEPENDENCY_DRIFT = "route_dependency_drift"
    ROUTE_FLOW_DRIFT = "route_flow_drift"
    ROUTE_CONTROL_DRIFT = "route_control_drift"
    ROUTE_CONTROL_UNKNOWN = "route_control_unknown"
    ROUTE_ARCHITECTURE_INVALID = "route_architecture_invalid"
    ENTRY_SOURCE_SCOPE_MISMATCH = "entry_source_scope_mismatch"
    TARGET_DEPENDENCY_SCOPE_MISMATCH = "target_dependency_scope_mismatch"
    DECLARED_PATH_MISMATCH = "declared_path_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class DependencyTrustRejected(ValueError):
    def __init__(
        self,
        reason: DependencyTrustRejectReason,
        message: str,
        *,
        dependency_id: str | None = None,
        route_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.dependency_id = dependency_id
        self.route_id = route_id
        self.control_id = control_id


@dataclass(frozen=True)
class ExternalDependency:
    dependency_id: str
    provider_id: str
    dependency_type: DependencyType
    criticality: DependencyCriticality
    endpoint_host: str
    endpoint_port: int
    transport_mode: TransportMode
    authentication_mode: AuthenticationMode
    expected_server_identity: str
    owner_id: str
    egress_data_classes: tuple[EgressDataClass, ...]
    exposed_secret_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    fail_closed: bool
    description: str


@dataclass(frozen=True)
class ServiceEgressRoute:
    route_id: str
    source_asset_id: str
    dependency_id: str
    owner_id: str
    via_flow_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    purpose: str


@dataclass(frozen=True)
class DependencyTrustManifest:
    dependency_graph_id: str
    version: str
    architecture_sha256: str
    created_at_epoch: int
    dependencies: tuple[ExternalDependency, ...]
    routes: tuple[ServiceEgressRoute, ...]
    schema_version: str = P7E_DEPENDENCY_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class DependencyTrustRequest:
    dependency_graph_id: str
    dependency_graph_version: str
    dependency_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    entry_source_asset_ids: tuple[str, ...]
    target_dependency_ids: tuple[str, ...]
    evaluated_at_epoch: int
    declared_exposed_path_ids: tuple[str, ...]
    declared_max_exposed_risk_score: int


@dataclass(frozen=True)
class DependencyTrustPolicy:
    expected_dependency_graph_id: str
    expected_dependency_graph_version: str
    expected_dependency_graph_sha256: str
    expected_architecture_sha256: str
    expected_p7a_assessment_evidence_sha256: str
    expected_p7b_assessment_evidence_sha256: str
    expected_p7c_assessment_evidence_sha256: str
    expected_p7d_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_dependency_ids: frozenset[str]
    required_route_ids: frozenset[str]
    entry_source_asset_ids: frozenset[str]
    target_dependency_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    trusted_provider_ids: frozenset[str]
    expected_dependency_type: Mapping[str, DependencyType]
    minimum_criticality: Mapping[str, DependencyCriticality]
    expected_endpoint_host: Mapping[str, str]
    expected_endpoint_port: Mapping[str, int]
    expected_transport_mode: Mapping[str, TransportMode]
    expected_authentication_mode: Mapping[str, AuthenticationMode]
    expected_server_identity: Mapping[str, str]
    allowed_egress_data_classes: Mapping[str, frozenset[EgressDataClass]]
    allowed_exposed_secret_ids: Mapping[str, frozenset[str]]
    expected_dependency_control_ids: Mapping[str, frozenset[str]]
    expected_fail_closed: Mapping[str, bool]
    expected_route_source_asset: Mapping[str, str]
    expected_route_dependency: Mapping[str, str]
    expected_route_flow_ids: Mapping[str, tuple[str, ...]]
    expected_route_control_ids: Mapping[str, frozenset[str]]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class ThirdPartyTrustPathFact:
    path_id: str
    route_id: str
    source_asset_id: str
    dependency_id: str
    provider_id: str
    dependency_type: DependencyType
    criticality: DependencyCriticality
    endpoint_host: str
    endpoint_port: int
    transport_mode: TransportMode
    authentication_mode: AuthenticationMode
    server_identity: str
    egress_data_classes: tuple[str, ...]
    exposed_secret_ids: tuple[str, ...]
    architecture_flow_ids: tuple[str, ...]
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    fail_closed: bool
    exposed: bool
    risk_score: int
    exposure_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedDependencyTrustAssessment:
    dependency_graph_id: str
    dependency_graph_version: str
    dependency_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    entry_source_asset_ids: tuple[str, ...]
    target_dependency_ids: tuple[str, ...]
    topology_path_count: int
    exposed_path_count: int
    controlled_path_count: int
    critical_exposed_path_count: int
    secret_bearing_exposed_path_count: int
    restricted_or_secret_data_exposed_path_count: int
    fail_open_exposed_path_count: int
    max_exposed_risk_score: int
    prioritized_exposed_path_ids: tuple[str, ...]
    paths: tuple[ThirdPartyTrustPathFact, ...]
    assessment_evidence_sha256: str
    exact_dependency_graph_binding_verified: bool = True
    exact_architecture_binding_verified: bool = True
    exact_p7a_assessment_binding_verified: bool = True
    exact_p7b_assessment_binding_verified: bool = True
    exact_p7c_assessment_binding_verified: bool = True
    exact_p7d_assessment_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    destination_identity_policy_pinned: bool = True
    transport_auth_policy_pinned: bool = True
    egress_scope_policy_pinned: bool = True
    fail_closed_policy_pinned: bool = True
    risk_derived_from_evidence: bool = True
    mitigating_controls_visible: bool = True
    caller_summary_trusted: bool = False
    production_dependency_discovery: bool = False
    live_dns_or_certificate_validation: bool = False
    production_egress_enforcement: bool = False
    real_third_party_requests: bool = False
    formal_supply_chain_assurance: bool = False
    network_operations: int = 0
    schema_version: str = P7E_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7E_DEPENDENCY_POLICY_VERSION
    assessment_mode: str = P7E_ASSESSMENT_MODE


def _reject(reason: DependencyTrustRejectReason, message: str, **context: str | None) -> None:
    raise DependencyTrustRejected(reason, message, **context)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _criticality_rank(value: DependencyCriticality) -> int:
    return {
        DependencyCriticality.LOW: 1,
        DependencyCriticality.MEDIUM: 2,
        DependencyCriticality.HIGH: 3,
        DependencyCriticality.CRITICAL: 4,
    }[value]


def _data_rank(value: EgressDataClass) -> int:
    return {
        EgressDataClass.PUBLIC: 1,
        EgressDataClass.INTERNAL: 2,
        EgressDataClass.CONFIDENTIAL: 3,
        EgressDataClass.RESTRICTED: 4,
        EgressDataClass.SECRET: 5,
    }[value]


def canonical_dependency_trust_manifest_bytes(manifest: DependencyTrustManifest) -> bytes:
    document = {
        "architecture_sha256": manifest.architecture_sha256.casefold(),
        "created_at_epoch": manifest.created_at_epoch,
        "dependencies": [
            {
                "authentication_mode": item.authentication_mode.value,
                "criticality": item.criticality.value,
                "dependency_id": item.dependency_id,
                "dependency_type": item.dependency_type.value,
                "description": item.description,
                "egress_data_classes": sorted(value.value for value in item.egress_data_classes),
                "endpoint_host": item.endpoint_host.casefold(),
                "endpoint_port": item.endpoint_port,
                "expected_server_identity": item.expected_server_identity.casefold(),
                "exposed_secret_ids": sorted(item.exposed_secret_ids),
                "fail_closed": item.fail_closed,
                "owner_id": item.owner_id,
                "provider_id": item.provider_id,
                "required_control_ids": sorted(item.required_control_ids),
                "transport_mode": item.transport_mode.value,
            }
            for item in sorted(manifest.dependencies, key=lambda value: value.dependency_id)
        ],
        "dependency_graph_id": manifest.dependency_graph_id,
        "routes": [
            {
                "dependency_id": item.dependency_id,
                "owner_id": item.owner_id,
                "purpose": item.purpose,
                "required_control_ids": sorted(item.required_control_ids),
                "route_id": item.route_id,
                "source_asset_id": item.source_asset_id,
                "via_flow_ids": list(item.via_flow_ids),
            }
            for item in sorted(manifest.routes, key=lambda value: value.route_id)
        ],
        "schema_version": manifest.schema_version,
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def dependency_trust_manifest_digest(manifest: DependencyTrustManifest) -> str:
    return hashlib.sha256(canonical_dependency_trust_manifest_bytes(manifest)).hexdigest()


def dependency_trust_path_identifier(route: ServiceEgressRoute, dependency: ExternalDependency) -> str:
    document = {
        "dependency_id": dependency.dependency_id,
        "route_id": route.route_id,
        "source_asset_id": route.source_asset_id,
        "via_flow_ids": list(route.via_flow_ids),
    }
    digest = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"third-party-path-{digest[:20]}"


def _validate_policy(policy: DependencyTrustPolicy) -> None:
    hashes = (
        policy.expected_dependency_graph_sha256,
        policy.expected_architecture_sha256,
        policy.expected_p7a_assessment_evidence_sha256,
        policy.expected_p7b_assessment_evidence_sha256,
        policy.expected_p7c_assessment_evidence_sha256,
        policy.expected_p7d_assessment_evidence_sha256,
        policy.expected_posture_evidence_sha256,
        policy.expected_control_catalog_sha256,
    )
    if (
        not policy.expected_dependency_graph_id
        or not policy.expected_dependency_graph_version
        or not all(_is_sha256(value) for value in hashes)
        or not policy.required_dependency_ids
        or not policy.required_route_ids
        or not policy.entry_source_asset_ids
        or not policy.target_dependency_ids
        or not policy.trusted_owner_ids
        or not policy.trusted_provider_ids
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
    ):
        _reject(DependencyTrustRejectReason.POLICY_INVALID, "dependency trust policy metadata is invalid")
    maps = (
        policy.expected_dependency_type,
        policy.minimum_criticality,
        policy.expected_endpoint_host,
        policy.expected_endpoint_port,
        policy.expected_transport_mode,
        policy.expected_authentication_mode,
        policy.expected_server_identity,
        policy.allowed_egress_data_classes,
        policy.allowed_exposed_secret_ids,
        policy.expected_dependency_control_ids,
        policy.expected_fail_closed,
    )
    if any(set(mapping) != set(policy.required_dependency_ids) for mapping in maps):
        _reject(DependencyTrustRejectReason.POLICY_INVALID, "dependency policy maps must exactly cover required dependencies")
    route_maps = (
        policy.expected_route_source_asset,
        policy.expected_route_dependency,
        policy.expected_route_flow_ids,
        policy.expected_route_control_ids,
    )
    if any(set(mapping) != set(policy.required_route_ids) for mapping in route_maps):
        _reject(DependencyTrustRejectReason.POLICY_INVALID, "route policy maps must exactly cover required routes")


def _validate_upstream(
    policy: DependencyTrustPolicy,
    architecture: ArchitectureManifest,
    p7a: VerifiedAttackPathAssessment,
    p7b: VerifiedPrivilegeEscalationAssessment,
    p7c: VerifiedDataExfiltrationAssessment,
    p7d: VerifiedSecretExposureAssessment,
    posture: VerifiedSecurityPosture,
) -> tuple[str, dict[str, ControlStatus]]:
    architecture_sha = architecture_manifest_digest(architecture)
    if architecture_sha != policy.expected_architecture_sha256.casefold():
        _reject(DependencyTrustRejectReason.ARCHITECTURE_DIGEST_MISMATCH, "architecture digest does not match policy")
    if not p7a.exact_architecture_binding_verified:
        _reject(DependencyTrustRejectReason.P7A_ASSESSMENT_UNVERIFIED, "P7-A architecture binding is not verified")
    if p7a.architecture_sha256.casefold() != architecture_sha or p7a.assessment_evidence_sha256.casefold() != policy.expected_p7a_assessment_evidence_sha256.casefold():
        _reject(DependencyTrustRejectReason.P7A_ASSESSMENT_MISMATCH, "P7-A assessment identity does not match policy")
    if not p7b.exact_architecture_binding_verified or not p7b.exact_p7a_assessment_binding_verified:
        _reject(DependencyTrustRejectReason.P7B_ASSESSMENT_UNVERIFIED, "P7-B upstream bindings are not verified")
    if p7b.architecture_sha256.casefold() != architecture_sha or p7b.assessment_evidence_sha256.casefold() != policy.expected_p7b_assessment_evidence_sha256.casefold():
        _reject(DependencyTrustRejectReason.P7B_ASSESSMENT_MISMATCH, "P7-B assessment identity does not match policy")
    if not p7c.exact_architecture_binding_verified or not p7c.exact_p7a_assessment_binding_verified or not p7c.exact_p7b_assessment_binding_verified:
        _reject(DependencyTrustRejectReason.P7C_ASSESSMENT_UNVERIFIED, "P7-C upstream bindings are not verified")
    if p7c.architecture_sha256.casefold() != architecture_sha or p7c.assessment_evidence_sha256.casefold() != policy.expected_p7c_assessment_evidence_sha256.casefold():
        _reject(DependencyTrustRejectReason.P7C_ASSESSMENT_MISMATCH, "P7-C assessment identity does not match policy")
    if not p7d.exact_architecture_binding_verified or not p7d.exact_p7a_assessment_binding_verified or not p7d.exact_p7b_assessment_binding_verified or not p7d.exact_p7c_assessment_binding_verified:
        _reject(DependencyTrustRejectReason.P7D_ASSESSMENT_UNVERIFIED, "P7-D upstream bindings are not verified")
    if p7d.architecture_sha256.casefold() != architecture_sha or p7d.assessment_evidence_sha256.casefold() != policy.expected_p7d_assessment_evidence_sha256.casefold():
        _reject(DependencyTrustRejectReason.P7D_ASSESSMENT_MISMATCH, "P7-D assessment identity does not match policy")
    if not posture.exact_release_identity_verified or not posture.exact_upstream_evidence_binding_verified or not posture.control_catalog_verified or not posture.status_derived_from_evidence:
        _reject(DependencyTrustRejectReason.POSTURE_UNVERIFIED, "P6-D posture evidence is not fully verified")
    if posture.posture_evidence_sha256.casefold() != policy.expected_posture_evidence_sha256.casefold():
        _reject(DependencyTrustRejectReason.POSTURE_DIGEST_MISMATCH, "P6-D posture digest does not match policy")
    if posture.control_catalog_sha256.casefold() != policy.expected_control_catalog_sha256.casefold():
        _reject(DependencyTrustRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog does not match policy")
    statuses: dict[str, ControlStatus] = {}
    for assessment in posture.assessments:
        if assessment.control_id in statuses or not isinstance(assessment.status, ControlStatus):
            _reject(DependencyTrustRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control evidence is duplicate or malformed", control_id=assessment.control_id)
        statuses[assessment.control_id] = assessment.status
    if set(posture.satisfied_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.SATISFIED}:
        _reject(DependencyTrustRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D satisfied-control summary is inconsistent")
    if set(posture.exceptioned_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.EXCEPTIONED}:
        _reject(DependencyTrustRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D exception summary is inconsistent")
    if set(posture.not_evaluated_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.NOT_EVALUATED}:
        _reject(DependencyTrustRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D not-evaluated summary is inconsistent")
    return architecture_sha, statuses


def _validate_manifest(
    policy: DependencyTrustPolicy,
    request: DependencyTrustRequest,
    manifest: DependencyTrustManifest,
    architecture: ArchitectureManifest,
    statuses: Mapping[str, ControlStatus],
) -> tuple[dict[str, ExternalDependency], dict[str, ServiceEgressRoute], str]:
    if manifest.schema_version != P7E_DEPENDENCY_MANIFEST_SCHEMA_VERSION or not manifest.dependency_graph_id or not manifest.version:
        _reject(DependencyTrustRejectReason.MANIFEST_INVALID, "dependency trust manifest metadata is invalid")
    actual_sha = dependency_trust_manifest_digest(manifest)
    if not hmac.compare_digest(actual_sha, policy.expected_dependency_graph_sha256.casefold()) or not hmac.compare_digest(actual_sha, request.dependency_graph_sha256.casefold()):
        _reject(DependencyTrustRejectReason.MANIFEST_DIGEST_MISMATCH, "dependency graph digest does not match request/policy")
    if manifest.dependency_graph_id != policy.expected_dependency_graph_id or manifest.version != policy.expected_dependency_graph_version:
        _reject(DependencyTrustRejectReason.MANIFEST_INVALID, "dependency graph identity/version does not match policy")
    if manifest.architecture_sha256.casefold() != policy.expected_architecture_sha256.casefold():
        _reject(DependencyTrustRejectReason.ARCHITECTURE_DIGEST_MISMATCH, "manifest architecture binding does not match policy")
    age = request.evaluated_at_epoch - manifest.created_at_epoch
    if age > policy.max_manifest_age_seconds:
        _reject(DependencyTrustRejectReason.MANIFEST_STALE, "dependency manifest is stale")
    if age < -policy.max_future_skew_seconds:
        _reject(DependencyTrustRejectReason.MANIFEST_FUTURE, "dependency manifest timestamp is too far in the future")

    deps: dict[str, ExternalDependency] = {}
    for item in manifest.dependencies:
        if item.dependency_id in deps:
            _reject(DependencyTrustRejectReason.DEPENDENCY_DUPLICATE, "duplicate dependency ID", dependency_id=item.dependency_id)
        deps[item.dependency_id] = item
    if set(deps) != set(policy.required_dependency_ids):
        _reject(DependencyTrustRejectReason.DEPENDENCY_COVERAGE_MISMATCH, "dependency coverage differs from policy")
    for dependency_id, item in deps.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(DependencyTrustRejectReason.DEPENDENCY_OWNER_UNTRUSTED, "dependency owner is untrusted", dependency_id=dependency_id)
        if item.provider_id not in policy.trusted_provider_ids:
            _reject(DependencyTrustRejectReason.PROVIDER_UNTRUSTED, "dependency provider is untrusted", dependency_id=dependency_id)
        if item.dependency_type != policy.expected_dependency_type[dependency_id]:
            _reject(DependencyTrustRejectReason.DEPENDENCY_TYPE_DRIFT, "dependency type changed", dependency_id=dependency_id)
        if _criticality_rank(item.criticality) < _criticality_rank(policy.minimum_criticality[dependency_id]):
            _reject(DependencyTrustRejectReason.CRITICALITY_DOWNGRADE, "dependency criticality was downgraded", dependency_id=dependency_id)
        if item.endpoint_host.casefold() != policy.expected_endpoint_host[dependency_id].casefold():
            _reject(DependencyTrustRejectReason.ENDPOINT_DRIFT, "dependency endpoint host changed", dependency_id=dependency_id)
        if item.endpoint_port != policy.expected_endpoint_port[dependency_id]:
            _reject(DependencyTrustRejectReason.PORT_DRIFT, "dependency endpoint port changed", dependency_id=dependency_id)
        if item.transport_mode != policy.expected_transport_mode[dependency_id]:
            _reject(DependencyTrustRejectReason.TRANSPORT_DRIFT, "dependency transport mode changed", dependency_id=dependency_id)
        if item.authentication_mode != policy.expected_authentication_mode[dependency_id]:
            _reject(DependencyTrustRejectReason.AUTHENTICATION_DRIFT, "dependency authentication mode changed", dependency_id=dependency_id)
        if item.expected_server_identity.casefold() != policy.expected_server_identity[dependency_id].casefold():
            _reject(DependencyTrustRejectReason.SERVER_IDENTITY_DRIFT, "dependency server identity changed", dependency_id=dependency_id)
        if not set(item.egress_data_classes).issubset(policy.allowed_egress_data_classes[dependency_id]):
            _reject(DependencyTrustRejectReason.DATA_CLASS_SCOPE_MISMATCH, "dependency data class scope exceeds policy", dependency_id=dependency_id)
        if not set(item.exposed_secret_ids).issubset(policy.allowed_exposed_secret_ids[dependency_id]):
            _reject(DependencyTrustRejectReason.SECRET_SCOPE_MISMATCH, "dependency secret scope exceeds policy", dependency_id=dependency_id)
        if set(item.required_control_ids) != set(policy.expected_dependency_control_ids[dependency_id]):
            _reject(DependencyTrustRejectReason.DEPENDENCY_CONTROL_DRIFT, "dependency controls differ from policy", dependency_id=dependency_id)
        for control_id in item.required_control_ids:
            if control_id not in statuses:
                _reject(DependencyTrustRejectReason.DEPENDENCY_CONTROL_UNKNOWN, "dependency references unknown control", dependency_id=dependency_id, control_id=control_id)
        if item.fail_closed != policy.expected_fail_closed[dependency_id]:
            _reject(DependencyTrustRejectReason.FAIL_CLOSED_DRIFT, "dependency fail-closed setting differs from policy", dependency_id=dependency_id)

    routes: dict[str, ServiceEgressRoute] = {}
    for item in manifest.routes:
        if item.route_id in routes:
            _reject(DependencyTrustRejectReason.ROUTE_DUPLICATE, "duplicate route ID", route_id=item.route_id)
        routes[item.route_id] = item
    if set(routes) != set(policy.required_route_ids):
        _reject(DependencyTrustRejectReason.ROUTE_COVERAGE_MISMATCH, "route coverage differs from policy")

    assets = {item.asset_id: item for item in architecture.assets}
    flows = {item.flow_id: item for item in architecture.flows}
    for route_id, item in routes.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(DependencyTrustRejectReason.ROUTE_OWNER_UNTRUSTED, "route owner is untrusted", route_id=route_id)
        if item.source_asset_id not in assets or item.dependency_id not in deps:
            _reject(DependencyTrustRejectReason.ROUTE_REFERENCE_INVALID, "route references unknown source/dependency", route_id=route_id)
        if item.source_asset_id != policy.expected_route_source_asset[route_id]:
            _reject(DependencyTrustRejectReason.ROUTE_SOURCE_DRIFT, "route source asset changed", route_id=route_id)
        if item.dependency_id != policy.expected_route_dependency[route_id]:
            _reject(DependencyTrustRejectReason.ROUTE_DEPENDENCY_DRIFT, "route dependency changed", route_id=route_id)
        if tuple(item.via_flow_ids) != tuple(policy.expected_route_flow_ids[route_id]):
            _reject(DependencyTrustRejectReason.ROUTE_FLOW_DRIFT, "route architecture flow binding changed", route_id=route_id)
        if set(item.required_control_ids) != set(policy.expected_route_control_ids[route_id]):
            _reject(DependencyTrustRejectReason.ROUTE_CONTROL_DRIFT, "route controls differ from policy", route_id=route_id)
        for control_id in item.required_control_ids:
            if control_id not in statuses:
                _reject(DependencyTrustRejectReason.ROUTE_CONTROL_UNKNOWN, "route references unknown control", route_id=route_id, control_id=control_id)
        if not item.via_flow_ids:
            _reject(DependencyTrustRejectReason.ROUTE_ARCHITECTURE_INVALID, "route must bind at least one architecture flow", route_id=route_id)
        prior_target: str | None = None
        for flow_id in item.via_flow_ids:
            flow = flows.get(flow_id)
            if flow is None:
                _reject(DependencyTrustRejectReason.ROUTE_ARCHITECTURE_INVALID, "route references unknown architecture flow", route_id=route_id)
            if prior_target is not None and flow.source_asset_id != prior_target:
                _reject(DependencyTrustRejectReason.ROUTE_ARCHITECTURE_INVALID, "route architecture flows are not contiguous", route_id=route_id)
            prior_target = flow.target_asset_id
        if prior_target != item.source_asset_id:
            _reject(DependencyTrustRejectReason.ROUTE_ARCHITECTURE_INVALID, "route architecture flows must terminate at egress source asset", route_id=route_id)
    return deps, routes, actual_sha


def _risk_score(dependency: ExternalDependency, exceptioned: tuple[str, ...], not_evaluated: tuple[str, ...]) -> int:
    score = _criticality_rank(dependency.criticality) * 20
    if dependency.exposed_secret_ids:
        score += 24
    max_data = max((_data_rank(value) for value in dependency.egress_data_classes), default=1)
    score += max(0, max_data - 2) * 8
    score += len(exceptioned) * 14 + len(not_evaluated) * 12
    if dependency.transport_mode == TransportMode.PLAINTEXT:
        score += 30
    if dependency.authentication_mode == AuthenticationMode.NONE:
        score += 24
    if not dependency.fail_closed:
        score += 18
    return score


class ExternalDependencyTrustAnalyzer:
    def __init__(self, policy: DependencyTrustPolicy) -> None:
        _validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: DependencyTrustRequest,
        manifest: DependencyTrustManifest,
        architecture: ArchitectureManifest,
        p7a_assessment: VerifiedAttackPathAssessment,
        p7b_assessment: VerifiedPrivilegeEscalationAssessment,
        p7c_assessment: VerifiedDataExfiltrationAssessment,
        p7d_assessment: VerifiedSecretExposureAssessment,
        posture: VerifiedSecurityPosture,
    ) -> VerifiedDependencyTrustAssessment:
        if (
            request.dependency_graph_id != self.policy.expected_dependency_graph_id
            or request.dependency_graph_version != self.policy.expected_dependency_graph_version
            or request.architecture_sha256.casefold() != self.policy.expected_architecture_sha256.casefold()
            or request.p7a_assessment_evidence_sha256.casefold() != self.policy.expected_p7a_assessment_evidence_sha256.casefold()
            or request.p7b_assessment_evidence_sha256.casefold() != self.policy.expected_p7b_assessment_evidence_sha256.casefold()
            or request.p7c_assessment_evidence_sha256.casefold() != self.policy.expected_p7c_assessment_evidence_sha256.casefold()
            or request.p7d_assessment_evidence_sha256.casefold() != self.policy.expected_p7d_assessment_evidence_sha256.casefold()
            or request.posture_evidence_sha256.casefold() != self.policy.expected_posture_evidence_sha256.casefold()
            or not _is_sha256(request.dependency_graph_sha256)
        ):
            _reject(DependencyTrustRejectReason.REQUEST_INVALID, "dependency trust request identity/evidence binding is invalid")
        if set(request.entry_source_asset_ids) != set(self.policy.entry_source_asset_ids):
            _reject(DependencyTrustRejectReason.ENTRY_SOURCE_SCOPE_MISMATCH, "request entry-source scope differs from policy")
        if set(request.target_dependency_ids) != set(self.policy.target_dependency_ids):
            _reject(DependencyTrustRejectReason.TARGET_DEPENDENCY_SCOPE_MISMATCH, "request target-dependency scope differs from policy")

        architecture_sha, statuses = _validate_upstream(
            self.policy,
            architecture,
            p7a_assessment,
            p7b_assessment,
            p7c_assessment,
            p7d_assessment,
            posture,
        )
        dependencies, routes, manifest_sha = _validate_manifest(
            self.policy,
            request,
            manifest,
            architecture,
            statuses,
        )

        paths: list[ThirdPartyTrustPathFact] = []
        for route in sorted(routes.values(), key=lambda item: item.route_id):
            if route.source_asset_id not in self.policy.entry_source_asset_ids or route.dependency_id not in self.policy.target_dependency_ids:
                continue
            dependency = dependencies[route.dependency_id]
            required_controls = tuple(sorted(set(route.required_control_ids) | set(dependency.required_control_ids)))
            satisfied = tuple(control_id for control_id in required_controls if statuses[control_id] == ControlStatus.SATISFIED)
            exceptioned = tuple(control_id for control_id in required_controls if statuses[control_id] == ControlStatus.EXCEPTIONED)
            not_evaluated = tuple(control_id for control_id in required_controls if statuses[control_id] == ControlStatus.NOT_EVALUATED)
            reasons: list[str] = []
            if exceptioned:
                reasons.append("exceptioned_egress_control")
            if not_evaluated:
                reasons.append("not_evaluated_egress_control")
            if dependency.transport_mode == TransportMode.PLAINTEXT:
                reasons.append("plaintext_transport")
            if dependency.authentication_mode == AuthenticationMode.NONE:
                reasons.append("unauthenticated_dependency")
            if not dependency.expected_server_identity:
                reasons.append("missing_destination_identity")
            if dependency.criticality == DependencyCriticality.CRITICAL and not dependency.fail_closed:
                reasons.append("critical_dependency_fail_open")
            exposed = bool(reasons)
            score = _risk_score(dependency, exceptioned, not_evaluated) if exposed else 0
            paths.append(
                ThirdPartyTrustPathFact(
                    path_id=dependency_trust_path_identifier(route, dependency),
                    route_id=route.route_id,
                    source_asset_id=route.source_asset_id,
                    dependency_id=dependency.dependency_id,
                    provider_id=dependency.provider_id,
                    dependency_type=dependency.dependency_type,
                    criticality=dependency.criticality,
                    endpoint_host=dependency.endpoint_host,
                    endpoint_port=dependency.endpoint_port,
                    transport_mode=dependency.transport_mode,
                    authentication_mode=dependency.authentication_mode,
                    server_identity=dependency.expected_server_identity,
                    egress_data_classes=tuple(sorted(value.value for value in dependency.egress_data_classes)),
                    exposed_secret_ids=tuple(sorted(dependency.exposed_secret_ids)),
                    architecture_flow_ids=tuple(route.via_flow_ids),
                    satisfied_control_ids=satisfied,
                    exceptioned_control_ids=exceptioned,
                    not_evaluated_control_ids=not_evaluated,
                    fail_closed=dependency.fail_closed,
                    exposed=exposed,
                    risk_score=score,
                    exposure_reasons=tuple(reasons),
                    mitigating_control_ids=satisfied,
                )
            )

        exposed_paths = [item for item in paths if item.exposed]
        controlled_paths = [item for item in paths if not item.exposed]
        prioritized = tuple(item.path_id for item in sorted(exposed_paths, key=lambda value: (-value.risk_score, value.path_id)))
        max_score = max((item.risk_score for item in exposed_paths), default=0)
        if set(request.declared_exposed_path_ids) != set(prioritized):
            _reject(DependencyTrustRejectReason.DECLARED_PATH_MISMATCH, "caller-declared exposed dependency paths differ from derived evidence")
        if request.declared_max_exposed_risk_score != max_score:
            _reject(DependencyTrustRejectReason.DECLARED_RISK_MISMATCH, "caller-declared dependency risk differs from derived evidence")

        evidence_document = {
            "architecture_sha256": architecture_sha,
            "control_catalog_sha256": posture.control_catalog_sha256.casefold(),
            "dependency_graph_sha256": manifest_sha,
            "entry_source_asset_ids": sorted(request.entry_source_asset_ids),
            "exposed_path_ids": list(prioritized),
            "max_exposed_risk_score": max_score,
            "p7a_assessment_evidence_sha256": p7a_assessment.assessment_evidence_sha256.casefold(),
            "p7b_assessment_evidence_sha256": p7b_assessment.assessment_evidence_sha256.casefold(),
            "p7c_assessment_evidence_sha256": p7c_assessment.assessment_evidence_sha256.casefold(),
            "p7d_assessment_evidence_sha256": p7d_assessment.assessment_evidence_sha256.casefold(),
            "path_facts": [asdict(item) for item in paths],
            "posture_evidence_sha256": posture.posture_evidence_sha256.casefold(),
            "target_dependency_ids": sorted(request.target_dependency_ids),
        }
        assessment_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        sensitive = {EgressDataClass.RESTRICTED.value, EgressDataClass.SECRET.value}
        return VerifiedDependencyTrustAssessment(
            dependency_graph_id=manifest.dependency_graph_id,
            dependency_graph_version=manifest.version,
            dependency_graph_sha256=manifest_sha,
            architecture_sha256=architecture_sha,
            p7a_assessment_evidence_sha256=p7a_assessment.assessment_evidence_sha256.casefold(),
            p7b_assessment_evidence_sha256=p7b_assessment.assessment_evidence_sha256.casefold(),
            p7c_assessment_evidence_sha256=p7c_assessment.assessment_evidence_sha256.casefold(),
            p7d_assessment_evidence_sha256=p7d_assessment.assessment_evidence_sha256.casefold(),
            posture_evidence_sha256=posture.posture_evidence_sha256.casefold(),
            control_catalog_sha256=posture.control_catalog_sha256.casefold(),
            entry_source_asset_ids=tuple(sorted(request.entry_source_asset_ids)),
            target_dependency_ids=tuple(sorted(request.target_dependency_ids)),
            topology_path_count=len(paths),
            exposed_path_count=len(exposed_paths),
            controlled_path_count=len(controlled_paths),
            critical_exposed_path_count=sum(item.criticality == DependencyCriticality.CRITICAL for item in exposed_paths),
            secret_bearing_exposed_path_count=sum(bool(item.exposed_secret_ids) for item in exposed_paths),
            restricted_or_secret_data_exposed_path_count=sum(bool(set(item.egress_data_classes) & sensitive) for item in exposed_paths),
            fail_open_exposed_path_count=sum(not item.fail_closed for item in exposed_paths),
            max_exposed_risk_score=max_score,
            prioritized_exposed_path_ids=prioritized,
            paths=tuple(paths),
            assessment_evidence_sha256=assessment_sha,
        )
