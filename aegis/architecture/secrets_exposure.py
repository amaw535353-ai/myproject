from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .attack_paths import ArchitectureManifest, VerifiedAttackPathAssessment, architecture_manifest_digest
from .data_types import VerifiedDataExfiltrationAssessment
from .privilege_types import VerifiedPrivilegeEscalationAssessment


P7D_SECRET_POLICY_VERSION = "secrets-credential-trust-root-exposure-v1"
P7D_SECRET_MANIFEST_SCHEMA_VERSION = "aegis-secret-exposure-manifest-v1"
P7D_ASSESSMENT_SCHEMA_VERSION = "aegis-secret-exposure-assessment-v1"
P7D_ASSESSMENT_MODE = "deterministic-evidence-bound-secret-blast-radius-analysis-v1"


class SecretKind(StrEnum):
    API_TOKEN = "api_token"
    SERVICE_CREDENTIAL = "service_credential"
    DATABASE_CREDENTIAL = "database_credential"
    MODEL_PUBLISHER_KEY = "model_publisher_key"
    RELEASE_SIGNING_KEY = "release_signing_key"
    TELEMETRY_CREDENTIAL = "telemetry_credential"
    BUILD_TOKEN = "build_token"
    ROOT_SIGNING_KEY = "root_signing_key"


class SecretSensitivity(StrEnum):
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecretScope(StrEnum):
    TENANT = "tenant"
    WORKLOAD = "workload"
    PLATFORM = "platform"
    MODEL_SUPPLY_CHAIN = "model_supply_chain"
    SECURITY = "security"
    GLOBAL_TRUST_ROOT = "global_trust_root"


class ExposureScope(StrEnum):
    TENANT = "tenant"
    WORKLOAD = "workload"
    PLATFORM = "platform"
    MODEL_SUPPLY_CHAIN = "model_supply_chain"
    SECURITY = "security"
    EXTERNAL = "external"


class ExposureSurfaceType(StrEnum):
    APPLICATION_CONFIG = "application_config"
    BUILD_RUNNER = "build_runner"
    RELEASE_ARTIFACT = "release_artifact"
    KEY_VAULT = "key_vault"
    TOOL_GATEWAY = "tool_gateway"
    MODEL_REGISTRY = "model_registry"
    MODEL_RUNTIME = "model_runtime"
    TELEMETRY_PIPELINE = "telemetry_pipeline"
    EXTERNAL_EGRESS = "external_egress"


class SecretTransferChannel(StrEnum):
    CONFIG_INJECTION = "config_injection"
    ENVIRONMENT_INJECTION = "environment_injection"
    FILE_MOUNT = "file_mount"
    BUILD_SECRET = "build_secret"
    ARTIFACT_EMBEDDING = "artifact_embedding"
    TOOL_CREDENTIAL_BROKER = "tool_credential_broker"
    MODEL_RELEASE_SIGNING = "model_release_signing"
    RUNTIME_CREDENTIAL_INJECTION = "runtime_credential_injection"
    TELEMETRY_EXPORT = "telemetry_export"
    LOGGING = "logging"


class SecretExposureRejectReason(StrEnum):
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
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    SURFACE_DUPLICATE = "surface_duplicate"
    SURFACE_COVERAGE_MISMATCH = "surface_coverage_mismatch"
    SURFACE_OWNER_UNTRUSTED = "surface_owner_untrusted"
    SURFACE_TYPE_DRIFT = "surface_type_drift"
    SURFACE_ZONE_DRIFT = "surface_zone_drift"
    SURFACE_SCOPE_DRIFT = "surface_scope_drift"
    SURFACE_ARCHITECTURE_DRIFT = "surface_architecture_drift"
    SECRET_DUPLICATE = "secret_duplicate"
    SECRET_COVERAGE_MISMATCH = "secret_coverage_mismatch"
    SECRET_OWNER_UNTRUSTED = "secret_owner_untrusted"
    SECRET_HOME_DRIFT = "secret_home_drift"
    SECRET_KIND_DRIFT = "secret_kind_drift"
    SECRET_SCOPE_DRIFT = "secret_scope_drift"
    SECRET_SENSITIVITY_DOWNGRADE = "secret_sensitivity_downgrade"
    SECRET_TRUST_ROOT_DRIFT = "secret_trust_root_drift"
    SECRET_ROTATION_INVALID = "secret_rotation_invalid"
    EDGE_DUPLICATE = "edge_duplicate"
    EDGE_COVERAGE_MISMATCH = "edge_coverage_mismatch"
    EDGE_OWNER_UNTRUSTED = "edge_owner_untrusted"
    EDGE_REFERENCE_INVALID = "edge_reference_invalid"
    EDGE_SELF_LOOP = "edge_self_loop"
    EDGE_SECRET_DRIFT = "edge_secret_drift"
    EDGE_ENDPOINT_DRIFT = "edge_endpoint_drift"
    EDGE_CHANNEL_DRIFT = "edge_channel_drift"
    EDGE_FLOW_DRIFT = "edge_flow_drift"
    EDGE_CONTROL_DRIFT = "edge_control_drift"
    EDGE_CONTROL_UNKNOWN = "edge_control_unknown"
    EDGE_ARCHITECTURE_ROUTE_INVALID = "edge_architecture_route_invalid"
    ENTRY_SECRET_SCOPE_MISMATCH = "entry_secret_scope_mismatch"
    TARGET_SURFACE_SCOPE_MISMATCH = "target_surface_scope_mismatch"
    PATH_LIMIT_EXCEEDED = "path_limit_exceeded"
    DECLARED_PATH_MISMATCH = "declared_path_mismatch"
    DECLARED_BLAST_RADIUS_MISMATCH = "declared_blast_radius_mismatch"


class SecretExposureRejected(ValueError):
    def __init__(
        self,
        reason: SecretExposureRejectReason,
        message: str,
        *,
        surface_id: str | None = None,
        secret_id: str | None = None,
        edge_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.surface_id = surface_id
        self.secret_id = secret_id
        self.edge_id = edge_id
        self.control_id = control_id


@dataclass(frozen=True)
class ExposureSurface:
    surface_id: str
    surface_type: ExposureSurfaceType
    exposure_scope: ExposureScope
    trust_zone: str
    owner_id: str
    architecture_asset_id: str | None
    external_egress: bool
    description: str


@dataclass(frozen=True)
class SecretMaterial:
    secret_id: str
    kind: SecretKind
    sensitivity: SecretSensitivity
    authority_scope: SecretScope
    owner_id: str
    home_surface_id: str
    rotated_at_epoch: int
    expires_at_epoch: int
    trust_root: bool
    description: str


@dataclass(frozen=True)
class SecretTransferEdge:
    edge_id: str
    secret_id: str
    source_surface_id: str
    target_surface_id: str
    channel: SecretTransferChannel
    owner_id: str
    via_flow_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    plaintext_exposure: bool
    persistent_copy: bool
    purpose: str


@dataclass(frozen=True)
class SecretExposureManifest:
    secret_graph_id: str
    version: str
    architecture_sha256: str
    created_at_epoch: int
    surfaces: tuple[ExposureSurface, ...]
    secrets: tuple[SecretMaterial, ...]
    edges: tuple[SecretTransferEdge, ...]
    schema_version: str = P7D_SECRET_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class SecretExposureRequest:
    secret_graph_id: str
    secret_graph_version: str
    secret_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    entry_secret_ids: tuple[str, ...]
    target_surface_ids: tuple[str, ...]
    evaluated_at_epoch: int
    declared_exposed_path_ids: tuple[str, ...]
    declared_max_blast_radius_score: int


@dataclass(frozen=True)
class SecretExposurePolicy:
    expected_secret_graph_id: str
    expected_secret_graph_version: str
    expected_secret_graph_sha256: str
    expected_architecture_sha256: str
    expected_p7a_assessment_evidence_sha256: str
    expected_p7b_assessment_evidence_sha256: str
    expected_p7c_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_surface_ids: frozenset[str]
    required_secret_ids: frozenset[str]
    required_edge_ids: frozenset[str]
    entry_secret_ids: frozenset[str]
    target_surface_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_surface_type: Mapping[str, ExposureSurfaceType]
    expected_surface_scope: Mapping[str, ExposureScope]
    expected_surface_zone: Mapping[str, str]
    expected_architecture_asset_by_surface: Mapping[str, str | None]
    expected_kind_by_secret: Mapping[str, SecretKind]
    expected_scope_by_secret: Mapping[str, SecretScope]
    expected_home_surface_by_secret: Mapping[str, str]
    minimum_sensitivity_by_secret: Mapping[str, SecretSensitivity]
    expected_trust_root_by_secret: Mapping[str, bool]
    max_rotation_age_seconds_by_secret: Mapping[str, int]
    allowed_target_surfaces_by_secret: Mapping[str, frozenset[str]]
    allowed_surface_scopes_by_secret: Mapping[str, frozenset[ExposureScope]]
    forbid_plaintext_by_secret: Mapping[str, bool]
    forbid_persistent_copy_by_secret: Mapping[str, bool]
    expected_secret_id_by_edge: Mapping[str, str]
    expected_endpoints_by_edge: Mapping[str, tuple[str, str]]
    expected_channel_by_edge: Mapping[str, SecretTransferChannel]
    expected_flow_ids_by_edge: Mapping[str, tuple[str, ...]]
    expected_control_ids_by_edge: Mapping[str, frozenset[str]]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30
    max_path_hops: int = 10
    max_paths: int = 128


@dataclass(frozen=True)
class SecretExposurePathFact:
    path_id: str
    secret_id: str
    secret_kind: SecretKind
    secret_sensitivity: SecretSensitivity
    authority_scope: SecretScope
    trust_root: bool
    surface_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    architecture_flow_ids: tuple[str, ...]
    channel_sequence: tuple[str, ...]
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    unauthorized_surface_ids: tuple[str, ...]
    scope_violation_surface_ids: tuple[str, ...]
    plaintext_edge_ids: tuple[str, ...]
    persistent_copy_edge_ids: tuple[str, ...]
    rotation_overdue: bool
    expired: bool
    external_egress: bool
    exposed: bool
    blast_radius_score: int
    exposure_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedSecretExposureAssessment:
    secret_graph_id: str
    secret_graph_version: str
    secret_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    entry_secret_ids: tuple[str, ...]
    target_surface_ids: tuple[str, ...]
    topology_path_count: int
    exposed_path_count: int
    controlled_path_count: int
    critical_exposed_path_count: int
    trust_root_exposed_path_count: int
    external_egress_exposed_path_count: int
    max_blast_radius_score: int
    prioritized_exposed_path_ids: tuple[str, ...]
    paths: tuple[SecretExposurePathFact, ...]
    assessment_evidence_sha256: str
    exact_secret_graph_binding_verified: bool = True
    exact_architecture_binding_verified: bool = True
    exact_p7a_assessment_binding_verified: bool = True
    exact_p7b_assessment_binding_verified: bool = True
    exact_p7c_assessment_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    secret_identity_policy_pinned: bool = True
    rotation_policy_pinned: bool = True
    trust_root_policy_pinned: bool = True
    transfer_routes_policy_pinned: bool = True
    blast_radius_derived_from_evidence: bool = True
    mitigating_controls_visible: bool = True
    caller_summary_trusted: bool = False
    production_secret_discovery: bool = False
    real_credential_use: bool = False
    production_key_rotation: bool = False
    production_vault_integration: bool = False
    live_secret_exfiltration_testing: bool = False
    formal_blast_radius_proof: bool = False
    network_operations: int = 0
    schema_version: str = P7D_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7D_SECRET_POLICY_VERSION
    assessment_mode: str = P7D_ASSESSMENT_MODE


def _reject(reason: SecretExposureRejectReason, message: str, **context: str | None) -> None:
    raise SecretExposureRejected(reason, message, **context)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _sensitivity_rank(value: SecretSensitivity) -> int:
    return {SecretSensitivity.MEDIUM: 1, SecretSensitivity.HIGH: 2, SecretSensitivity.CRITICAL: 3}[value]


def _scope_rank(value: SecretScope) -> int:
    return {
        SecretScope.TENANT: 1,
        SecretScope.WORKLOAD: 2,
        SecretScope.PLATFORM: 3,
        SecretScope.MODEL_SUPPLY_CHAIN: 3,
        SecretScope.SECURITY: 4,
        SecretScope.GLOBAL_TRUST_ROOT: 5,
    }[value]


def canonical_secret_exposure_manifest_bytes(manifest: SecretExposureManifest) -> bytes:
    document = {
        "architecture_sha256": manifest.architecture_sha256.casefold(),
        "created_at_epoch": manifest.created_at_epoch,
        "edges": [
            {
                "channel": edge.channel.value,
                "edge_id": edge.edge_id,
                "owner_id": edge.owner_id,
                "persistent_copy": edge.persistent_copy,
                "plaintext_exposure": edge.plaintext_exposure,
                "purpose": edge.purpose,
                "required_control_ids": sorted(edge.required_control_ids),
                "secret_id": edge.secret_id,
                "source_surface_id": edge.source_surface_id,
                "target_surface_id": edge.target_surface_id,
                "via_flow_ids": list(edge.via_flow_ids),
            }
            for edge in sorted(manifest.edges, key=lambda item: item.edge_id)
        ],
        "schema_version": manifest.schema_version,
        "secret_graph_id": manifest.secret_graph_id,
        "secrets": [
            {
                "authority_scope": secret.authority_scope.value,
                "description": secret.description,
                "expires_at_epoch": secret.expires_at_epoch,
                "home_surface_id": secret.home_surface_id,
                "kind": secret.kind.value,
                "owner_id": secret.owner_id,
                "rotated_at_epoch": secret.rotated_at_epoch,
                "secret_id": secret.secret_id,
                "sensitivity": secret.sensitivity.value,
                "trust_root": secret.trust_root,
            }
            for secret in sorted(manifest.secrets, key=lambda item: item.secret_id)
        ],
        "surfaces": [
            {
                "architecture_asset_id": surface.architecture_asset_id,
                "description": surface.description,
                "exposure_scope": surface.exposure_scope.value,
                "external_egress": surface.external_egress,
                "owner_id": surface.owner_id,
                "surface_id": surface.surface_id,
                "surface_type": surface.surface_type.value,
                "trust_zone": surface.trust_zone,
            }
            for surface in sorted(manifest.surfaces, key=lambda item: item.surface_id)
        ],
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def secret_exposure_manifest_digest(manifest: SecretExposureManifest) -> str:
    return hashlib.sha256(canonical_secret_exposure_manifest_bytes(manifest)).hexdigest()


def secret_exposure_path_identifier(secret_id: str, surface_ids: tuple[str, ...], edge_ids: tuple[str, ...]) -> str:
    payload = json.dumps(
        {"edge_ids": list(edge_ids), "secret_id": secret_id, "surface_ids": list(surface_ids)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"secret-path-{hashlib.sha256(payload).hexdigest()[:20]}"


def _require_exact_keys(mapping: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    if set(mapping) != expected:
        _reject(SecretExposureRejectReason.POLICY_INVALID, f"policy {label} keys must exactly match required inventory")


def _validate_policy(policy: SecretExposurePolicy) -> None:
    if not policy.expected_secret_graph_id or not policy.expected_secret_graph_version:
        _reject(SecretExposureRejectReason.POLICY_INVALID, "secret exposure policy identity is incomplete")
    for digest in (
        policy.expected_secret_graph_sha256,
        policy.expected_architecture_sha256,
        policy.expected_p7a_assessment_evidence_sha256,
        policy.expected_p7b_assessment_evidence_sha256,
        policy.expected_p7c_assessment_evidence_sha256,
        policy.expected_posture_evidence_sha256,
        policy.expected_control_catalog_sha256,
    ):
        if not _is_sha256(digest):
            _reject(SecretExposureRejectReason.POLICY_INVALID, "policy contains an invalid SHA-256 pin")
    if not policy.entry_secret_ids or not policy.target_surface_ids:
        _reject(SecretExposureRejectReason.POLICY_INVALID, "entry-secret and target-surface scopes must be non-empty")
    if not policy.entry_secret_ids <= policy.required_secret_ids:
        _reject(SecretExposureRejectReason.POLICY_INVALID, "entry secret scope is outside required secret inventory")
    if not policy.target_surface_ids <= policy.required_surface_ids:
        _reject(SecretExposureRejectReason.POLICY_INVALID, "target surface scope is outside required surface inventory")
    for mapping, expected, label in (
        (policy.expected_surface_type, policy.required_surface_ids, "surface-type"),
        (policy.expected_surface_scope, policy.required_surface_ids, "surface-scope"),
        (policy.expected_surface_zone, policy.required_surface_ids, "surface-zone"),
        (policy.expected_architecture_asset_by_surface, policy.required_surface_ids, "surface-architecture"),
        (policy.expected_kind_by_secret, policy.required_secret_ids, "secret-kind"),
        (policy.expected_scope_by_secret, policy.required_secret_ids, "secret-scope"),
        (policy.expected_home_surface_by_secret, policy.required_secret_ids, "secret-home"),
        (policy.minimum_sensitivity_by_secret, policy.required_secret_ids, "secret-sensitivity"),
        (policy.expected_trust_root_by_secret, policy.required_secret_ids, "secret-trust-root"),
        (policy.max_rotation_age_seconds_by_secret, policy.required_secret_ids, "secret-rotation-age"),
        (policy.allowed_target_surfaces_by_secret, policy.required_secret_ids, "secret-target-surfaces"),
        (policy.allowed_surface_scopes_by_secret, policy.required_secret_ids, "secret-surface-scopes"),
        (policy.forbid_plaintext_by_secret, policy.required_secret_ids, "secret-plaintext-policy"),
        (policy.forbid_persistent_copy_by_secret, policy.required_secret_ids, "secret-persistence-policy"),
        (policy.expected_secret_id_by_edge, policy.required_edge_ids, "edge-secret"),
        (policy.expected_endpoints_by_edge, policy.required_edge_ids, "edge-endpoints"),
        (policy.expected_channel_by_edge, policy.required_edge_ids, "edge-channel"),
        (policy.expected_flow_ids_by_edge, policy.required_edge_ids, "edge-flows"),
        (policy.expected_control_ids_by_edge, policy.required_edge_ids, "edge-controls"),
    ):
        _require_exact_keys(mapping, expected, label)
    if any(value <= 0 for value in policy.max_rotation_age_seconds_by_secret.values()):
        _reject(SecretExposureRejectReason.POLICY_INVALID, "rotation age bounds must be positive")
    if any(not value for value in policy.allowed_target_surfaces_by_secret.values()):
        _reject(SecretExposureRejectReason.POLICY_INVALID, "every secret needs at least one authorized surface")
    if any(not value for value in policy.allowed_surface_scopes_by_secret.values()):
        _reject(SecretExposureRejectReason.POLICY_INVALID, "every secret needs at least one authorized exposure scope")
    if policy.max_manifest_age_seconds <= 0 or policy.max_future_skew_seconds < 0 or policy.max_path_hops <= 0 or policy.max_paths <= 0:
        _reject(SecretExposureRejectReason.POLICY_INVALID, "policy freshness/path bounds are invalid")


def _validate_request(request: SecretExposureRequest, policy: SecretExposurePolicy) -> None:
    if request.secret_graph_id != policy.expected_secret_graph_id or request.secret_graph_version != policy.expected_secret_graph_version:
        _reject(SecretExposureRejectReason.REQUEST_INVALID, "request secret graph identity differs from policy")
    for actual, expected in (
        (request.secret_graph_sha256, policy.expected_secret_graph_sha256),
        (request.architecture_sha256, policy.expected_architecture_sha256),
        (request.p7a_assessment_evidence_sha256, policy.expected_p7a_assessment_evidence_sha256),
        (request.p7b_assessment_evidence_sha256, policy.expected_p7b_assessment_evidence_sha256),
        (request.p7c_assessment_evidence_sha256, policy.expected_p7c_assessment_evidence_sha256),
        (request.posture_evidence_sha256, policy.expected_posture_evidence_sha256),
    ):
        if not _is_sha256(actual) or actual.casefold() != expected.casefold():
            _reject(SecretExposureRejectReason.REQUEST_INVALID, "request digest binding differs from policy")
    if set(request.entry_secret_ids) != policy.entry_secret_ids:
        _reject(SecretExposureRejectReason.ENTRY_SECRET_SCOPE_MISMATCH, "request entry secrets differ from policy")
    if set(request.target_surface_ids) != policy.target_surface_ids:
        _reject(SecretExposureRejectReason.TARGET_SURFACE_SCOPE_MISMATCH, "request target surfaces differ from policy")
    if len(set(request.entry_secret_ids)) != len(request.entry_secret_ids) or len(set(request.target_surface_ids)) != len(request.target_surface_ids):
        _reject(SecretExposureRejectReason.REQUEST_INVALID, "request contains duplicate entry or target identifiers")
    if request.evaluated_at_epoch <= 0 or request.declared_max_blast_radius_score < 0:
        _reject(SecretExposureRejectReason.REQUEST_INVALID, "request time or declared blast radius is invalid")


def _validate_upstream(
    request: SecretExposureRequest,
    policy: SecretExposurePolicy,
    architecture: ArchitectureManifest,
    p7a: VerifiedAttackPathAssessment,
    p7b: VerifiedPrivilegeEscalationAssessment,
    p7c: VerifiedDataExfiltrationAssessment,
    posture: VerifiedSecurityPosture,
) -> tuple[dict[str, object], dict[str, object], dict[str, ControlStatus], str]:
    architecture_sha = architecture_manifest_digest(architecture)
    if architecture_sha.casefold() != policy.expected_architecture_sha256.casefold() or request.architecture_sha256.casefold() != architecture_sha.casefold():
        _reject(SecretExposureRejectReason.ARCHITECTURE_DIGEST_MISMATCH, "architecture digest differs from request/policy")
    assets = {item.asset_id: item for item in architecture.assets}
    flows = {item.flow_id: item for item in architecture.flows}
    if len(assets) != len(architecture.assets) or len(flows) != len(architecture.flows):
        _reject(SecretExposureRejectReason.ARCHITECTURE_INVALID, "architecture contains duplicate assets or flows")

    if not (p7a.exact_architecture_binding_verified and p7a.required_graph_coverage_verified and p7a.missing_and_exceptioned_controls_visible):
        _reject(SecretExposureRejectReason.P7A_ASSESSMENT_UNVERIFIED, "P7-A evidence is not verified")
    if p7a.architecture_sha256.casefold() != architecture_sha.casefold() or p7a.assessment_evidence_sha256.casefold() != request.p7a_assessment_evidence_sha256.casefold():
        _reject(SecretExposureRejectReason.P7A_ASSESSMENT_MISMATCH, "P7-A evidence binding differs")

    if not (p7b.exact_identity_graph_binding_verified and p7b.exact_architecture_binding_verified and p7b.mitigating_controls_visible):
        _reject(SecretExposureRejectReason.P7B_ASSESSMENT_UNVERIFIED, "P7-B evidence is not verified")
    if p7b.architecture_sha256.casefold() != architecture_sha.casefold() or p7b.assessment_evidence_sha256.casefold() != request.p7b_assessment_evidence_sha256.casefold():
        _reject(SecretExposureRejectReason.P7B_ASSESSMENT_MISMATCH, "P7-B evidence binding differs")

    if not (p7c.exact_data_graph_binding_verified and p7c.exact_architecture_binding_verified and p7c.mitigating_controls_visible):
        _reject(SecretExposureRejectReason.P7C_ASSESSMENT_UNVERIFIED, "P7-C evidence is not verified")
    if p7c.architecture_sha256.casefold() != architecture_sha.casefold() or p7c.assessment_evidence_sha256.casefold() != request.p7c_assessment_evidence_sha256.casefold():
        _reject(SecretExposureRejectReason.P7C_ASSESSMENT_MISMATCH, "P7-C evidence binding differs")

    if not (
        posture.exact_release_identity_verified
        and posture.exact_upstream_evidence_binding_verified
        and posture.control_catalog_verified
        and posture.status_derived_from_evidence
        and posture.missing_evidence_visible
    ):
        _reject(SecretExposureRejectReason.POSTURE_UNVERIFIED, "P6-D posture is not verified")
    if posture.posture_evidence_sha256.casefold() != request.posture_evidence_sha256.casefold():
        _reject(SecretExposureRejectReason.POSTURE_DIGEST_MISMATCH, "posture digest differs")
    if posture.control_catalog_sha256.casefold() != policy.expected_control_catalog_sha256.casefold():
        _reject(SecretExposureRejectReason.CONTROL_CATALOG_MISMATCH, "control catalog digest differs")

    controls: dict[str, ControlStatus] = {}
    for assessment in posture.assessments:
        if assessment.control_id in controls:
            _reject(SecretExposureRejectReason.CONTROL_EVIDENCE_INVALID, "duplicate posture control assessment", control_id=assessment.control_id)
        controls[assessment.control_id] = assessment.status
    for status, identifiers in (
        (ControlStatus.SATISFIED, set(posture.satisfied_control_ids)),
        (ControlStatus.EXCEPTIONED, set(posture.exceptioned_control_ids)),
        (ControlStatus.NOT_EVALUATED, set(posture.not_evaluated_control_ids)),
    ):
        if identifiers != {control_id for control_id, observed in controls.items() if observed == status}:
            _reject(SecretExposureRejectReason.CONTROL_EVIDENCE_INVALID, "posture control status summary is inconsistent")
    return assets, flows, controls, architecture_sha


def _validate_manifest(
    manifest: SecretExposureManifest,
    request: SecretExposureRequest,
    policy: SecretExposurePolicy,
    assets: Mapping[str, object],
    flows: Mapping[str, object],
    controls: Mapping[str, ControlStatus],
    architecture_sha: str,
) -> tuple[dict[str, ExposureSurface], dict[str, SecretMaterial], dict[str, SecretTransferEdge], str]:
    if manifest.schema_version != P7D_SECRET_MANIFEST_SCHEMA_VERSION or manifest.secret_graph_id != policy.expected_secret_graph_id or manifest.version != policy.expected_secret_graph_version:
        _reject(SecretExposureRejectReason.MANIFEST_INVALID, "secret exposure manifest identity/schema is invalid")
    if manifest.architecture_sha256.casefold() != architecture_sha.casefold():
        _reject(SecretExposureRejectReason.ARCHITECTURE_DIGEST_MISMATCH, "secret manifest architecture binding differs")
    manifest_sha = secret_exposure_manifest_digest(manifest)
    if manifest_sha.casefold() != policy.expected_secret_graph_sha256.casefold() or request.secret_graph_sha256.casefold() != manifest_sha.casefold():
        _reject(SecretExposureRejectReason.MANIFEST_DIGEST_MISMATCH, "secret manifest digest differs")
    age = request.evaluated_at_epoch - manifest.created_at_epoch
    if age > policy.max_manifest_age_seconds:
        _reject(SecretExposureRejectReason.MANIFEST_STALE, "secret exposure manifest is stale")
    if age < -policy.max_future_skew_seconds:
        _reject(SecretExposureRejectReason.MANIFEST_FUTURE, "secret exposure manifest is from the future")

    surfaces = {item.surface_id: item for item in manifest.surfaces}
    secrets = {item.secret_id: item for item in manifest.secrets}
    edges = {item.edge_id: item for item in manifest.edges}
    if len(surfaces) != len(manifest.surfaces):
        _reject(SecretExposureRejectReason.SURFACE_DUPLICATE, "duplicate exposure surface")
    if len(secrets) != len(manifest.secrets):
        _reject(SecretExposureRejectReason.SECRET_DUPLICATE, "duplicate secret identity")
    if len(edges) != len(manifest.edges):
        _reject(SecretExposureRejectReason.EDGE_DUPLICATE, "duplicate secret transfer edge")
    if set(surfaces) != policy.required_surface_ids:
        _reject(SecretExposureRejectReason.SURFACE_COVERAGE_MISMATCH, "surface inventory differs from policy")
    if set(secrets) != policy.required_secret_ids:
        _reject(SecretExposureRejectReason.SECRET_COVERAGE_MISMATCH, "secret inventory differs from policy")
    if set(edges) != policy.required_edge_ids:
        _reject(SecretExposureRejectReason.EDGE_COVERAGE_MISMATCH, "secret transfer inventory differs from policy")

    for surface_id, surface in surfaces.items():
        if surface.owner_id not in policy.trusted_owner_ids:
            _reject(SecretExposureRejectReason.SURFACE_OWNER_UNTRUSTED, "surface owner is not trusted", surface_id=surface_id)
        if surface.surface_type != policy.expected_surface_type[surface_id]:
            _reject(SecretExposureRejectReason.SURFACE_TYPE_DRIFT, "surface type differs from policy", surface_id=surface_id)
        if surface.exposure_scope != policy.expected_surface_scope[surface_id]:
            _reject(SecretExposureRejectReason.SURFACE_SCOPE_DRIFT, "surface exposure scope differs from policy", surface_id=surface_id)
        if surface.trust_zone != policy.expected_surface_zone[surface_id]:
            _reject(SecretExposureRejectReason.SURFACE_ZONE_DRIFT, "surface trust zone differs from policy", surface_id=surface_id)
        if surface.architecture_asset_id != policy.expected_architecture_asset_by_surface[surface_id]:
            _reject(SecretExposureRejectReason.SURFACE_ARCHITECTURE_DRIFT, "surface architecture mapping differs from policy", surface_id=surface_id)
        if surface.architecture_asset_id is not None and surface.architecture_asset_id not in assets:
            _reject(SecretExposureRejectReason.SURFACE_ARCHITECTURE_DRIFT, "surface references unknown architecture asset", surface_id=surface_id)

    for secret_id, secret in secrets.items():
        if secret.owner_id not in policy.trusted_owner_ids:
            _reject(SecretExposureRejectReason.SECRET_OWNER_UNTRUSTED, "secret owner is not trusted", secret_id=secret_id)
        if secret.home_surface_id != policy.expected_home_surface_by_secret[secret_id] or secret.home_surface_id not in surfaces:
            _reject(SecretExposureRejectReason.SECRET_HOME_DRIFT, "secret home surface differs from policy", secret_id=secret_id)
        if secret.kind != policy.expected_kind_by_secret[secret_id]:
            _reject(SecretExposureRejectReason.SECRET_KIND_DRIFT, "secret kind differs from policy", secret_id=secret_id)
        if secret.authority_scope != policy.expected_scope_by_secret[secret_id]:
            _reject(SecretExposureRejectReason.SECRET_SCOPE_DRIFT, "secret authority scope differs from policy", secret_id=secret_id)
        if _sensitivity_rank(secret.sensitivity) < _sensitivity_rank(policy.minimum_sensitivity_by_secret[secret_id]):
            _reject(SecretExposureRejectReason.SECRET_SENSITIVITY_DOWNGRADE, "secret sensitivity is below policy floor", secret_id=secret_id)
        if secret.trust_root != policy.expected_trust_root_by_secret[secret_id]:
            _reject(SecretExposureRejectReason.SECRET_TRUST_ROOT_DRIFT, "secret trust-root classification differs from policy", secret_id=secret_id)
        if secret.rotated_at_epoch <= 0 or secret.expires_at_epoch <= secret.rotated_at_epoch or secret.rotated_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
            _reject(SecretExposureRejectReason.SECRET_ROTATION_INVALID, "secret rotation/expiry metadata is invalid", secret_id=secret_id)

    for edge_id, edge in edges.items():
        if edge.owner_id not in policy.trusted_owner_ids:
            _reject(SecretExposureRejectReason.EDGE_OWNER_UNTRUSTED, "secret transfer owner is not trusted", edge_id=edge_id)
        if edge.secret_id not in secrets or edge.source_surface_id not in surfaces or edge.target_surface_id not in surfaces:
            _reject(SecretExposureRejectReason.EDGE_REFERENCE_INVALID, "secret transfer references unknown inventory", edge_id=edge_id)
        if edge.source_surface_id == edge.target_surface_id:
            _reject(SecretExposureRejectReason.EDGE_SELF_LOOP, "secret transfer self-loop is invalid", edge_id=edge_id)
        if edge.secret_id != policy.expected_secret_id_by_edge[edge_id]:
            _reject(SecretExposureRejectReason.EDGE_SECRET_DRIFT, "edge secret binding differs from policy", edge_id=edge_id)
        if (edge.source_surface_id, edge.target_surface_id) != policy.expected_endpoints_by_edge[edge_id]:
            _reject(SecretExposureRejectReason.EDGE_ENDPOINT_DRIFT, "edge endpoints differ from policy", edge_id=edge_id)
        if edge.channel != policy.expected_channel_by_edge[edge_id]:
            _reject(SecretExposureRejectReason.EDGE_CHANNEL_DRIFT, "edge channel differs from policy", edge_id=edge_id)
        if tuple(edge.via_flow_ids) != tuple(policy.expected_flow_ids_by_edge[edge_id]):
            _reject(SecretExposureRejectReason.EDGE_FLOW_DRIFT, "edge architecture route differs from policy", edge_id=edge_id)
        if frozenset(edge.required_control_ids) != policy.expected_control_ids_by_edge[edge_id] or len(set(edge.required_control_ids)) != len(edge.required_control_ids):
            _reject(SecretExposureRejectReason.EDGE_CONTROL_DRIFT, "edge controls differ from policy", edge_id=edge_id)
        for control_id in edge.required_control_ids:
            if control_id not in controls:
                _reject(SecretExposureRejectReason.EDGE_CONTROL_UNKNOWN, "edge references unknown posture control", edge_id=edge_id, control_id=control_id)
        for flow_id in edge.via_flow_ids:
            if flow_id not in flows:
                _reject(SecretExposureRejectReason.EDGE_ARCHITECTURE_ROUTE_INVALID, "edge references unknown architecture flow", edge_id=edge_id)
        if edge.via_flow_ids:
            route = [flows[flow_id] for flow_id in edge.via_flow_ids]
            if any(route[index].target_asset_id != route[index + 1].source_asset_id for index in range(len(route) - 1)):
                _reject(SecretExposureRejectReason.EDGE_ARCHITECTURE_ROUTE_INVALID, "edge architecture route is not contiguous", edge_id=edge_id)
            source_asset = surfaces[edge.source_surface_id].architecture_asset_id
            target_asset = surfaces[edge.target_surface_id].architecture_asset_id
            if source_asset is not None and route[0].source_asset_id != source_asset:
                _reject(SecretExposureRejectReason.EDGE_ARCHITECTURE_ROUTE_INVALID, "edge route source differs from mapped architecture asset", edge_id=edge_id)
            if target_asset is not None and route[-1].target_asset_id != target_asset:
                _reject(SecretExposureRejectReason.EDGE_ARCHITECTURE_ROUTE_INVALID, "edge route target differs from mapped architecture asset", edge_id=edge_id)
            route_controls = {control for flow in route for control in flow.required_control_ids}
            if not set(edge.required_control_ids) <= route_controls:
                _reject(SecretExposureRejectReason.EDGE_ARCHITECTURE_ROUTE_INVALID, "edge control is not present on its architecture route", edge_id=edge_id)
    return surfaces, secrets, edges, manifest_sha


def _path_fact(
    secret: SecretMaterial,
    edge_path: tuple[SecretTransferEdge, ...],
    surfaces: Mapping[str, ExposureSurface],
    controls: Mapping[str, ControlStatus],
    policy: SecretExposurePolicy,
    evaluated_at_epoch: int,
) -> SecretExposurePathFact:
    surface_ids = (edge_path[0].source_surface_id,) + tuple(edge.target_surface_id for edge in edge_path)
    edge_ids = tuple(edge.edge_id for edge in edge_path)
    architecture_flow_ids = tuple(flow_id for edge in edge_path for flow_id in edge.via_flow_ids)
    satisfied: set[str] = set()
    exceptioned: set[str] = set()
    not_evaluated: set[str] = set()
    for edge in edge_path:
        for control_id in edge.required_control_ids:
            status = controls[control_id]
            if status == ControlStatus.SATISFIED:
                satisfied.add(control_id)
            elif status == ControlStatus.EXCEPTIONED:
                exceptioned.add(control_id)
            else:
                not_evaluated.add(control_id)

    unauthorized = tuple(
        sorted(
            {
                surface_id
                for surface_id in surface_ids[1:]
                if surface_id not in policy.allowed_target_surfaces_by_secret[secret.secret_id]
            }
        )
    )
    scope_violations = tuple(
        sorted(
            {
                surface_id
                for surface_id in surface_ids[1:]
                if surfaces[surface_id].exposure_scope not in policy.allowed_surface_scopes_by_secret[secret.secret_id]
            }
        )
    )
    plaintext_edges = tuple(
        sorted(
            edge.edge_id
            for edge in edge_path
            if edge.plaintext_exposure and policy.forbid_plaintext_by_secret[secret.secret_id]
        )
    )
    persistent_edges = tuple(
        sorted(
            edge.edge_id
            for edge in edge_path
            if edge.persistent_copy and policy.forbid_persistent_copy_by_secret[secret.secret_id]
        )
    )
    rotation_overdue = evaluated_at_epoch - secret.rotated_at_epoch > policy.max_rotation_age_seconds_by_secret[secret.secret_id]
    expired = evaluated_at_epoch >= secret.expires_at_epoch
    external_egress = any(surfaces[surface_id].external_egress for surface_id in surface_ids[1:])

    reasons = (
        [f"unauthorized_surface:{item}" for item in unauthorized]
        + [f"scope_violation:{item}" for item in scope_violations]
        + [f"plaintext_exposure:{item}" for item in plaintext_edges]
        + [f"persistent_copy:{item}" for item in persistent_edges]
        + (["rotation_overdue"] if rotation_overdue else [])
        + (["secret_expired"] if expired else [])
        + [f"exceptioned_control:{item}" for item in sorted(exceptioned)]
        + [f"not_evaluated_control:{item}" for item in sorted(not_evaluated)]
        + (["trust_root_external_egress"] if secret.trust_root and external_egress else [])
    )
    exposed = bool(reasons)
    blast_radius_score = (
        10
        + _sensitivity_rank(secret.sensitivity) * 28
        + _scope_rank(secret.authority_scope) * 5
        + len(edge_path) * 2
        + len(unauthorized) * 18
        + len(scope_violations) * 14
        + len(plaintext_edges) * 22
        + len(persistent_edges) * 15
        + len(exceptioned) * 10
        + len(not_evaluated) * 6
        + (18 if rotation_overdue else 0)
        + (24 if expired else 0)
        + (30 if secret.trust_root else 0)
        + (25 if external_egress else 0)
    )
    return SecretExposurePathFact(
        path_id=secret_exposure_path_identifier(secret.secret_id, surface_ids, edge_ids),
        secret_id=secret.secret_id,
        secret_kind=secret.kind,
        secret_sensitivity=secret.sensitivity,
        authority_scope=secret.authority_scope,
        trust_root=secret.trust_root,
        surface_ids=surface_ids,
        edge_ids=edge_ids,
        architecture_flow_ids=architecture_flow_ids,
        channel_sequence=tuple(edge.channel.value for edge in edge_path),
        satisfied_control_ids=tuple(sorted(satisfied)),
        exceptioned_control_ids=tuple(sorted(exceptioned)),
        not_evaluated_control_ids=tuple(sorted(not_evaluated)),
        unauthorized_surface_ids=unauthorized,
        scope_violation_surface_ids=scope_violations,
        plaintext_edge_ids=plaintext_edges,
        persistent_copy_edge_ids=persistent_edges,
        rotation_overdue=rotation_overdue,
        expired=expired,
        external_egress=external_egress,
        exposed=exposed,
        blast_radius_score=blast_radius_score,
        exposure_reasons=tuple(sorted(reasons)),
        mitigating_control_ids=tuple(sorted(satisfied)),
    )


def _enumerate_paths(
    secrets: Mapping[str, SecretMaterial],
    edges: Mapping[str, SecretTransferEdge],
    surfaces: Mapping[str, ExposureSurface],
    controls: Mapping[str, ControlStatus],
    policy: SecretExposurePolicy,
    evaluated_at_epoch: int,
) -> tuple[SecretExposurePathFact, ...]:
    adjacency: dict[tuple[str, str], list[SecretTransferEdge]] = {}
    for edge in edges.values():
        adjacency.setdefault((edge.secret_id, edge.source_surface_id), []).append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda item: item.edge_id)
    results: list[SecretExposurePathFact] = []
    truncated = False

    def walk(secret: SecretMaterial, current: str, path: tuple[SecretTransferEdge, ...], visited: frozenset[str]) -> None:
        nonlocal truncated
        if current in policy.target_surface_ids and path:
            results.append(_path_fact(secret, path, surfaces, controls, policy, evaluated_at_epoch))
            if len(results) > policy.max_paths:
                _reject(SecretExposureRejectReason.PATH_LIMIT_EXCEEDED, "secret topology exceeds path bound")
            return
        outgoing = [
            edge
            for edge in adjacency.get((secret.secret_id, current), ())
            if edge.target_surface_id not in visited
        ]
        if len(path) >= policy.max_path_hops:
            if outgoing:
                truncated = True
            return
        for edge in outgoing:
            walk(secret, edge.target_surface_id, path + (edge,), visited | frozenset({edge.target_surface_id}))

    for secret_id in sorted(policy.entry_secret_ids):
        secret = secrets[secret_id]
        walk(secret, secret.home_surface_id, (), frozenset({secret.home_surface_id}))
    if truncated:
        _reject(SecretExposureRejectReason.PATH_LIMIT_EXCEEDED, "secret path hop bound truncated reachable topology")
    unique = {item.path_id: item for item in results}
    if len(unique) != len(results):
        _reject(SecretExposureRejectReason.PATH_LIMIT_EXCEEDED, "secret path identifier collision detected")
    return tuple(sorted(unique.values(), key=lambda item: item.path_id))


class SecretsCredentialTrustRootExposureAnalyzer:
    """Derive synthetic secret exposure and blast-radius paths from pinned evidence.

    The analyzer never reads real credentials, invokes a vault, rotates a key, or performs
    exfiltration. It evaluates a deterministic manifest against exact architecture,
    assurance, identity, data-flow, and posture evidence.
    """

    def __init__(self, policy: SecretExposurePolicy) -> None:
        self._policy = policy

    def evaluate(
        self,
        request: SecretExposureRequest,
        manifest: SecretExposureManifest,
        architecture: ArchitectureManifest,
        p7a_assessment: VerifiedAttackPathAssessment,
        p7b_assessment: VerifiedPrivilegeEscalationAssessment,
        p7c_assessment: VerifiedDataExfiltrationAssessment,
        posture: VerifiedSecurityPosture,
    ) -> VerifiedSecretExposureAssessment:
        _validate_policy(self._policy)
        _validate_request(request, self._policy)
        assets, flows, controls, architecture_sha = _validate_upstream(
            request,
            self._policy,
            architecture,
            p7a_assessment,
            p7b_assessment,
            p7c_assessment,
            posture,
        )
        surfaces, secrets, edges, manifest_sha = _validate_manifest(
            manifest,
            request,
            self._policy,
            assets,
            flows,
            controls,
            architecture_sha,
        )
        paths = _enumerate_paths(
            secrets,
            edges,
            surfaces,
            controls,
            self._policy,
            request.evaluated_at_epoch,
        )
        exposed = tuple(item for item in paths if item.exposed)
        controlled = tuple(item for item in paths if not item.exposed)
        prioritized = tuple(
            item.path_id
            for item in sorted(
                exposed,
                key=lambda item: (-item.blast_radius_score, item.secret_id, item.path_id),
            )
        )
        max_score = max((item.blast_radius_score for item in exposed), default=0)
        if set(request.declared_exposed_path_ids) != set(prioritized):
            _reject(SecretExposureRejectReason.DECLARED_PATH_MISMATCH, "caller-declared exposed secret paths differ from derived evidence")
        if request.declared_max_blast_radius_score != max_score:
            _reject(SecretExposureRejectReason.DECLARED_BLAST_RADIUS_MISMATCH, "caller-declared blast radius differs from derived evidence")

        evidence_document = {
            "architecture_sha256": architecture_sha,
            "control_catalog_sha256": posture.control_catalog_sha256.casefold(),
            "entry_secret_ids": sorted(request.entry_secret_ids),
            "exposed_path_ids": list(prioritized),
            "max_blast_radius_score": max_score,
            "p7a_assessment_evidence_sha256": p7a_assessment.assessment_evidence_sha256.casefold(),
            "p7b_assessment_evidence_sha256": p7b_assessment.assessment_evidence_sha256.casefold(),
            "p7c_assessment_evidence_sha256": p7c_assessment.assessment_evidence_sha256.casefold(),
            "path_facts": [asdict(item) for item in paths],
            "posture_evidence_sha256": posture.posture_evidence_sha256.casefold(),
            "secret_graph_sha256": manifest_sha,
            "target_surface_ids": sorted(request.target_surface_ids),
        }
        assessment_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        return VerifiedSecretExposureAssessment(
            secret_graph_id=manifest.secret_graph_id,
            secret_graph_version=manifest.version,
            secret_graph_sha256=manifest_sha,
            architecture_sha256=architecture_sha,
            p7a_assessment_evidence_sha256=p7a_assessment.assessment_evidence_sha256.casefold(),
            p7b_assessment_evidence_sha256=p7b_assessment.assessment_evidence_sha256.casefold(),
            p7c_assessment_evidence_sha256=p7c_assessment.assessment_evidence_sha256.casefold(),
            posture_evidence_sha256=posture.posture_evidence_sha256.casefold(),
            control_catalog_sha256=posture.control_catalog_sha256.casefold(),
            entry_secret_ids=tuple(sorted(request.entry_secret_ids)),
            target_surface_ids=tuple(sorted(request.target_surface_ids)),
            topology_path_count=len(paths),
            exposed_path_count=len(exposed),
            controlled_path_count=len(controlled),
            critical_exposed_path_count=sum(item.secret_sensitivity == SecretSensitivity.CRITICAL for item in exposed),
            trust_root_exposed_path_count=sum(item.trust_root for item in exposed),
            external_egress_exposed_path_count=sum(item.external_egress for item in exposed),
            max_blast_radius_score=max_score,
            prioritized_exposed_path_ids=prioritized,
            paths=paths,
            assessment_evidence_sha256=assessment_sha,
        )
