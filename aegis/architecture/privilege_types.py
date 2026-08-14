from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

P7B_PRIVILEGE_POLICY_VERSION = "identity-privilege-capability-escalation-v1"
P7B_IDENTITY_SCHEMA_VERSION = "aegis-identity-capability-graph-v1"
P7B_ASSESSMENT_SCHEMA_VERSION = "aegis-privilege-escalation-assessment-v1"
P7B_ASSESSMENT_MODE = "deterministic-evidence-bound-privilege-path-analysis-v1"


class PrincipalType(StrEnum):
    EXTERNAL_USER = "external_user"
    TENANT_USER = "tenant_user"
    SERVICE_IDENTITY = "service_identity"
    TOOL_IDENTITY = "tool_identity"
    MODEL_PUBLISHER = "model_publisher"
    MODEL_RUNTIME = "model_runtime"
    SECURITY_IDENTITY = "security_identity"


class PrivilegeTier(StrEnum):
    UNTRUSTED = "untrusted"
    TENANT = "tenant"
    SERVICE = "service"
    PRIVILEGED = "privileged"
    SECURITY = "security"


class PrivilegeScope(StrEnum):
    PUBLIC = "public"
    TENANT = "tenant"
    WORKLOAD = "workload"
    SECURITY = "security"


class CapabilitySensitivity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DelegationType(StrEnum):
    AUTHENTICATED_SESSION = "authenticated_session"
    SERVER_PRINCIPAL_INJECTION = "server_principal_injection"
    TOOL_AUTHORIZATION = "tool_authorization"
    CREDENTIAL_BROKER = "credential_broker"
    MODEL_RELEASE_ADMISSION = "model_release_admission"
    RUNTIME_INVOCATION = "runtime_invocation"
    TELEMETRY_DELEGATION = "telemetry_delegation"


class PrivilegePathRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    ARCHITECTURE_INVALID = "architecture_invalid"
    ARCHITECTURE_DIGEST_MISMATCH = "architecture_digest_mismatch"
    P7A_ASSESSMENT_UNVERIFIED = "p7a_assessment_unverified"
    P7A_ASSESSMENT_MISMATCH = "p7a_assessment_mismatch"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    CONTROL_STATUS_MISMATCH = "control_status_mismatch"
    IDENTITY_MANIFEST_INVALID = "identity_manifest_invalid"
    IDENTITY_MANIFEST_DIGEST_MISMATCH = "identity_manifest_digest_mismatch"
    IDENTITY_MANIFEST_STALE = "identity_manifest_stale"
    IDENTITY_MANIFEST_FUTURE = "identity_manifest_future"
    PRINCIPAL_DUPLICATE = "principal_duplicate"
    PRINCIPAL_REQUIRED_MISSING = "principal_required_missing"
    PRINCIPAL_OWNER_UNTRUSTED = "principal_owner_untrusted"
    PRINCIPAL_ASSET_INVALID = "principal_asset_invalid"
    PRINCIPAL_TYPE_DRIFT = "principal_type_drift"
    PRINCIPAL_TIER_DRIFT = "principal_tier_drift"
    PRINCIPAL_SCOPE_DRIFT = "principal_scope_drift"
    PRINCIPAL_CAPABILITY_DRIFT = "principal_capability_drift"
    CAPABILITY_DUPLICATE = "capability_duplicate"
    CAPABILITY_REQUIRED_MISSING = "capability_required_missing"
    CAPABILITY_OWNER_UNTRUSTED = "capability_owner_untrusted"
    CAPABILITY_TARGET_INVALID = "capability_target_invalid"
    CAPABILITY_SENSITIVITY_DOWNGRADE = "capability_sensitivity_downgrade"
    CAPABILITY_TIER_DOWNGRADE = "capability_tier_downgrade"
    EDGE_DUPLICATE = "edge_duplicate"
    EDGE_REQUIRED_MISSING = "edge_required_missing"
    EDGE_OWNER_UNTRUSTED = "edge_owner_untrusted"
    EDGE_REFERENCE_INVALID = "edge_reference_invalid"
    EDGE_SELF_LOOP = "edge_self_loop"
    EDGE_ENDPOINT_DRIFT = "edge_endpoint_drift"
    EDGE_FLOW_DRIFT = "edge_flow_drift"
    EDGE_CONTROL_DRIFT = "edge_control_drift"
    EDGE_GRANT_DRIFT = "edge_grant_drift"
    EDGE_FLOW_INVALID = "edge_flow_invalid"
    EDGE_CONTROL_UNKNOWN = "edge_control_unknown"
    EDGE_CONTROL_NOT_ON_ROUTE = "edge_control_not_on_route"
    ATTESTED_ENTRY_SCOPE_MISMATCH = "attested_entry_scope_mismatch"
    TARGET_CAPABILITY_SCOPE_MISMATCH = "target_capability_scope_mismatch"
    PATH_LIMIT_EXCEEDED = "path_limit_exceeded"
    DECLARED_PATH_MISMATCH = "declared_path_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class PrivilegePathRejected(ValueError):
    def __init__(
        self,
        reason: PrivilegePathRejectReason,
        message: str,
        *,
        principal_id: str | None = None,
        capability_id: str | None = None,
        edge_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.principal_id = principal_id
        self.capability_id = capability_id
        self.edge_id = edge_id
        self.control_id = control_id


@dataclass(frozen=True)
class IdentityPrincipal:
    principal_id: str
    principal_type: PrincipalType
    home_asset_id: str
    owner_id: str
    privilege_tier: PrivilegeTier
    privilege_scope: PrivilegeScope
    native_capability_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class Capability:
    capability_id: str
    target_asset_id: str
    owner_id: str
    sensitivity: CapabilitySensitivity
    minimum_privilege_tier: PrivilegeTier
    description: str


@dataclass(frozen=True)
class PrivilegeTransition:
    edge_id: str
    source_principal_id: str
    target_principal_id: str
    delegation_type: DelegationType
    owner_id: str
    via_flow_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    granted_capability_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class IdentityCapabilityManifest:
    identity_graph_id: str
    version: str
    architecture_sha256: str
    created_at_epoch: int
    principals: tuple[IdentityPrincipal, ...]
    capabilities: tuple[Capability, ...]
    transitions: tuple[PrivilegeTransition, ...]
    schema_version: str = P7B_IDENTITY_SCHEMA_VERSION


@dataclass(frozen=True)
class PrivilegePathRequest:
    identity_graph_id: str
    identity_graph_version: str
    identity_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    entry_principal_ids: tuple[str, ...]
    target_capability_ids: tuple[str, ...]
    evaluated_at_epoch: int
    declared_exposed_path_ids: tuple[str, ...]
    declared_max_exposed_risk_score: int


@dataclass(frozen=True)
class PrivilegePathPolicy:
    expected_identity_graph_id: str
    expected_identity_graph_version: str
    expected_identity_graph_sha256: str
    expected_architecture_sha256: str
    expected_p7a_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_principal_ids: frozenset[str]
    required_capability_ids: frozenset[str]
    required_transition_ids: frozenset[str]
    entry_principal_ids: frozenset[str]
    target_capability_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_home_asset_by_principal: Mapping[str, str]
    expected_type_by_principal: Mapping[str, PrincipalType]
    expected_tier_by_principal: Mapping[str, PrivilegeTier]
    expected_scope_by_principal: Mapping[str, PrivilegeScope]
    expected_native_capabilities_by_principal: Mapping[str, frozenset[str]]
    expected_target_asset_by_capability: Mapping[str, str]
    minimum_sensitivity_by_capability: Mapping[str, CapabilitySensitivity]
    minimum_tier_by_capability: Mapping[str, PrivilegeTier]
    expected_transition_endpoints: Mapping[str, tuple[str, str]]
    expected_flow_ids_by_transition: Mapping[str, tuple[str, ...]]
    expected_control_ids_by_transition: Mapping[str, frozenset[str]]
    expected_granted_capability_ids_by_transition: Mapping[str, frozenset[str]]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30
    max_path_hops: int = 8
    max_paths: int = 128


@dataclass(frozen=True)
class PrivilegePathFact:
    path_id: str
    entry_principal_id: str
    final_principal_id: str
    target_capability_id: str
    principal_ids: tuple[str, ...]
    transition_ids: tuple[str, ...]
    architecture_flow_ids: tuple[str, ...]
    privilege_tier_sequence: tuple[str, ...]
    privilege_scope_sequence: tuple[str, ...]
    privilege_increase: int
    scope_increase: int
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    capability_sensitivity: CapabilitySensitivity
    exposed: bool
    risk_score: int
    exposure_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedPrivilegeEscalationAssessment:
    identity_graph_id: str
    identity_graph_version: str
    identity_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    entry_principal_ids: tuple[str, ...]
    target_capability_ids: tuple[str, ...]
    topology_path_count: int
    exposed_path_count: int
    controlled_path_count: int
    critical_exposed_path_count: int
    max_exposed_risk_score: int
    prioritized_exposed_path_ids: tuple[str, ...]
    paths: tuple[PrivilegePathFact, ...]
    assessment_evidence_sha256: str
    exact_identity_graph_binding_verified: bool = True
    exact_architecture_binding_verified: bool = True
    exact_p7a_assessment_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    principal_capability_policy_pinned: bool = True
    delegation_routes_policy_pinned: bool = True
    privilege_amplification_derived_from_evidence: bool = True
    mitigating_controls_visible: bool = True
    caller_summary_trusted: bool = False
    production_iam_discovery: bool = False
    real_credential_testing: bool = False
    production_exploitability_assessment: bool = False
    formal_authorization_proof: bool = False
    network_operations: int = 0
    schema_version: str = P7B_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7B_PRIVILEGE_POLICY_VERSION
    assessment_mode: str = P7B_ASSESSMENT_MODE
