from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


P7C_DATA_POLICY_VERSION = "data-flow-tenant-isolation-exfiltration-v1"
P7C_DATA_MANIFEST_SCHEMA_VERSION = "aegis-data-flow-manifest-v1"
P7C_ASSESSMENT_SCHEMA_VERSION = "aegis-data-exfiltration-assessment-v1"
P7C_ASSESSMENT_MODE = "deterministic-evidence-bound-data-exfiltration-analysis-v1"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class DataKind(StrEnum):
    TENANT_CONTENT = "tenant_content"
    CREDENTIAL = "credential"
    MODEL_INPUT = "model_input"
    MODEL_OUTPUT = "model_output"
    SECURITY_TELEMETRY = "security_telemetry"


class DataTransform(StrEnum):
    NONE = "none"
    REDACTED = "redacted"
    AGGREGATED = "aggregated"
    TOKENIZED = "tokenized"


class DataPathRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    ARCHITECTURE_INVALID = "architecture_invalid"
    ARCHITECTURE_DIGEST_MISMATCH = "architecture_digest_mismatch"
    P7A_ASSESSMENT_UNVERIFIED = "p7a_assessment_unverified"
    P7A_ASSESSMENT_MISMATCH = "p7a_assessment_mismatch"
    P7B_ASSESSMENT_UNVERIFIED = "p7b_assessment_unverified"
    P7B_ASSESSMENT_MISMATCH = "p7b_assessment_mismatch"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    CONTROL_STATUS_MISMATCH = "control_status_mismatch"
    DATA_MANIFEST_INVALID = "data_manifest_invalid"
    DATA_MANIFEST_DIGEST_MISMATCH = "data_manifest_digest_mismatch"
    DATA_MANIFEST_STALE = "data_manifest_stale"
    DATA_MANIFEST_FUTURE = "data_manifest_future"
    DATA_DUPLICATE = "data_duplicate"
    DATA_COVERAGE_MISMATCH = "data_coverage_mismatch"
    DATA_OWNER_UNTRUSTED = "data_owner_untrusted"
    DATA_ORIGIN_INVALID = "data_origin_invalid"
    DATA_TENANT_DRIFT = "data_tenant_drift"
    DATA_KIND_DRIFT = "data_kind_drift"
    DATA_CLASSIFICATION_DOWNGRADE = "data_classification_downgrade"
    EDGE_DUPLICATE = "edge_duplicate"
    EDGE_COVERAGE_MISMATCH = "edge_coverage_mismatch"
    EDGE_OWNER_UNTRUSTED = "edge_owner_untrusted"
    EDGE_REFERENCE_INVALID = "edge_reference_invalid"
    EDGE_SELF_LOOP = "edge_self_loop"
    EDGE_DATA_DRIFT = "edge_data_drift"
    EDGE_ENDPOINT_DRIFT = "edge_endpoint_drift"
    EDGE_FLOW_DRIFT = "edge_flow_drift"
    EDGE_CONTROL_DRIFT = "edge_control_drift"
    EDGE_TRANSFORM_DISALLOWED = "edge_transform_disallowed"
    EDGE_FLOW_INVALID = "edge_flow_invalid"
    EDGE_CONTROL_UNKNOWN = "edge_control_unknown"
    ENTRY_DATA_SCOPE_MISMATCH = "entry_data_scope_mismatch"
    TARGET_SINK_SCOPE_MISMATCH = "target_sink_scope_mismatch"
    PATH_LIMIT_EXCEEDED = "path_limit_exceeded"
    DECLARED_PATH_MISMATCH = "declared_path_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class DataPathRejected(ValueError):
    def __init__(
        self,
        reason: DataPathRejectReason,
        message: str,
        *,
        data_id: str | None = None,
        edge_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.data_id = data_id
        self.edge_id = edge_id
        self.control_id = control_id


@dataclass(frozen=True)
class DataObject:
    data_id: str
    tenant_id: str
    data_kind: DataKind
    classification: DataClassification
    origin_asset_id: str
    owner_id: str
    description: str


@dataclass(frozen=True)
class DataFlowEdge:
    edge_id: str
    data_id: str
    source_asset_id: str
    target_asset_id: str
    destination_tenant_id: str
    transform: DataTransform
    owner_id: str
    via_flow_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]
    purpose: str


@dataclass(frozen=True)
class DataFlowManifest:
    data_graph_id: str
    version: str
    architecture_sha256: str
    created_at_epoch: int
    data_objects: tuple[DataObject, ...]
    edges: tuple[DataFlowEdge, ...]
    schema_version: str = P7C_DATA_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class DataPathRequest:
    data_graph_id: str
    data_graph_version: str
    data_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    entry_data_ids: tuple[str, ...]
    target_sink_asset_ids: tuple[str, ...]
    evaluated_at_epoch: int
    declared_exposed_path_ids: tuple[str, ...]
    declared_max_exposed_risk_score: int


@dataclass(frozen=True)
class DataPathPolicy:
    expected_data_graph_id: str
    expected_data_graph_version: str
    expected_data_graph_sha256: str
    expected_architecture_sha256: str
    expected_p7a_assessment_evidence_sha256: str
    expected_p7b_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_data_ids: frozenset[str]
    required_edge_ids: frozenset[str]
    entry_data_ids: frozenset[str]
    target_sink_asset_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_tenant_by_data: Mapping[str, str]
    expected_kind_by_data: Mapping[str, DataKind]
    expected_origin_asset_by_data: Mapping[str, str]
    minimum_classification_by_data: Mapping[str, DataClassification]
    expected_data_id_by_edge: Mapping[str, str]
    expected_endpoints_by_edge: Mapping[str, tuple[str, str]]
    expected_flow_ids_by_edge: Mapping[str, tuple[str, ...]]
    expected_control_ids_by_edge: Mapping[str, frozenset[str]]
    allowed_transforms_by_edge: Mapping[str, frozenset[DataTransform]]
    allowed_destination_tenants_by_data: Mapping[str, frozenset[str]]
    allowed_sink_assets_by_data: Mapping[str, frozenset[str]]
    max_classification_by_sink_asset: Mapping[str, DataClassification]
    allowed_final_transforms_by_sink_asset: Mapping[str, frozenset[DataTransform]]
    egress_sink_asset_ids: frozenset[str]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30
    max_path_hops: int = 10
    max_paths: int = 128


@dataclass(frozen=True)
class DataPathFact:
    path_id: str
    data_id: str
    origin_asset_id: str
    target_sink_asset_id: str
    asset_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    architecture_flow_ids: tuple[str, ...]
    tenant_sequence: tuple[str, ...]
    transform_sequence: tuple[str, ...]
    classification: DataClassification
    data_kind: DataKind
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    tenant_violation_edge_ids: tuple[str, ...]
    sink_allowed: bool
    classification_allowed: bool
    final_transform_allowed: bool
    external_egress: bool
    exposed: bool
    risk_score: int
    exposure_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedDataExfiltrationAssessment:
    data_graph_id: str
    data_graph_version: str
    data_graph_sha256: str
    architecture_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    entry_data_ids: tuple[str, ...]
    target_sink_asset_ids: tuple[str, ...]
    topology_path_count: int
    exposed_path_count: int
    controlled_path_count: int
    restricted_or_secret_exposed_path_count: int
    cross_tenant_exposed_path_count: int
    external_egress_exposed_path_count: int
    max_exposed_risk_score: int
    prioritized_exposed_path_ids: tuple[str, ...]
    paths: tuple[DataPathFact, ...]
    assessment_evidence_sha256: str
    exact_data_graph_binding_verified: bool = True
    exact_architecture_binding_verified: bool = True
    exact_p7a_assessment_binding_verified: bool = True
    exact_p7b_assessment_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    tenant_ownership_policy_pinned: bool = True
    classification_floors_policy_pinned: bool = True
    route_controls_policy_pinned: bool = True
    exfiltration_derived_from_evidence: bool = True
    mitigating_controls_visible: bool = True
    caller_summary_trusted: bool = False
    production_data_discovery: bool = False
    production_dlp_enforcement: bool = False
    real_data_access: bool = False
    production_exfiltration_testing: bool = False
    formal_information_flow_proof: bool = False
    network_operations: int = 0
    schema_version: str = P7C_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7C_DATA_POLICY_VERSION
    assessment_mode: str = P7C_ASSESSMENT_MODE
