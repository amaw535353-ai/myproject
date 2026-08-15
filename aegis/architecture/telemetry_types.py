from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


P7G_TELEMETRY_POLICY_VERSION = "security-telemetry-integrity-detection-blind-spots-v1"
P7G_TELEMETRY_MANIFEST_SCHEMA_VERSION = "aegis-security-telemetry-coverage-manifest-v1"
P7G_ASSESSMENT_SCHEMA_VERSION = "aegis-security-telemetry-blind-spot-assessment-v1"
P7G_ASSESSMENT_MODE = "deterministic-evidence-bound-telemetry-integrity-analysis-v1"


class TelemetryEventClass(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PRIVILEGE_CHANGE = "privilege_change"
    TOOL_EXECUTION = "tool_execution"
    DATA_ACCESS = "data_access"
    DATA_EGRESS = "data_egress"
    SECRET_ACCESS = "secret_access"
    MODEL_RUNTIME = "model_runtime"
    MODEL_RELEASE = "model_release"
    DEPENDENCY_EGRESS = "dependency_egress"
    FAILOVER = "failover"
    SECURITY_CONTROL_CHANGE = "security_control_change"


class TelemetrySeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TelemetrySourceKind(StrEnum):
    P7A_ATTACK_PATH = "p7a_attack_path"
    P7B_PRIVILEGE_PATH = "p7b_privilege_path"
    P7C_DATA_PATH = "p7c_data_path"
    P7D_SECRET_PATH = "p7d_secret_path"
    P7E_DEPENDENCY_PATH = "p7e_dependency_path"
    P7F_FAILURE_SCENARIO = "p7f_failure_scenario"
    P6D_CONTROL = "p6d_control"


class TelemetryNodeType(StrEnum):
    PRODUCER = "producer"
    COLLECTOR = "collector"
    PROCESSOR = "processor"
    AUDIT_SINK = "audit_sink"
    ALERT_SINK = "alert_sink"


class TelemetryBlindSpotRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    P7A_ASSESSMENT_UNVERIFIED = "p7a_assessment_unverified"
    P7A_ASSESSMENT_MISMATCH = "p7a_assessment_mismatch"
    P7B_ASSESSMENT_UNVERIFIED = "p7b_assessment_unverified"
    P7B_ASSESSMENT_MISMATCH = "p7b_assessment_mismatch"
    P7C_ASSESSMENT_UNVERIFIED = "p7c_assessment_unverified"
    P7C_ASSESSMENT_MISMATCH = "p7c_assessment_mismatch"
    P7D_ASSESSMENT_UNVERIFIED = "p7d_assessment_unverified"
    P7D_ASSESSMENT_MISMATCH = "p7d_assessment_mismatch"
    P7E_ASSESSMENT_UNVERIFIED = "p7e_assessment_unverified"
    P7E_ASSESSMENT_MISMATCH = "p7e_assessment_mismatch"
    P7F_ASSESSMENT_UNVERIFIED = "p7f_assessment_unverified"
    P7F_ASSESSMENT_MISMATCH = "p7f_assessment_mismatch"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    REQUIREMENT_DUPLICATE = "requirement_duplicate"
    REQUIREMENT_COVERAGE_MISMATCH = "requirement_coverage_mismatch"
    REQUIREMENT_OWNER_UNTRUSTED = "requirement_owner_untrusted"
    REQUIREMENT_CLASS_DRIFT = "requirement_class_drift"
    REQUIREMENT_SEVERITY_DOWNGRADE = "requirement_severity_downgrade"
    REQUIREMENT_SOURCE_KIND_DRIFT = "requirement_source_kind_drift"
    REQUIREMENT_SOURCE_OBJECT_DRIFT = "requirement_source_object_drift"
    REQUIREMENT_SOURCE_OBJECT_UNKNOWN = "requirement_source_object_unknown"
    REQUIREMENT_FIELDS_DRIFT = "requirement_fields_drift"
    REQUIREMENT_ALERT_DRIFT = "requirement_alert_drift"
    REQUIREMENT_LATENCY_DRIFT = "requirement_latency_drift"
    NODE_DUPLICATE = "node_duplicate"
    NODE_COVERAGE_MISMATCH = "node_coverage_mismatch"
    NODE_OWNER_UNTRUSTED = "node_owner_untrusted"
    NODE_TYPE_DRIFT = "node_type_drift"
    NODE_ZONE_DRIFT = "node_zone_drift"
    NODE_INTEGRITY_CAPABILITY_DRIFT = "node_integrity_capability_drift"
    NODE_APPEND_ONLY_CAPABILITY_DRIFT = "node_append_only_capability_drift"
    NODE_ALERT_CAPABILITY_DRIFT = "node_alert_capability_drift"
    ROUTE_DUPLICATE = "route_duplicate"
    ROUTE_COVERAGE_MISMATCH = "route_coverage_mismatch"
    ROUTE_OWNER_UNTRUSTED = "route_owner_untrusted"
    ROUTE_OBSERVER_UNTRUSTED = "route_observer_untrusted"
    ROUTE_REQUIREMENT_DRIFT = "route_requirement_drift"
    ROUTE_NODE_DRIFT = "route_node_drift"
    ROUTE_NODE_UNKNOWN = "route_node_unknown"
    ROUTE_SHAPE_INVALID = "route_shape_invalid"
    ROUTE_CONTROL_DRIFT = "route_control_drift"
    ROUTE_CONTROL_UNKNOWN = "route_control_unknown"
    ROUTE_OBSERVATION_STALE = "route_observation_stale"
    ROUTE_OBSERVATION_FUTURE = "route_observation_future"
    ROUTE_FALLBACK_SCOPE_DRIFT = "route_fallback_scope_drift"
    ROUTE_DROPPED_FIELD_UNKNOWN = "route_dropped_field_unknown"
    REQUIREMENT_ROUTE_COVERAGE_MISMATCH = "requirement_route_coverage_mismatch"
    DECLARED_BLIND_SPOT_MISMATCH = "declared_blind_spot_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class TelemetryBlindSpotRejected(ValueError):
    def __init__(
        self,
        reason: TelemetryBlindSpotRejectReason,
        message: str,
        *,
        requirement_id: str | None = None,
        node_id: str | None = None,
        route_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.requirement_id = requirement_id
        self.node_id = node_id
        self.route_id = route_id
        self.control_id = control_id


@dataclass(frozen=True)
class TelemetryEventRequirement:
    requirement_id: str
    event_class: TelemetryEventClass
    severity: TelemetrySeverity
    source_kind: TelemetrySourceKind
    source_object_ids: tuple[str, ...]
    required_field_ids: tuple[str, ...]
    requires_alert: bool
    max_detection_latency_seconds: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class TelemetryNode:
    node_id: str
    node_type: TelemetryNodeType
    owner_id: str
    trust_zone: str
    integrity_validation_capable: bool
    append_only_capable: bool
    alert_capable: bool
    description: str


@dataclass(frozen=True)
class TelemetryRoute:
    route_id: str
    requirement_id: str
    node_ids: tuple[str, ...]
    owner_id: str
    observer_id: str
    required_control_ids: tuple[str, ...]
    observed_at_epoch: int
    source_signature_valid: bool
    chain_integrity_valid: bool
    append_only_acknowledged: bool
    alert_path_operational: bool
    observed_detection_latency_seconds: int
    covered_fallback_scenario_ids: tuple[str, ...]
    dropped_field_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class TelemetryCoverageManifest:
    telemetry_plan_id: str
    version: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    created_at_epoch: int
    requirements: tuple[TelemetryEventRequirement, ...]
    nodes: tuple[TelemetryNode, ...]
    routes: tuple[TelemetryRoute, ...]
    schema_version: str = P7G_TELEMETRY_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class TelemetryCoverageRequest:
    telemetry_plan_id: str
    telemetry_plan_version: str
    telemetry_plan_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    evaluated_at_epoch: int
    requirement_ids: tuple[str, ...]
    declared_blind_spot_requirement_ids: tuple[str, ...]
    declared_max_blind_spot_risk_score: int


@dataclass(frozen=True)
class TelemetryCoveragePolicy:
    expected_telemetry_plan_id: str
    expected_telemetry_plan_version: str
    expected_telemetry_plan_sha256: str
    expected_p7a_assessment_evidence_sha256: str
    expected_p7b_assessment_evidence_sha256: str
    expected_p7c_assessment_evidence_sha256: str
    expected_p7d_assessment_evidence_sha256: str
    expected_p7e_assessment_evidence_sha256: str
    expected_p7f_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_requirement_ids: frozenset[str]
    required_node_ids: frozenset[str]
    required_route_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    trusted_observer_ids: frozenset[str]
    expected_event_class_by_requirement: Mapping[str, TelemetryEventClass]
    minimum_severity_by_requirement: Mapping[str, TelemetrySeverity]
    expected_source_kind_by_requirement: Mapping[str, TelemetrySourceKind]
    expected_source_object_ids_by_requirement: Mapping[str, frozenset[str]]
    expected_required_field_ids_by_requirement: Mapping[str, frozenset[str]]
    expected_requires_alert_by_requirement: Mapping[str, bool]
    max_detection_latency_by_requirement: Mapping[str, int]
    required_fallback_scenario_ids_by_requirement: Mapping[str, frozenset[str]]
    expected_node_type: Mapping[str, TelemetryNodeType]
    expected_node_zone: Mapping[str, str]
    minimum_integrity_validation_capable: Mapping[str, bool]
    minimum_append_only_capable: Mapping[str, bool]
    minimum_alert_capable: Mapping[str, bool]
    expected_requirement_by_route: Mapping[str, str]
    expected_node_ids_by_route: Mapping[str, tuple[str, ...]]
    expected_control_ids_by_route: Mapping[str, frozenset[str]]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30
    max_observation_age_seconds: int = 3_600


@dataclass(frozen=True)
class TelemetryRequirementFact:
    requirement_id: str
    event_class: TelemetryEventClass
    severity: TelemetrySeverity
    source_kind: TelemetrySourceKind
    source_object_ids: tuple[str, ...]
    route_id: str
    node_ids: tuple[str, ...]
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    covered_fallback_scenario_ids: tuple[str, ...]
    missing_fallback_scenario_ids: tuple[str, ...]
    dropped_field_ids: tuple[str, ...]
    source_signature_valid: bool
    chain_integrity_valid: bool
    append_only_acknowledged: bool
    alert_path_operational: bool
    observed_detection_latency_seconds: int
    blind_spot: bool
    blind_spot_risk_score: int
    blind_spot_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedTelemetryCoverageAssessment:
    telemetry_plan_id: str
    telemetry_plan_version: str
    telemetry_plan_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    requirement_count: int
    monitored_requirement_count: int
    blind_spot_requirement_count: int
    critical_blind_spot_count: int
    high_or_critical_blind_spot_count: int
    fallback_blind_spot_count: int
    integrity_blind_spot_count: int
    alerting_blind_spot_count: int
    max_blind_spot_risk_score: int
    prioritized_blind_spot_requirement_ids: tuple[str, ...]
    requirements: tuple[TelemetryRequirementFact, ...]
    assessment_evidence_sha256: str
    exact_telemetry_plan_binding_verified: bool = True
    exact_p7a_assessment_binding_verified: bool = True
    exact_p7b_assessment_binding_verified: bool = True
    exact_p7c_assessment_binding_verified: bool = True
    exact_p7d_assessment_binding_verified: bool = True
    exact_p7e_assessment_binding_verified: bool = True
    exact_p7f_assessment_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    event_catalog_policy_pinned: bool = True
    telemetry_routes_policy_pinned: bool = True
    audit_integrity_derived_from_evidence: bool = True
    fallback_observability_derived_from_evidence: bool = True
    caller_summary_trusted: bool = False
    production_log_ingestion: bool = False
    production_siem_integration: bool = False
    production_alert_delivery: bool = False
    real_detection_effectiveness_measurement: bool = False
    formal_audit_completeness_proof: bool = False
    network_operations: int = 0
    schema_version: str = P7G_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7G_TELEMETRY_POLICY_VERSION
    assessment_mode: str = P7G_ASSESSMENT_MODE


def reject(reason: TelemetryBlindSpotRejectReason, message: str, **context: str | None) -> None:
    raise TelemetryBlindSpotRejected(reason, message, **context)
