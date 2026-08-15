from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from .dependency_trust import DependencyCriticality, EgressDataClass


P7F_RESILIENCE_POLICY_VERSION = "dependency-failure-graceful-degradation-security-v1"
P7F_RESILIENCE_MANIFEST_SCHEMA_VERSION = "aegis-dependency-resilience-plan-v1"
P7F_ASSESSMENT_SCHEMA_VERSION = "aegis-dependency-failure-security-assessment-v1"
P7F_ASSESSMENT_MODE = "deterministic-evidence-bound-graceful-degradation-security-v1"


class DependencyFailureState(StrEnum):
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNTRUSTED = "untrusted"


class FallbackMode(StrEnum):
    FAIL_CLOSED = "fail_closed"
    RETRY_PRIMARY = "retry_primary"
    ALTERNATE_DEPENDENCY = "alternate_dependency"
    LOCAL_SAFE_MODE = "local_safe_mode"
    CACHE_FALLBACK = "cache_fallback"


class ResilienceSecurityRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    P7E_ASSESSMENT_UNVERIFIED = "p7e_assessment_unverified"
    P7E_ASSESSMENT_MISMATCH = "p7e_assessment_mismatch"
    P7E_DEPENDENCY_PATH_AMBIGUOUS = "p7e_dependency_path_ambiguous"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    SCENARIO_DUPLICATE = "scenario_duplicate"
    SCENARIO_COVERAGE_MISMATCH = "scenario_coverage_mismatch"
    SCENARIO_OWNER_UNTRUSTED = "scenario_owner_untrusted"
    SCENARIO_DEPENDENCY_UNKNOWN = "scenario_dependency_unknown"
    SCENARIO_DEPENDENCY_DRIFT = "scenario_dependency_drift"
    SCENARIO_STATE_DRIFT = "scenario_state_drift"
    SCENARIO_CONTROL_DRIFT = "scenario_control_drift"
    SCENARIO_CONTROL_UNKNOWN = "scenario_control_unknown"
    FALLBACK_DUPLICATE = "fallback_duplicate"
    FALLBACK_COVERAGE_MISMATCH = "fallback_coverage_mismatch"
    FALLBACK_OWNER_UNTRUSTED = "fallback_owner_untrusted"
    FALLBACK_SCENARIO_UNKNOWN = "fallback_scenario_unknown"
    FALLBACK_SCENARIO_DRIFT = "fallback_scenario_drift"
    FALLBACK_MODE_DRIFT = "fallback_mode_drift"
    FALLBACK_TARGET_DRIFT = "fallback_target_drift"
    FALLBACK_TARGET_UNKNOWN = "fallback_target_unknown"
    FALLBACK_CONTROL_DRIFT = "fallback_control_drift"
    FALLBACK_CONTROL_UNKNOWN = "fallback_control_unknown"
    FALLBACK_CONTROL_OVERLAP = "fallback_control_overlap"
    FALLBACK_CONTROL_COVERAGE_MISMATCH = "fallback_control_coverage_mismatch"
    FALLBACK_DATA_SCOPE_MISMATCH = "fallback_data_scope_mismatch"
    FALLBACK_SECRET_SCOPE_MISMATCH = "fallback_secret_scope_mismatch"
    FALLBACK_SHAPE_INVALID = "fallback_shape_invalid"
    RETRY_BOUND_EXCEEDED = "retry_bound_exceeded"
    CACHE_TIMESTAMP_INVALID = "cache_timestamp_invalid"
    SCENARIO_FALLBACK_COVERAGE_MISMATCH = "scenario_fallback_coverage_mismatch"
    DECLARED_SCENARIO_MISMATCH = "declared_scenario_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class ResilienceSecurityRejected(ValueError):
    def __init__(
        self,
        reason: ResilienceSecurityRejectReason,
        message: str,
        *,
        scenario_id: str | None = None,
        fallback_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.scenario_id = scenario_id
        self.fallback_id = fallback_id
        self.control_id = control_id


@dataclass(frozen=True)
class DependencyFailureScenario:
    scenario_id: str
    dependency_id: str
    failure_state: DependencyFailureState
    owner_id: str
    required_control_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class FallbackStrategy:
    fallback_id: str
    scenario_id: str
    mode: FallbackMode
    owner_id: str
    target_dependency_id: str | None
    preserved_control_ids: tuple[str, ...]
    disabled_control_ids: tuple[str, ...]
    egress_data_classes: tuple[EgressDataClass, ...]
    secret_ids: tuple[str, ...]
    retry_attempts: int
    cached_at_epoch: int | None
    description: str


@dataclass(frozen=True)
class ResilienceSecurityManifest:
    resilience_plan_id: str
    version: str
    dependency_graph_sha256: str
    p7e_assessment_evidence_sha256: str
    created_at_epoch: int
    scenarios: tuple[DependencyFailureScenario, ...]
    fallbacks: tuple[FallbackStrategy, ...]
    schema_version: str = P7F_RESILIENCE_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class ResilienceSecurityRequest:
    resilience_plan_id: str
    resilience_plan_version: str
    resilience_plan_sha256: str
    dependency_graph_sha256: str
    p7e_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    evaluated_at_epoch: int
    scenario_ids: tuple[str, ...]
    declared_exposed_scenario_ids: tuple[str, ...]
    declared_max_security_risk_score: int


@dataclass(frozen=True)
class ResilienceSecurityPolicy:
    expected_resilience_plan_id: str
    expected_resilience_plan_version: str
    expected_resilience_plan_sha256: str
    expected_dependency_graph_sha256: str
    expected_p7e_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_scenario_ids: frozenset[str]
    required_fallback_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_dependency_by_scenario: Mapping[str, str]
    expected_failure_state_by_scenario: Mapping[str, DependencyFailureState]
    expected_required_control_ids_by_scenario: Mapping[str, frozenset[str]]
    expected_fallback_ids_by_scenario: Mapping[str, frozenset[str]]
    expected_scenario_by_fallback: Mapping[str, str]
    expected_mode_by_fallback: Mapping[str, FallbackMode]
    expected_target_dependency_by_fallback: Mapping[str, str | None]
    expected_preserved_control_ids_by_fallback: Mapping[str, frozenset[str]]
    expected_disabled_control_ids_by_fallback: Mapping[str, frozenset[str]]
    allowed_data_classes_by_fallback: Mapping[str, frozenset[EgressDataClass]]
    allowed_secret_ids_by_fallback: Mapping[str, frozenset[str]]
    max_retry_attempts_by_fallback: Mapping[str, int]
    max_cache_age_seconds_by_fallback: Mapping[str, int]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class FailureScenarioSecurityFact:
    scenario_id: str
    dependency_id: str
    failure_state: DependencyFailureState
    dependency_criticality: DependencyCriticality
    fallback_id: str
    fallback_mode: FallbackMode
    target_dependency_id: str | None
    service_continuity_expected: bool
    preserved_control_ids: tuple[str, ...]
    disabled_control_ids: tuple[str, ...]
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    egress_data_classes: tuple[str, ...]
    secret_ids: tuple[str, ...]
    cache_age_seconds: int | None
    retry_attempts: int
    security_preserved: bool
    exposed: bool
    security_risk_score: int
    exposure_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedResilienceSecurityAssessment:
    resilience_plan_id: str
    resilience_plan_version: str
    resilience_plan_sha256: str
    dependency_graph_sha256: str
    p7e_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    scenario_count: int
    exposed_scenario_count: int
    controlled_scenario_count: int
    service_continuity_scenario_count: int
    fail_closed_scenario_count: int
    critical_dependency_exposed_scenario_count: int
    untrusted_dependency_exposed_scenario_count: int
    max_security_risk_score: int
    prioritized_exposed_scenario_ids: tuple[str, ...]
    scenarios: tuple[FailureScenarioSecurityFact, ...]
    assessment_evidence_sha256: str
    exact_resilience_plan_binding_verified: bool = True
    exact_p7e_assessment_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    failure_states_policy_pinned: bool = True
    fallback_routes_policy_pinned: bool = True
    fail_closed_behavior_visible: bool = True
    security_degradation_derived_from_evidence: bool = True
    availability_and_security_distinguished: bool = True
    caller_summary_trusted: bool = False
    production_dependency_health_monitoring: bool = False
    production_failover_orchestration: bool = False
    live_chaos_testing: bool = False
    sla_or_slo_attestation: bool = False
    disaster_recovery_certification: bool = False
    network_operations: int = 0
    schema_version: str = P7F_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7F_RESILIENCE_POLICY_VERSION
    assessment_mode: str = P7F_ASSESSMENT_MODE


def reject(reason: ResilienceSecurityRejectReason, message: str, **context: str | None) -> None:
    raise ResilienceSecurityRejected(reason, message, **context)
