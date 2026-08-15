from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .dependency_trust import (
    AuthenticationMode,
    DependencyCriticality,
    EgressDataClass,
    ThirdPartyTrustPathFact,
    TransportMode,
    VerifiedDependencyTrustAssessment,
)


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


def _reject(reason: ResilienceSecurityRejectReason, message: str, **context: str | None) -> None:
    raise ResilienceSecurityRejected(reason, message, **context)


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


def _transport_rank(value: TransportMode) -> int:
    return {
        TransportMode.PLAINTEXT: 0,
        TransportMode.TLS: 1,
        TransportMode.MTLS: 2,
        TransportMode.PRIVATE_LINK: 3,
    }[value]


def _authentication_rank(value: AuthenticationMode) -> int:
    return {
        AuthenticationMode.NONE: 0,
        AuthenticationMode.API_KEY: 1,
        AuthenticationMode.OAUTH2: 2,
        AuthenticationMode.SIGNED_REQUEST: 3,
        AuthenticationMode.MTLS: 4,
    }[value]


def _data_rank(value: EgressDataClass) -> int:
    return {
        EgressDataClass.PUBLIC: 1,
        EgressDataClass.INTERNAL: 2,
        EgressDataClass.CONFIDENTIAL: 3,
        EgressDataClass.RESTRICTED: 4,
        EgressDataClass.SECRET: 5,
    }[value]


def canonical_resilience_security_manifest_bytes(manifest: ResilienceSecurityManifest) -> bytes:
    document = {
        "created_at_epoch": manifest.created_at_epoch,
        "dependency_graph_sha256": manifest.dependency_graph_sha256.casefold(),
        "fallbacks": [
            {
                "cached_at_epoch": item.cached_at_epoch,
                "description": item.description,
                "disabled_control_ids": sorted(item.disabled_control_ids),
                "egress_data_classes": sorted(value.value for value in item.egress_data_classes),
                "fallback_id": item.fallback_id,
                "mode": item.mode.value,
                "owner_id": item.owner_id,
                "preserved_control_ids": sorted(item.preserved_control_ids),
                "retry_attempts": item.retry_attempts,
                "scenario_id": item.scenario_id,
                "secret_ids": sorted(item.secret_ids),
                "target_dependency_id": item.target_dependency_id,
            }
            for item in sorted(manifest.fallbacks, key=lambda value: value.fallback_id)
        ],
        "p7e_assessment_evidence_sha256": manifest.p7e_assessment_evidence_sha256.casefold(),
        "resilience_plan_id": manifest.resilience_plan_id,
        "scenarios": [
            {
                "dependency_id": item.dependency_id,
                "description": item.description,
                "failure_state": item.failure_state.value,
                "owner_id": item.owner_id,
                "required_control_ids": sorted(item.required_control_ids),
                "scenario_id": item.scenario_id,
            }
            for item in sorted(manifest.scenarios, key=lambda value: value.scenario_id)
        ],
        "schema_version": manifest.schema_version,
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def resilience_security_manifest_digest(manifest: ResilienceSecurityManifest) -> str:
    return hashlib.sha256(canonical_resilience_security_manifest_bytes(manifest)).hexdigest()


def _validate_policy(policy: ResilienceSecurityPolicy) -> None:
    hashes = (
        policy.expected_resilience_plan_sha256,
        policy.expected_dependency_graph_sha256,
        policy.expected_p7e_assessment_evidence_sha256,
        policy.expected_posture_evidence_sha256,
        policy.expected_control_catalog_sha256,
    )
    if (
        not policy.expected_resilience_plan_id
        or not policy.expected_resilience_plan_version
        or not all(_is_sha256(value) for value in hashes)
        or not policy.required_scenario_ids
        or not policy.required_fallback_ids
        or not policy.trusted_owner_ids
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
    ):
        _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "resilience security policy metadata is invalid")
    scenario_maps = (
        policy.expected_dependency_by_scenario,
        policy.expected_failure_state_by_scenario,
        policy.expected_required_control_ids_by_scenario,
        policy.expected_fallback_ids_by_scenario,
    )
    if any(set(mapping) != set(policy.required_scenario_ids) for mapping in scenario_maps):
        _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "scenario policy maps must exactly cover required scenarios")
    fallback_maps = (
        policy.expected_scenario_by_fallback,
        policy.expected_mode_by_fallback,
        policy.expected_target_dependency_by_fallback,
        policy.expected_preserved_control_ids_by_fallback,
        policy.expected_disabled_control_ids_by_fallback,
        policy.allowed_data_classes_by_fallback,
        policy.allowed_secret_ids_by_fallback,
        policy.max_retry_attempts_by_fallback,
        policy.max_cache_age_seconds_by_fallback,
    )
    if any(set(mapping) != set(policy.required_fallback_ids) for mapping in fallback_maps):
        _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "fallback policy maps must exactly cover required fallbacks")
    covered_fallbacks: set[str] = set()
    for scenario_id, fallback_ids in policy.expected_fallback_ids_by_scenario.items():
        if not fallback_ids:
            _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "every failure scenario requires at least one fallback")
        for fallback_id in fallback_ids:
            if fallback_id not in policy.required_fallback_ids or policy.expected_scenario_by_fallback.get(fallback_id) != scenario_id:
                _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "scenario-to-fallback policy mapping is inconsistent")
            if fallback_id in covered_fallbacks:
                _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "a fallback cannot be assigned to multiple scenarios")
            covered_fallbacks.add(fallback_id)
    if covered_fallbacks != set(policy.required_fallback_ids):
        _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "scenario fallback coverage is incomplete")
    if any(value < 0 for value in policy.max_retry_attempts_by_fallback.values()):
        _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "retry bounds cannot be negative")
    if any(value < 0 for value in policy.max_cache_age_seconds_by_fallback.values()):
        _reject(ResilienceSecurityRejectReason.POLICY_INVALID, "cache-age bounds cannot be negative")


def _validate_upstream(
    policy: ResilienceSecurityPolicy,
    p7e: VerifiedDependencyTrustAssessment,
    posture: VerifiedSecurityPosture,
) -> tuple[dict[str, ThirdPartyTrustPathFact], dict[str, ControlStatus]]:
    if (
        not p7e.exact_dependency_graph_binding_verified
        or not p7e.exact_architecture_binding_verified
        or not p7e.exact_p7a_assessment_binding_verified
        or not p7e.exact_p7b_assessment_binding_verified
        or not p7e.exact_p7c_assessment_binding_verified
        or not p7e.exact_p7d_assessment_binding_verified
        or not p7e.exact_p6d_posture_binding_verified
        or not p7e.destination_identity_policy_pinned
        or not p7e.transport_auth_policy_pinned
        or not p7e.egress_scope_policy_pinned
        or not p7e.fail_closed_policy_pinned
        or not p7e.risk_derived_from_evidence
    ):
        _reject(ResilienceSecurityRejectReason.P7E_ASSESSMENT_UNVERIFIED, "P7-E dependency trust evidence is not fully verified")
    if (
        p7e.dependency_graph_sha256.casefold() != policy.expected_dependency_graph_sha256.casefold()
        or p7e.assessment_evidence_sha256.casefold() != policy.expected_p7e_assessment_evidence_sha256.casefold()
        or p7e.posture_evidence_sha256.casefold() != policy.expected_posture_evidence_sha256.casefold()
        or p7e.control_catalog_sha256.casefold() != policy.expected_control_catalog_sha256.casefold()
    ):
        _reject(ResilienceSecurityRejectReason.P7E_ASSESSMENT_MISMATCH, "P7-E assessment identity does not match resilience policy")
    path_by_dependency: dict[str, ThirdPartyTrustPathFact] = {}
    for path in p7e.paths:
        if path.dependency_id in path_by_dependency:
            _reject(ResilienceSecurityRejectReason.P7E_DEPENDENCY_PATH_AMBIGUOUS, "P7-E contains multiple trust paths for one dependency")
        path_by_dependency[path.dependency_id] = path

    if (
        not posture.exact_release_identity_verified
        or not posture.exact_upstream_evidence_binding_verified
        or not posture.control_catalog_verified
        or not posture.status_derived_from_evidence
    ):
        _reject(ResilienceSecurityRejectReason.POSTURE_UNVERIFIED, "P6-D posture evidence is not fully verified")
    if posture.posture_evidence_sha256.casefold() != policy.expected_posture_evidence_sha256.casefold():
        _reject(ResilienceSecurityRejectReason.POSTURE_DIGEST_MISMATCH, "P6-D posture digest does not match resilience policy")
    if posture.control_catalog_sha256.casefold() != policy.expected_control_catalog_sha256.casefold():
        _reject(ResilienceSecurityRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog does not match resilience policy")
    statuses: dict[str, ControlStatus] = {}
    for assessment in posture.assessments:
        if assessment.control_id in statuses or not isinstance(assessment.status, ControlStatus):
            _reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control evidence is duplicate or malformed", control_id=assessment.control_id)
        statuses[assessment.control_id] = assessment.status
    if set(posture.satisfied_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.SATISFIED}:
        _reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D satisfied-control summary is inconsistent")
    if set(posture.exceptioned_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.EXCEPTIONED}:
        _reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D exception summary is inconsistent")
    if set(posture.not_evaluated_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.NOT_EVALUATED}:
        _reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D not-evaluated summary is inconsistent")
    return path_by_dependency, statuses


def _validate_manifest(
    policy: ResilienceSecurityPolicy,
    request: ResilienceSecurityRequest,
    manifest: ResilienceSecurityManifest,
    path_by_dependency: Mapping[str, ThirdPartyTrustPathFact],
    statuses: Mapping[str, ControlStatus],
) -> tuple[dict[str, DependencyFailureScenario], dict[str, FallbackStrategy], str]:
    if (
        manifest.schema_version != P7F_RESILIENCE_MANIFEST_SCHEMA_VERSION
        or not manifest.resilience_plan_id
        or not manifest.version
        or not _is_sha256(manifest.dependency_graph_sha256)
        or not _is_sha256(manifest.p7e_assessment_evidence_sha256)
    ):
        _reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience manifest metadata is invalid")
    actual_sha = resilience_security_manifest_digest(manifest)
    if (
        not hmac.compare_digest(actual_sha, policy.expected_resilience_plan_sha256.casefold())
        or not hmac.compare_digest(actual_sha, request.resilience_plan_sha256.casefold())
    ):
        _reject(ResilienceSecurityRejectReason.MANIFEST_DIGEST_MISMATCH, "resilience plan digest does not match request/policy")
    if manifest.resilience_plan_id != policy.expected_resilience_plan_id or manifest.version != policy.expected_resilience_plan_version:
        _reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience plan identity/version does not match policy")
    if manifest.dependency_graph_sha256.casefold() != policy.expected_dependency_graph_sha256.casefold():
        _reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience plan dependency graph binding differs from policy")
    if manifest.p7e_assessment_evidence_sha256.casefold() != policy.expected_p7e_assessment_evidence_sha256.casefold():
        _reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience plan P7-E evidence binding differs from policy")
    age = request.evaluated_at_epoch - manifest.created_at_epoch
    if age > policy.max_manifest_age_seconds:
        _reject(ResilienceSecurityRejectReason.MANIFEST_STALE, "resilience manifest is stale")
    if age < -policy.max_future_skew_seconds:
        _reject(ResilienceSecurityRejectReason.MANIFEST_FUTURE, "resilience manifest timestamp is too far in the future")

    scenarios: dict[str, DependencyFailureScenario] = {}
    for item in manifest.scenarios:
        if item.scenario_id in scenarios:
            _reject(ResilienceSecurityRejectReason.SCENARIO_DUPLICATE, "duplicate failure scenario ID", scenario_id=item.scenario_id)
        scenarios[item.scenario_id] = item
    if set(scenarios) != set(policy.required_scenario_ids):
        _reject(ResilienceSecurityRejectReason.SCENARIO_COVERAGE_MISMATCH, "failure scenario coverage differs from policy")
    for scenario_id, item in scenarios.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(ResilienceSecurityRejectReason.SCENARIO_OWNER_UNTRUSTED, "failure scenario owner is untrusted", scenario_id=scenario_id)
        if item.dependency_id not in path_by_dependency:
            _reject(ResilienceSecurityRejectReason.SCENARIO_DEPENDENCY_UNKNOWN, "failure scenario references dependency not present in P7-E evidence", scenario_id=scenario_id)
        if item.dependency_id != policy.expected_dependency_by_scenario[scenario_id]:
            _reject(ResilienceSecurityRejectReason.SCENARIO_DEPENDENCY_DRIFT, "failure scenario dependency differs from policy", scenario_id=scenario_id)
        if item.failure_state != policy.expected_failure_state_by_scenario[scenario_id]:
            _reject(ResilienceSecurityRejectReason.SCENARIO_STATE_DRIFT, "failure scenario state differs from policy", scenario_id=scenario_id)
        if set(item.required_control_ids) != set(policy.expected_required_control_ids_by_scenario[scenario_id]):
            _reject(ResilienceSecurityRejectReason.SCENARIO_CONTROL_DRIFT, "failure scenario controls differ from policy", scenario_id=scenario_id)
        for control_id in item.required_control_ids:
            if control_id not in statuses:
                _reject(ResilienceSecurityRejectReason.SCENARIO_CONTROL_UNKNOWN, "failure scenario references unknown control", scenario_id=scenario_id, control_id=control_id)

    fallbacks: dict[str, FallbackStrategy] = {}
    actual_fallbacks_by_scenario: dict[str, set[str]] = {scenario_id: set() for scenario_id in scenarios}
    for item in manifest.fallbacks:
        if item.fallback_id in fallbacks:
            _reject(ResilienceSecurityRejectReason.FALLBACK_DUPLICATE, "duplicate fallback ID", fallback_id=item.fallback_id)
        fallbacks[item.fallback_id] = item
    if set(fallbacks) != set(policy.required_fallback_ids):
        _reject(ResilienceSecurityRejectReason.FALLBACK_COVERAGE_MISMATCH, "fallback coverage differs from policy")
    for fallback_id, item in fallbacks.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(ResilienceSecurityRejectReason.FALLBACK_OWNER_UNTRUSTED, "fallback owner is untrusted", fallback_id=fallback_id)
        scenario = scenarios.get(item.scenario_id)
        if scenario is None:
            _reject(ResilienceSecurityRejectReason.FALLBACK_SCENARIO_UNKNOWN, "fallback references unknown scenario", fallback_id=fallback_id)
        if item.scenario_id != policy.expected_scenario_by_fallback[fallback_id]:
            _reject(ResilienceSecurityRejectReason.FALLBACK_SCENARIO_DRIFT, "fallback scenario binding differs from policy", fallback_id=fallback_id)
        actual_fallbacks_by_scenario[item.scenario_id].add(fallback_id)
        if item.mode != policy.expected_mode_by_fallback[fallback_id]:
            _reject(ResilienceSecurityRejectReason.FALLBACK_MODE_DRIFT, "fallback mode differs from policy", fallback_id=fallback_id)
        if item.target_dependency_id != policy.expected_target_dependency_by_fallback[fallback_id]:
            _reject(ResilienceSecurityRejectReason.FALLBACK_TARGET_DRIFT, "fallback target dependency differs from policy", fallback_id=fallback_id)
        if item.target_dependency_id is not None and item.target_dependency_id not in path_by_dependency:
            _reject(ResilienceSecurityRejectReason.FALLBACK_TARGET_UNKNOWN, "fallback target dependency is absent from P7-E evidence", fallback_id=fallback_id)
        if set(item.preserved_control_ids) != set(policy.expected_preserved_control_ids_by_fallback[fallback_id]):
            _reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_DRIFT, "fallback preserved controls differ from policy", fallback_id=fallback_id)
        if set(item.disabled_control_ids) != set(policy.expected_disabled_control_ids_by_fallback[fallback_id]):
            _reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_DRIFT, "fallback disabled controls differ from policy", fallback_id=fallback_id)
        if set(item.preserved_control_ids) & set(item.disabled_control_ids):
            _reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_OVERLAP, "a control cannot be both preserved and disabled", fallback_id=fallback_id)
        if set(scenario.required_control_ids) != set(item.preserved_control_ids) | set(item.disabled_control_ids):
            _reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_COVERAGE_MISMATCH, "fallback must account for every required scenario control", fallback_id=fallback_id)
        for control_id in tuple(item.preserved_control_ids) + tuple(item.disabled_control_ids):
            if control_id not in statuses:
                _reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_UNKNOWN, "fallback references unknown control", fallback_id=fallback_id, control_id=control_id)
        if not set(item.egress_data_classes).issubset(policy.allowed_data_classes_by_fallback[fallback_id]):
            _reject(ResilienceSecurityRejectReason.FALLBACK_DATA_SCOPE_MISMATCH, "fallback data scope exceeds policy", fallback_id=fallback_id)
        if not set(item.secret_ids).issubset(policy.allowed_secret_ids_by_fallback[fallback_id]):
            _reject(ResilienceSecurityRejectReason.FALLBACK_SECRET_SCOPE_MISMATCH, "fallback secret scope exceeds policy", fallback_id=fallback_id)
        if item.retry_attempts < 0 or item.retry_attempts > policy.max_retry_attempts_by_fallback[fallback_id]:
            _reject(ResilienceSecurityRejectReason.RETRY_BOUND_EXCEEDED, "fallback retry attempts exceed policy", fallback_id=fallback_id)
        if item.cached_at_epoch is not None and item.cached_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
            _reject(ResilienceSecurityRejectReason.CACHE_TIMESTAMP_INVALID, "fallback cache timestamp is too far in the future", fallback_id=fallback_id)

        if item.mode == FallbackMode.FAIL_CLOSED:
            if item.target_dependency_id is not None or item.retry_attempts != 0 or item.cached_at_epoch is not None or item.egress_data_classes or item.secret_ids or item.disabled_control_ids:
                _reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "fail-closed fallback cannot transmit, retry, cache, target another dependency, or disable controls", fallback_id=fallback_id)
        elif item.mode == FallbackMode.RETRY_PRIMARY:
            if item.target_dependency_id != scenario.dependency_id or item.retry_attempts <= 0 or item.cached_at_epoch is not None:
                _reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "retry-primary fallback must target the primary dependency with bounded retries and no cache", fallback_id=fallback_id)
        elif item.mode == FallbackMode.ALTERNATE_DEPENDENCY:
            if item.target_dependency_id is None or item.target_dependency_id == scenario.dependency_id or item.retry_attempts != 0 or item.cached_at_epoch is not None:
                _reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "alternate-dependency fallback must target a different P7-E dependency with no retry/cache fields", fallback_id=fallback_id)
        elif item.mode == FallbackMode.LOCAL_SAFE_MODE:
            if item.target_dependency_id is not None or item.retry_attempts != 0 or item.cached_at_epoch is not None or item.secret_ids:
                _reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "local safe mode cannot target external dependency, retry, cache, or consume secrets", fallback_id=fallback_id)
        elif item.mode == FallbackMode.CACHE_FALLBACK:
            if item.target_dependency_id is not None or item.retry_attempts != 0 or item.cached_at_epoch is None:
                _reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "cache fallback requires a cache timestamp and cannot target/retry an external dependency", fallback_id=fallback_id)

    for scenario_id, expected_ids in policy.expected_fallback_ids_by_scenario.items():
        if actual_fallbacks_by_scenario[scenario_id] != set(expected_ids):
            _reject(ResilienceSecurityRejectReason.SCENARIO_FALLBACK_COVERAGE_MISMATCH, "scenario fallback coverage differs from policy", scenario_id=scenario_id)
    return scenarios, fallbacks, actual_sha


def _risk_score(
    primary: ThirdPartyTrustPathFact,
    fallback: FallbackStrategy,
    exceptioned: tuple[str, ...],
    not_evaluated: tuple[str, ...],
    reasons: tuple[str, ...],
) -> int:
    score = _criticality_rank(primary.criticality) * 18
    if fallback.secret_ids:
        score += 18
    if fallback.egress_data_classes:
        max_data = max(_data_rank(value) for value in fallback.egress_data_classes)
        score += max(0, max_data - 2) * 7
    score += len(fallback.disabled_control_ids) * 20
    score += len(exceptioned) * 14 + len(not_evaluated) * 12
    if "alternate_dependency_exposed" in reasons:
        score += 24
    if "alternate_transport_weaker" in reasons or "alternate_authentication_weaker" in reasons:
        score += 18
    if "retrying_untrusted_primary" in reasons:
        score += 30
    if "stale_cache_fallback" in reasons:
        score += 20
    return score


class DependencyFailureSecurityAnalyzer:
    def __init__(self, policy: ResilienceSecurityPolicy) -> None:
        _validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: ResilienceSecurityRequest,
        manifest: ResilienceSecurityManifest,
        p7e_assessment: VerifiedDependencyTrustAssessment,
        posture: VerifiedSecurityPosture,
    ) -> VerifiedResilienceSecurityAssessment:
        if (
            request.resilience_plan_id != self.policy.expected_resilience_plan_id
            or request.resilience_plan_version != self.policy.expected_resilience_plan_version
            or not _is_sha256(request.resilience_plan_sha256)
            or request.dependency_graph_sha256.casefold() != self.policy.expected_dependency_graph_sha256.casefold()
            or request.p7e_assessment_evidence_sha256.casefold() != self.policy.expected_p7e_assessment_evidence_sha256.casefold()
            or request.posture_evidence_sha256.casefold() != self.policy.expected_posture_evidence_sha256.casefold()
            or set(request.scenario_ids) != set(self.policy.required_scenario_ids)
        ):
            _reject(ResilienceSecurityRejectReason.REQUEST_INVALID, "resilience request identity/evidence/scope is invalid")

        path_by_dependency, statuses = _validate_upstream(self.policy, p7e_assessment, posture)
        scenarios, fallbacks, manifest_sha = _validate_manifest(
            self.policy,
            request,
            manifest,
            path_by_dependency,
            statuses,
        )

        facts: list[FailureScenarioSecurityFact] = []
        for scenario_id in sorted(scenarios):
            scenario = scenarios[scenario_id]
            primary = path_by_dependency[scenario.dependency_id]
            fallback_ids = sorted(self.policy.expected_fallback_ids_by_scenario[scenario_id])
            for fallback_id in fallback_ids:
                fallback = fallbacks[fallback_id]
                preserved = tuple(sorted(fallback.preserved_control_ids))
                disabled = tuple(sorted(fallback.disabled_control_ids))
                satisfied = tuple(control_id for control_id in preserved if statuses[control_id] == ControlStatus.SATISFIED)
                exceptioned = tuple(control_id for control_id in preserved if statuses[control_id] == ControlStatus.EXCEPTIONED)
                not_evaluated = tuple(control_id for control_id in preserved if statuses[control_id] == ControlStatus.NOT_EVALUATED)
                reasons: list[str] = []
                cache_age: int | None = None

                if disabled:
                    reasons.append("required_security_control_disabled")
                if fallback.mode != FallbackMode.FAIL_CLOSED:
                    if exceptioned:
                        reasons.append("exceptioned_fallback_control")
                    if not_evaluated:
                        reasons.append("not_evaluated_fallback_control")

                if fallback.mode == FallbackMode.RETRY_PRIMARY and scenario.failure_state == DependencyFailureState.UNTRUSTED:
                    reasons.append("retrying_untrusted_primary")
                if fallback.mode == FallbackMode.ALTERNATE_DEPENDENCY:
                    alternate = path_by_dependency[fallback.target_dependency_id or ""]
                    if alternate.exposed:
                        reasons.append("alternate_dependency_exposed")
                    if _transport_rank(alternate.transport_mode) < _transport_rank(primary.transport_mode):
                        reasons.append("alternate_transport_weaker")
                    if _authentication_rank(alternate.authentication_mode) < _authentication_rank(primary.authentication_mode):
                        reasons.append("alternate_authentication_weaker")
                if fallback.mode == FallbackMode.CACHE_FALLBACK:
                    cache_age = request.evaluated_at_epoch - int(fallback.cached_at_epoch or 0)
                    if cache_age < 0:
                        reasons.append("future_cache_material")
                    elif cache_age > self.policy.max_cache_age_seconds_by_fallback[fallback_id]:
                        reasons.append("stale_cache_fallback")

                service_continuity = fallback.mode != FallbackMode.FAIL_CLOSED
                exposed = bool(reasons)
                security_preserved = not exposed
                risk = _risk_score(primary, fallback, exceptioned, not_evaluated, tuple(reasons)) if exposed else 0
                facts.append(
                    FailureScenarioSecurityFact(
                        scenario_id=scenario_id,
                        dependency_id=scenario.dependency_id,
                        failure_state=scenario.failure_state,
                        dependency_criticality=primary.criticality,
                        fallback_id=fallback_id,
                        fallback_mode=fallback.mode,
                        target_dependency_id=fallback.target_dependency_id,
                        service_continuity_expected=service_continuity,
                        preserved_control_ids=preserved,
                        disabled_control_ids=disabled,
                        satisfied_control_ids=satisfied,
                        exceptioned_control_ids=exceptioned,
                        not_evaluated_control_ids=not_evaluated,
                        egress_data_classes=tuple(sorted(value.value for value in fallback.egress_data_classes)),
                        secret_ids=tuple(sorted(fallback.secret_ids)),
                        cache_age_seconds=cache_age,
                        retry_attempts=fallback.retry_attempts,
                        security_preserved=security_preserved,
                        exposed=exposed,
                        security_risk_score=risk,
                        exposure_reasons=tuple(reasons),
                        mitigating_control_ids=satisfied,
                    )
                )

        exposed_facts = [item for item in facts if item.exposed]
        exposed_scenario_ids = tuple(sorted({item.scenario_id for item in exposed_facts}))
        max_risk = max((item.security_risk_score for item in exposed_facts), default=0)
        if set(request.declared_exposed_scenario_ids) != set(exposed_scenario_ids):
            _reject(ResilienceSecurityRejectReason.DECLARED_SCENARIO_MISMATCH, "caller-declared exposed failure scenarios differ from derived evidence")
        if request.declared_max_security_risk_score != max_risk:
            _reject(ResilienceSecurityRejectReason.DECLARED_RISK_MISMATCH, "caller-declared resilience security risk differs from derived evidence")

        scenario_exposed = {item.scenario_id for item in exposed_facts}
        critical_exposed = {
            item.scenario_id
            for item in exposed_facts
            if item.dependency_criticality == DependencyCriticality.CRITICAL
        }
        untrusted_exposed = {
            item.scenario_id
            for item in exposed_facts
            if item.failure_state == DependencyFailureState.UNTRUSTED
        }
        evidence_document = {
            "control_catalog_sha256": posture.control_catalog_sha256.casefold(),
            "dependency_graph_sha256": p7e_assessment.dependency_graph_sha256.casefold(),
            "exposed_scenario_ids": list(exposed_scenario_ids),
            "max_security_risk_score": max_risk,
            "p7e_assessment_evidence_sha256": p7e_assessment.assessment_evidence_sha256.casefold(),
            "posture_evidence_sha256": posture.posture_evidence_sha256.casefold(),
            "resilience_plan_sha256": manifest_sha,
            "scenario_facts": [asdict(item) for item in facts],
        }
        assessment_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        return VerifiedResilienceSecurityAssessment(
            resilience_plan_id=manifest.resilience_plan_id,
            resilience_plan_version=manifest.version,
            resilience_plan_sha256=manifest_sha,
            dependency_graph_sha256=p7e_assessment.dependency_graph_sha256.casefold(),
            p7e_assessment_evidence_sha256=p7e_assessment.assessment_evidence_sha256.casefold(),
            posture_evidence_sha256=posture.posture_evidence_sha256.casefold(),
            control_catalog_sha256=posture.control_catalog_sha256.casefold(),
            scenario_count=len(scenarios),
            exposed_scenario_count=len(scenario_exposed),
            controlled_scenario_count=len(scenarios) - len(scenario_exposed),
            service_continuity_scenario_count=len({item.scenario_id for item in facts if item.service_continuity_expected}),
            fail_closed_scenario_count=len({item.scenario_id for item in facts if item.fallback_mode == FallbackMode.FAIL_CLOSED}),
            critical_dependency_exposed_scenario_count=len(critical_exposed),
            untrusted_dependency_exposed_scenario_count=len(untrusted_exposed),
            max_security_risk_score=max_risk,
            prioritized_exposed_scenario_ids=tuple(
                item[1]
                for item in sorted(
                    (
                        max(fact.security_risk_score for fact in exposed_facts if fact.scenario_id == scenario_id),
                        scenario_id,
                    )
                    for scenario_id in scenario_exposed
                , key=lambda value: (-value[0], value[1]))
            ),
            scenarios=tuple(facts),
            assessment_evidence_sha256=assessment_sha,
        )
