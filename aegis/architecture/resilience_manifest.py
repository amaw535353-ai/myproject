from __future__ import annotations

import hashlib
import hmac
import json
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .dependency_trust import ThirdPartyTrustPathFact, VerifiedDependencyTrustAssessment
from .resilience_types import (
    FallbackMode,
    FallbackStrategy,
    P7F_RESILIENCE_MANIFEST_SCHEMA_VERSION,
    ResilienceSecurityManifest,
    ResilienceSecurityPolicy,
    ResilienceSecurityRejectReason,
    ResilienceSecurityRequest,
    DependencyFailureScenario,
    reject,
)


def is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


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


def validate_policy(policy: ResilienceSecurityPolicy) -> None:
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
        or not all(is_sha256(value) for value in hashes)
        or not policy.required_scenario_ids
        or not policy.required_fallback_ids
        or not policy.trusted_owner_ids
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
    ):
        reject(ResilienceSecurityRejectReason.POLICY_INVALID, "resilience security policy metadata is invalid")
    scenario_maps = (
        policy.expected_dependency_by_scenario,
        policy.expected_failure_state_by_scenario,
        policy.expected_required_control_ids_by_scenario,
        policy.expected_fallback_ids_by_scenario,
    )
    if any(set(mapping) != set(policy.required_scenario_ids) for mapping in scenario_maps):
        reject(ResilienceSecurityRejectReason.POLICY_INVALID, "scenario policy maps must exactly cover required scenarios")
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
        reject(ResilienceSecurityRejectReason.POLICY_INVALID, "fallback policy maps must exactly cover required fallbacks")
    covered_fallbacks: set[str] = set()
    for scenario_id, fallback_ids in policy.expected_fallback_ids_by_scenario.items():
        if not fallback_ids:
            reject(ResilienceSecurityRejectReason.POLICY_INVALID, "every failure scenario requires at least one fallback")
        for fallback_id in fallback_ids:
            if fallback_id not in policy.required_fallback_ids or policy.expected_scenario_by_fallback.get(fallback_id) != scenario_id:
                reject(ResilienceSecurityRejectReason.POLICY_INVALID, "scenario-to-fallback policy mapping is inconsistent")
            if fallback_id in covered_fallbacks:
                reject(ResilienceSecurityRejectReason.POLICY_INVALID, "a fallback cannot be assigned to multiple scenarios")
            covered_fallbacks.add(fallback_id)
    if covered_fallbacks != set(policy.required_fallback_ids):
        reject(ResilienceSecurityRejectReason.POLICY_INVALID, "scenario fallback coverage is incomplete")
    if any(value < 0 for value in policy.max_retry_attempts_by_fallback.values()):
        reject(ResilienceSecurityRejectReason.POLICY_INVALID, "retry bounds cannot be negative")
    if any(value < 0 for value in policy.max_cache_age_seconds_by_fallback.values()):
        reject(ResilienceSecurityRejectReason.POLICY_INVALID, "cache-age bounds cannot be negative")


def validate_upstream(
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
        reject(ResilienceSecurityRejectReason.P7E_ASSESSMENT_UNVERIFIED, "P7-E dependency trust evidence is not fully verified")
    if (
        p7e.dependency_graph_sha256.casefold() != policy.expected_dependency_graph_sha256.casefold()
        or p7e.assessment_evidence_sha256.casefold() != policy.expected_p7e_assessment_evidence_sha256.casefold()
        or p7e.posture_evidence_sha256.casefold() != policy.expected_posture_evidence_sha256.casefold()
        or p7e.control_catalog_sha256.casefold() != policy.expected_control_catalog_sha256.casefold()
    ):
        reject(ResilienceSecurityRejectReason.P7E_ASSESSMENT_MISMATCH, "P7-E assessment identity does not match resilience policy")
    path_by_dependency: dict[str, ThirdPartyTrustPathFact] = {}
    for path in p7e.paths:
        if path.dependency_id in path_by_dependency:
            reject(ResilienceSecurityRejectReason.P7E_DEPENDENCY_PATH_AMBIGUOUS, "P7-E contains multiple trust paths for one dependency")
        path_by_dependency[path.dependency_id] = path

    if (
        not posture.exact_release_identity_verified
        or not posture.exact_upstream_evidence_binding_verified
        or not posture.control_catalog_verified
        or not posture.status_derived_from_evidence
    ):
        reject(ResilienceSecurityRejectReason.POSTURE_UNVERIFIED, "P6-D posture evidence is not fully verified")
    if posture.posture_evidence_sha256.casefold() != policy.expected_posture_evidence_sha256.casefold():
        reject(ResilienceSecurityRejectReason.POSTURE_DIGEST_MISMATCH, "P6-D posture digest does not match resilience policy")
    if posture.control_catalog_sha256.casefold() != policy.expected_control_catalog_sha256.casefold():
        reject(ResilienceSecurityRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog does not match resilience policy")
    statuses: dict[str, ControlStatus] = {}
    for assessment in posture.assessments:
        if assessment.control_id in statuses or not isinstance(assessment.status, ControlStatus):
            reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control evidence is duplicate or malformed", control_id=assessment.control_id)
        statuses[assessment.control_id] = assessment.status
    if set(posture.satisfied_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.SATISFIED}:
        reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D satisfied-control summary is inconsistent")
    if set(posture.exceptioned_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.EXCEPTIONED}:
        reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D exception summary is inconsistent")
    if set(posture.not_evaluated_control_ids) != {key for key, value in statuses.items() if value == ControlStatus.NOT_EVALUATED}:
        reject(ResilienceSecurityRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D not-evaluated summary is inconsistent")
    return path_by_dependency, statuses


def validate_manifest(
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
        or not is_sha256(manifest.dependency_graph_sha256)
        or not is_sha256(manifest.p7e_assessment_evidence_sha256)
    ):
        reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience manifest metadata is invalid")
    actual_sha = resilience_security_manifest_digest(manifest)
    if (
        not hmac.compare_digest(actual_sha, policy.expected_resilience_plan_sha256.casefold())
        or not hmac.compare_digest(actual_sha, request.resilience_plan_sha256.casefold())
    ):
        reject(ResilienceSecurityRejectReason.MANIFEST_DIGEST_MISMATCH, "resilience plan digest does not match request/policy")
    if manifest.resilience_plan_id != policy.expected_resilience_plan_id or manifest.version != policy.expected_resilience_plan_version:
        reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience plan identity/version does not match policy")
    if manifest.dependency_graph_sha256.casefold() != policy.expected_dependency_graph_sha256.casefold():
        reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience plan dependency graph binding differs from policy")
    if manifest.p7e_assessment_evidence_sha256.casefold() != policy.expected_p7e_assessment_evidence_sha256.casefold():
        reject(ResilienceSecurityRejectReason.MANIFEST_INVALID, "resilience plan P7-E evidence binding differs from policy")
    age = request.evaluated_at_epoch - manifest.created_at_epoch
    if age > policy.max_manifest_age_seconds:
        reject(ResilienceSecurityRejectReason.MANIFEST_STALE, "resilience manifest is stale")
    if age < -policy.max_future_skew_seconds:
        reject(ResilienceSecurityRejectReason.MANIFEST_FUTURE, "resilience manifest timestamp is too far in the future")

    scenarios: dict[str, DependencyFailureScenario] = {}
    for item in manifest.scenarios:
        if item.scenario_id in scenarios:
            reject(ResilienceSecurityRejectReason.SCENARIO_DUPLICATE, "duplicate failure scenario ID", scenario_id=item.scenario_id)
        scenarios[item.scenario_id] = item
    if set(scenarios) != set(policy.required_scenario_ids):
        reject(ResilienceSecurityRejectReason.SCENARIO_COVERAGE_MISMATCH, "failure scenario coverage differs from policy")
    for scenario_id, item in scenarios.items():
        if item.owner_id not in policy.trusted_owner_ids:
            reject(ResilienceSecurityRejectReason.SCENARIO_OWNER_UNTRUSTED, "failure scenario owner is untrusted", scenario_id=scenario_id)
        if item.dependency_id not in path_by_dependency:
            reject(ResilienceSecurityRejectReason.SCENARIO_DEPENDENCY_UNKNOWN, "failure scenario references dependency not present in P7-E evidence", scenario_id=scenario_id)
        if item.dependency_id != policy.expected_dependency_by_scenario[scenario_id]:
            reject(ResilienceSecurityRejectReason.SCENARIO_DEPENDENCY_DRIFT, "failure scenario dependency differs from policy", scenario_id=scenario_id)
        if item.failure_state != policy.expected_failure_state_by_scenario[scenario_id]:
            reject(ResilienceSecurityRejectReason.SCENARIO_STATE_DRIFT, "failure scenario state differs from policy", scenario_id=scenario_id)
        if set(item.required_control_ids) != set(policy.expected_required_control_ids_by_scenario[scenario_id]):
            reject(ResilienceSecurityRejectReason.SCENARIO_CONTROL_DRIFT, "failure scenario controls differ from policy", scenario_id=scenario_id)
        for control_id in item.required_control_ids:
            if control_id not in statuses:
                reject(ResilienceSecurityRejectReason.SCENARIO_CONTROL_UNKNOWN, "failure scenario references unknown control", scenario_id=scenario_id, control_id=control_id)

    fallbacks: dict[str, FallbackStrategy] = {}
    actual_fallbacks_by_scenario: dict[str, set[str]] = {scenario_id: set() for scenario_id in scenarios}
    for item in manifest.fallbacks:
        if item.fallback_id in fallbacks:
            reject(ResilienceSecurityRejectReason.FALLBACK_DUPLICATE, "duplicate fallback ID", fallback_id=item.fallback_id)
        fallbacks[item.fallback_id] = item
    if set(fallbacks) != set(policy.required_fallback_ids):
        reject(ResilienceSecurityRejectReason.FALLBACK_COVERAGE_MISMATCH, "fallback coverage differs from policy")
    for fallback_id, item in fallbacks.items():
        if item.owner_id not in policy.trusted_owner_ids:
            reject(ResilienceSecurityRejectReason.FALLBACK_OWNER_UNTRUSTED, "fallback owner is untrusted", fallback_id=fallback_id)
        scenario = scenarios.get(item.scenario_id)
        if scenario is None:
            reject(ResilienceSecurityRejectReason.FALLBACK_SCENARIO_UNKNOWN, "fallback references unknown scenario", fallback_id=fallback_id)
        if item.scenario_id != policy.expected_scenario_by_fallback[fallback_id]:
            reject(ResilienceSecurityRejectReason.FALLBACK_SCENARIO_DRIFT, "fallback scenario binding differs from policy", fallback_id=fallback_id)
        actual_fallbacks_by_scenario[item.scenario_id].add(fallback_id)
        if item.mode != policy.expected_mode_by_fallback[fallback_id]:
            reject(ResilienceSecurityRejectReason.FALLBACK_MODE_DRIFT, "fallback mode differs from policy", fallback_id=fallback_id)
        if item.target_dependency_id != policy.expected_target_dependency_by_fallback[fallback_id]:
            reject(ResilienceSecurityRejectReason.FALLBACK_TARGET_DRIFT, "fallback target dependency differs from policy", fallback_id=fallback_id)
        if item.target_dependency_id is not None and item.target_dependency_id not in path_by_dependency:
            reject(ResilienceSecurityRejectReason.FALLBACK_TARGET_UNKNOWN, "fallback target dependency is absent from P7-E evidence", fallback_id=fallback_id)
        if set(item.preserved_control_ids) != set(policy.expected_preserved_control_ids_by_fallback[fallback_id]):
            reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_DRIFT, "fallback preserved controls differ from policy", fallback_id=fallback_id)
        if set(item.disabled_control_ids) != set(policy.expected_disabled_control_ids_by_fallback[fallback_id]):
            reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_DRIFT, "fallback disabled controls differ from policy", fallback_id=fallback_id)
        if set(item.preserved_control_ids) & set(item.disabled_control_ids):
            reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_OVERLAP, "a control cannot be both preserved and disabled", fallback_id=fallback_id)
        if set(scenario.required_control_ids) != set(item.preserved_control_ids) | set(item.disabled_control_ids):
            reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_COVERAGE_MISMATCH, "fallback must account for every required scenario control", fallback_id=fallback_id)
        for control_id in tuple(item.preserved_control_ids) + tuple(item.disabled_control_ids):
            if control_id not in statuses:
                reject(ResilienceSecurityRejectReason.FALLBACK_CONTROL_UNKNOWN, "fallback references unknown control", fallback_id=fallback_id, control_id=control_id)
        if not set(item.egress_data_classes).issubset(policy.allowed_data_classes_by_fallback[fallback_id]):
            reject(ResilienceSecurityRejectReason.FALLBACK_DATA_SCOPE_MISMATCH, "fallback data scope exceeds policy", fallback_id=fallback_id)
        if not set(item.secret_ids).issubset(policy.allowed_secret_ids_by_fallback[fallback_id]):
            reject(ResilienceSecurityRejectReason.FALLBACK_SECRET_SCOPE_MISMATCH, "fallback secret scope exceeds policy", fallback_id=fallback_id)
        if item.retry_attempts < 0 or item.retry_attempts > policy.max_retry_attempts_by_fallback[fallback_id]:
            reject(ResilienceSecurityRejectReason.RETRY_BOUND_EXCEEDED, "fallback retry attempts exceed policy", fallback_id=fallback_id)
        if item.cached_at_epoch is not None and item.cached_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
            reject(ResilienceSecurityRejectReason.CACHE_TIMESTAMP_INVALID, "fallback cache timestamp is too far in the future", fallback_id=fallback_id)

        if item.mode == FallbackMode.FAIL_CLOSED:
            if item.target_dependency_id is not None or item.retry_attempts != 0 or item.cached_at_epoch is not None or item.egress_data_classes or item.secret_ids or item.disabled_control_ids:
                reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "fail-closed fallback cannot transmit, retry, cache, target another dependency, or disable controls", fallback_id=fallback_id)
        elif item.mode == FallbackMode.RETRY_PRIMARY:
            if item.target_dependency_id != scenario.dependency_id or item.retry_attempts <= 0 or item.cached_at_epoch is not None:
                reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "retry-primary fallback must target the primary dependency with bounded retries and no cache", fallback_id=fallback_id)
        elif item.mode == FallbackMode.ALTERNATE_DEPENDENCY:
            if item.target_dependency_id is None or item.target_dependency_id == scenario.dependency_id or item.retry_attempts != 0 or item.cached_at_epoch is not None:
                reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "alternate-dependency fallback must target a different P7-E dependency with no retry/cache fields", fallback_id=fallback_id)
        elif item.mode == FallbackMode.LOCAL_SAFE_MODE:
            if item.target_dependency_id is not None or item.retry_attempts != 0 or item.cached_at_epoch is not None or item.secret_ids:
                reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "local safe mode cannot target external dependency, retry, cache, or consume secrets", fallback_id=fallback_id)
        elif item.mode == FallbackMode.CACHE_FALLBACK:
            if item.target_dependency_id is not None or item.retry_attempts != 0 or item.cached_at_epoch is None:
                reject(ResilienceSecurityRejectReason.FALLBACK_SHAPE_INVALID, "cache fallback requires a cache timestamp and cannot target/retry an external dependency", fallback_id=fallback_id)

    for scenario_id, expected_ids in policy.expected_fallback_ids_by_scenario.items():
        if actual_fallbacks_by_scenario[scenario_id] != set(expected_ids):
            reject(ResilienceSecurityRejectReason.SCENARIO_FALLBACK_COVERAGE_MISMATCH, "scenario fallback coverage differs from policy", scenario_id=scenario_id)
    return scenarios, fallbacks, actual_sha
