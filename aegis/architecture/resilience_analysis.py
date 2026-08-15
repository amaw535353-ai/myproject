from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .dependency_trust import (
    AuthenticationMode,
    DependencyCriticality,
    EgressDataClass,
    ThirdPartyTrustPathFact,
    TransportMode,
    VerifiedDependencyTrustAssessment,
)
from .resilience_manifest import is_sha256, validate_manifest, validate_policy, validate_upstream
from .resilience_types import (
    DependencyFailureState,
    FailureScenarioSecurityFact,
    FallbackMode,
    FallbackStrategy,
    ResilienceSecurityManifest,
    ResilienceSecurityPolicy,
    ResilienceSecurityRejectReason,
    ResilienceSecurityRequest,
    VerifiedResilienceSecurityAssessment,
    reject,
)


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


def _prioritized_scenarios(facts: list[FailureScenarioSecurityFact]) -> tuple[str, ...]:
    exposed = [item for item in facts if item.exposed]
    scenario_ids = sorted({item.scenario_id for item in exposed})
    scores = [
        (
            max(item.security_risk_score for item in exposed if item.scenario_id == scenario_id),
            scenario_id,
        )
        for scenario_id in scenario_ids
    ]
    return tuple(scenario_id for _, scenario_id in sorted(scores, key=lambda value: (-value[0], value[1])))


class DependencyFailureSecurityAnalyzer:
    def __init__(self, policy: ResilienceSecurityPolicy) -> None:
        validate_policy(policy)
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
            or not is_sha256(request.resilience_plan_sha256)
            or request.dependency_graph_sha256.casefold() != self.policy.expected_dependency_graph_sha256.casefold()
            or request.p7e_assessment_evidence_sha256.casefold() != self.policy.expected_p7e_assessment_evidence_sha256.casefold()
            or request.posture_evidence_sha256.casefold() != self.policy.expected_posture_evidence_sha256.casefold()
            or set(request.scenario_ids) != set(self.policy.required_scenario_ids)
        ):
            reject(ResilienceSecurityRejectReason.REQUEST_INVALID, "resilience request identity/evidence/scope is invalid")

        path_by_dependency, statuses = validate_upstream(self.policy, p7e_assessment, posture)
        scenarios, fallbacks, manifest_sha = validate_manifest(
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
            for fallback_id in sorted(self.policy.expected_fallback_ids_by_scenario[scenario_id]):
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
            reject(ResilienceSecurityRejectReason.DECLARED_SCENARIO_MISMATCH, "caller-declared exposed failure scenarios differ from derived evidence")
        if request.declared_max_security_risk_score != max_risk:
            reject(ResilienceSecurityRejectReason.DECLARED_RISK_MISMATCH, "caller-declared resilience security risk differs from derived evidence")

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
            prioritized_exposed_scenario_ids=_prioritized_scenarios(facts),
            scenarios=tuple(facts),
            assessment_evidence_sha256=assessment_sha,
        )
