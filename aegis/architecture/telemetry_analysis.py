from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .attack_paths import VerifiedAttackPathAssessment
from .data_types import VerifiedDataExfiltrationAssessment
from .dependency_trust import VerifiedDependencyTrustAssessment
from .privilege_types import VerifiedPrivilegeEscalationAssessment
from .resilience_types import VerifiedResilienceSecurityAssessment
from .secrets_exposure import VerifiedSecretExposureAssessment
from .telemetry_manifest import is_sha256, severity_rank, validate_manifest, validate_policy, validate_upstreams
from .telemetry_types import (
    TelemetryBlindSpotRejectReason,
    TelemetryCoverageManifest,
    TelemetryCoveragePolicy,
    TelemetryCoverageRequest,
    TelemetryRequirementFact,
    TelemetrySeverity,
    VerifiedTelemetryCoverageAssessment,
    reject,
)


def _risk_score(severity: TelemetrySeverity, reasons: tuple[str, ...], missing_fallback_count: int, dropped_field_count: int) -> int:
    score = {
        TelemetrySeverity.LOW: 20,
        TelemetrySeverity.MEDIUM: 40,
        TelemetrySeverity.HIGH: 65,
        TelemetrySeverity.CRITICAL: 85,
    }[severity]
    weights = {
        "source_signature_invalid": 25,
        "telemetry_chain_integrity_invalid": 30,
        "append_only_audit_not_acknowledged": 22,
        "alert_path_unavailable": 24,
        "detection_latency_exceeded": 14,
        "exceptioned_telemetry_control": 18,
        "not_evaluated_telemetry_control": 16,
        "fallback_observability_gap": 20,
        "required_fields_dropped": 12,
    }
    score += sum(weights.get(reason, 0) for reason in reasons)
    score += max(0, missing_fallback_count - 1) * 6
    score += max(0, dropped_field_count - 1) * 4
    return score


class SecurityTelemetryIntegrityAnalyzer:
    def __init__(self, policy: TelemetryCoveragePolicy) -> None:
        validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: TelemetryCoverageRequest,
        manifest: TelemetryCoverageManifest,
        p7a_assessment: VerifiedAttackPathAssessment,
        p7b_assessment: VerifiedPrivilegeEscalationAssessment,
        p7c_assessment: VerifiedDataExfiltrationAssessment,
        p7d_assessment: VerifiedSecretExposureAssessment,
        p7e_assessment: VerifiedDependencyTrustAssessment,
        p7f_assessment: VerifiedResilienceSecurityAssessment,
        posture: VerifiedSecurityPosture,
    ) -> VerifiedTelemetryCoverageAssessment:
        request_pins = (
            (request.p7a_assessment_evidence_sha256, self.policy.expected_p7a_assessment_evidence_sha256),
            (request.p7b_assessment_evidence_sha256, self.policy.expected_p7b_assessment_evidence_sha256),
            (request.p7c_assessment_evidence_sha256, self.policy.expected_p7c_assessment_evidence_sha256),
            (request.p7d_assessment_evidence_sha256, self.policy.expected_p7d_assessment_evidence_sha256),
            (request.p7e_assessment_evidence_sha256, self.policy.expected_p7e_assessment_evidence_sha256),
            (request.p7f_assessment_evidence_sha256, self.policy.expected_p7f_assessment_evidence_sha256),
            (request.posture_evidence_sha256, self.policy.expected_posture_evidence_sha256),
        )
        if (
            request.telemetry_plan_id != self.policy.expected_telemetry_plan_id
            or request.telemetry_plan_version != self.policy.expected_telemetry_plan_version
            or not is_sha256(request.telemetry_plan_sha256)
            or any(left.casefold() != right.casefold() for left, right in request_pins)
            or set(request.requirement_ids) != set(self.policy.required_requirement_ids)
        ):
            reject(TelemetryBlindSpotRejectReason.REQUEST_INVALID, "telemetry coverage request identity/evidence/scope is invalid")

        source_objects, statuses = validate_upstreams(
            self.policy,
            p7a_assessment,
            p7b_assessment,
            p7c_assessment,
            p7d_assessment,
            p7e_assessment,
            p7f_assessment,
            posture,
        )
        requirements, _nodes, routes, manifest_sha = validate_manifest(
            self.policy,
            request,
            manifest,
            source_objects,
            statuses,
        )
        route_by_requirement = {item.requirement_id: item for item in routes.values()}

        facts: list[TelemetryRequirementFact] = []
        for requirement_id in sorted(requirements):
            requirement = requirements[requirement_id]
            route = route_by_requirement[requirement_id]
            satisfied = tuple(sorted(control_id for control_id in route.required_control_ids if statuses[control_id] == ControlStatus.SATISFIED))
            exceptioned = tuple(sorted(control_id for control_id in route.required_control_ids if statuses[control_id] == ControlStatus.EXCEPTIONED))
            not_evaluated = tuple(sorted(control_id for control_id in route.required_control_ids if statuses[control_id] == ControlStatus.NOT_EVALUATED))
            required_fallbacks = set(self.policy.required_fallback_scenario_ids_by_requirement[requirement_id])
            covered_fallbacks = set(route.covered_fallback_scenario_ids)
            missing_fallbacks = tuple(sorted(required_fallbacks - covered_fallbacks))
            dropped_fields = tuple(sorted(route.dropped_field_ids))

            reasons: list[str] = []
            if not route.source_signature_valid:
                reasons.append("source_signature_invalid")
            if not route.chain_integrity_valid:
                reasons.append("telemetry_chain_integrity_invalid")
            if not route.append_only_acknowledged:
                reasons.append("append_only_audit_not_acknowledged")
            if requirement.requires_alert and not route.alert_path_operational:
                reasons.append("alert_path_unavailable")
            if route.observed_detection_latency_seconds > requirement.max_detection_latency_seconds:
                reasons.append("detection_latency_exceeded")
            if exceptioned:
                reasons.append("exceptioned_telemetry_control")
            if not_evaluated:
                reasons.append("not_evaluated_telemetry_control")
            if missing_fallbacks:
                reasons.append("fallback_observability_gap")
            if dropped_fields:
                reasons.append("required_fields_dropped")

            blind_spot = bool(reasons)
            risk = _risk_score(requirement.severity, tuple(reasons), len(missing_fallbacks), len(dropped_fields)) if blind_spot else 0
            facts.append(
                TelemetryRequirementFact(
                    requirement_id=requirement_id,
                    event_class=requirement.event_class,
                    severity=requirement.severity,
                    source_kind=requirement.source_kind,
                    source_object_ids=tuple(sorted(requirement.source_object_ids)),
                    route_id=route.route_id,
                    node_ids=tuple(route.node_ids),
                    satisfied_control_ids=satisfied,
                    exceptioned_control_ids=exceptioned,
                    not_evaluated_control_ids=not_evaluated,
                    covered_fallback_scenario_ids=tuple(sorted(covered_fallbacks)),
                    missing_fallback_scenario_ids=missing_fallbacks,
                    dropped_field_ids=dropped_fields,
                    source_signature_valid=route.source_signature_valid,
                    chain_integrity_valid=route.chain_integrity_valid,
                    append_only_acknowledged=route.append_only_acknowledged,
                    alert_path_operational=route.alert_path_operational,
                    observed_detection_latency_seconds=route.observed_detection_latency_seconds,
                    blind_spot=blind_spot,
                    blind_spot_risk_score=risk,
                    blind_spot_reasons=tuple(reasons),
                    mitigating_control_ids=satisfied,
                )
            )

        blind = [item for item in facts if item.blind_spot]
        prioritized = tuple(item.requirement_id for item in sorted(blind, key=lambda value: (-value.blind_spot_risk_score, value.requirement_id)))
        max_risk = max((item.blind_spot_risk_score for item in blind), default=0)
        if set(request.declared_blind_spot_requirement_ids) != set(prioritized):
            reject(TelemetryBlindSpotRejectReason.DECLARED_BLIND_SPOT_MISMATCH, "caller-declared telemetry blind spots differ from derived evidence")
        if request.declared_max_blind_spot_risk_score != max_risk:
            reject(TelemetryBlindSpotRejectReason.DECLARED_RISK_MISMATCH, "caller-declared telemetry blind-spot risk differs from derived evidence")

        integrity_reasons = {
            "source_signature_invalid",
            "telemetry_chain_integrity_invalid",
            "append_only_audit_not_acknowledged",
            "required_fields_dropped",
        }
        alerting_reasons = {"alert_path_unavailable", "detection_latency_exceeded"}
        fallback_reasons = {"fallback_observability_gap"}
        evidence_document = {
            "blind_spot_requirement_ids": list(prioritized),
            "control_catalog_sha256": str(getattr(posture, "control_catalog_sha256")).casefold(),
            "max_blind_spot_risk_score": max_risk,
            "p7a_assessment_evidence_sha256": str(getattr(p7a_assessment, "assessment_evidence_sha256")).casefold(),
            "p7b_assessment_evidence_sha256": str(getattr(p7b_assessment, "assessment_evidence_sha256")).casefold(),
            "p7c_assessment_evidence_sha256": str(getattr(p7c_assessment, "assessment_evidence_sha256")).casefold(),
            "p7d_assessment_evidence_sha256": str(getattr(p7d_assessment, "assessment_evidence_sha256")).casefold(),
            "p7e_assessment_evidence_sha256": str(getattr(p7e_assessment, "assessment_evidence_sha256")).casefold(),
            "p7f_assessment_evidence_sha256": str(getattr(p7f_assessment, "assessment_evidence_sha256")).casefold(),
            "posture_evidence_sha256": str(getattr(posture, "posture_evidence_sha256")).casefold(),
            "requirement_facts": [asdict(item) for item in facts],
            "telemetry_plan_sha256": manifest_sha,
        }
        assessment_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        return VerifiedTelemetryCoverageAssessment(
            telemetry_plan_id=manifest.telemetry_plan_id,
            telemetry_plan_version=manifest.version,
            telemetry_plan_sha256=manifest_sha,
            p7a_assessment_evidence_sha256=str(getattr(p7a_assessment, "assessment_evidence_sha256")).casefold(),
            p7b_assessment_evidence_sha256=str(getattr(p7b_assessment, "assessment_evidence_sha256")).casefold(),
            p7c_assessment_evidence_sha256=str(getattr(p7c_assessment, "assessment_evidence_sha256")).casefold(),
            p7d_assessment_evidence_sha256=str(getattr(p7d_assessment, "assessment_evidence_sha256")).casefold(),
            p7e_assessment_evidence_sha256=str(getattr(p7e_assessment, "assessment_evidence_sha256")).casefold(),
            p7f_assessment_evidence_sha256=str(getattr(p7f_assessment, "assessment_evidence_sha256")).casefold(),
            posture_evidence_sha256=str(getattr(posture, "posture_evidence_sha256")).casefold(),
            control_catalog_sha256=str(getattr(posture, "control_catalog_sha256")).casefold(),
            requirement_count=len(facts),
            monitored_requirement_count=len(facts) - len(blind),
            blind_spot_requirement_count=len(blind),
            critical_blind_spot_count=sum(item.severity == TelemetrySeverity.CRITICAL for item in blind),
            high_or_critical_blind_spot_count=sum(severity_rank(item.severity) >= severity_rank(TelemetrySeverity.HIGH) for item in blind),
            fallback_blind_spot_count=sum(bool(set(item.blind_spot_reasons) & fallback_reasons) for item in blind),
            integrity_blind_spot_count=sum(bool(set(item.blind_spot_reasons) & integrity_reasons) for item in blind),
            alerting_blind_spot_count=sum(bool(set(item.blind_spot_reasons) & alerting_reasons) for item in blind),
            max_blind_spot_risk_score=max_risk,
            prioritized_blind_spot_requirement_ids=prioritized,
            requirements=tuple(facts),
            assessment_evidence_sha256=assessment_sha,
        )
