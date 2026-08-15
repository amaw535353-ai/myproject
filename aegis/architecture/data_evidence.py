from __future__ import annotations

import hmac

from aegis.assurance.posture_reporting import (
    P6D_POSTURE_EVIDENCE_SCHEMA_VERSION,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)

from .attack_paths import P7A_ASSESSMENT_SCHEMA_VERSION, VerifiedAttackPathAssessment
from .data_manifest import is_sha256, reject
from .data_types import DataPathPolicy, DataPathRejectReason, DataPathRequest
from .privilege_types import P7B_ASSESSMENT_SCHEMA_VERSION, VerifiedPrivilegeEscalationAssessment


def validate_upstream_evidence(
    *,
    request: DataPathRequest,
    policy: DataPathPolicy,
    architecture_sha256: str,
    p7a_assessment: VerifiedAttackPathAssessment,
    p7b_assessment: VerifiedPrivilegeEscalationAssessment,
    posture: VerifiedSecurityPosture,
) -> dict[str, ControlStatus]:
    if (
        p7a_assessment.schema_version != P7A_ASSESSMENT_SCHEMA_VERSION
        or not p7a_assessment.exact_architecture_binding_verified
        or not p7a_assessment.required_graph_coverage_verified
        or not p7a_assessment.trust_boundaries_policy_pinned
        or not p7a_assessment.exact_posture_binding_verified
        or not p7a_assessment.control_status_derived_from_p6d
        or not p7a_assessment.missing_and_exceptioned_controls_visible
        or p7a_assessment.caller_summary_trusted
        or p7a_assessment.network_operations != 0
        or not is_sha256(p7a_assessment.architecture_sha256)
        or not is_sha256(p7a_assessment.posture_evidence_sha256)
        or not is_sha256(p7a_assessment.control_catalog_sha256)
        or not is_sha256(p7a_assessment.assessment_evidence_sha256)
    ):
        reject(DataPathRejectReason.P7A_ASSESSMENT_UNVERIFIED, "data-flow analysis requires intact P7-A attack-path evidence")
    if (
        not hmac.compare_digest(p7a_assessment.architecture_sha256.casefold(), architecture_sha256.casefold())
        or not hmac.compare_digest(p7a_assessment.assessment_evidence_sha256.casefold(), policy.expected_p7a_assessment_evidence_sha256.casefold())
        or not hmac.compare_digest(request.p7a_assessment_evidence_sha256.casefold(), p7a_assessment.assessment_evidence_sha256.casefold())
    ):
        reject(DataPathRejectReason.P7A_ASSESSMENT_MISMATCH, "P7-A architecture/assessment evidence differs from P7-C policy")

    if (
        p7b_assessment.schema_version != P7B_ASSESSMENT_SCHEMA_VERSION
        or not p7b_assessment.exact_identity_graph_binding_verified
        or not p7b_assessment.exact_architecture_binding_verified
        or not p7b_assessment.exact_p7a_assessment_binding_verified
        or not p7b_assessment.exact_p6d_posture_binding_verified
        or not p7b_assessment.principal_capability_policy_pinned
        or not p7b_assessment.delegation_routes_policy_pinned
        or not p7b_assessment.privilege_amplification_derived_from_evidence
        or not p7b_assessment.mitigating_controls_visible
        or p7b_assessment.caller_summary_trusted
        or p7b_assessment.network_operations != 0
        or not is_sha256(p7b_assessment.architecture_sha256)
        or not is_sha256(p7b_assessment.p7a_assessment_evidence_sha256)
        or not is_sha256(p7b_assessment.posture_evidence_sha256)
        or not is_sha256(p7b_assessment.control_catalog_sha256)
        or not is_sha256(p7b_assessment.assessment_evidence_sha256)
    ):
        reject(DataPathRejectReason.P7B_ASSESSMENT_UNVERIFIED, "data-flow analysis requires intact P7-B privilege evidence")
    if (
        not hmac.compare_digest(p7b_assessment.architecture_sha256.casefold(), architecture_sha256.casefold())
        or not hmac.compare_digest(p7b_assessment.p7a_assessment_evidence_sha256.casefold(), p7a_assessment.assessment_evidence_sha256.casefold())
        or not hmac.compare_digest(p7b_assessment.assessment_evidence_sha256.casefold(), policy.expected_p7b_assessment_evidence_sha256.casefold())
        or not hmac.compare_digest(request.p7b_assessment_evidence_sha256.casefold(), p7b_assessment.assessment_evidence_sha256.casefold())
    ):
        reject(DataPathRejectReason.P7B_ASSESSMENT_MISMATCH, "P7-B privilege evidence differs from P7-C policy")

    if (
        posture.schema_version != P6D_POSTURE_EVIDENCE_SCHEMA_VERSION
        or not posture.exact_release_identity_verified
        or not posture.exact_upstream_evidence_binding_verified
        or not posture.control_catalog_verified
        or not posture.status_derived_from_evidence
        or not posture.missing_evidence_visible
        or not posture.exception_scope_visible
        or posture.caller_declared_green_trusted
        or posture.network_operations != 0
        or not isinstance(posture.overall_rating, PostureRating)
        or not is_sha256(posture.posture_evidence_sha256)
        or not is_sha256(posture.control_catalog_sha256)
    ):
        reject(DataPathRejectReason.POSTURE_UNVERIFIED, "data-flow analysis requires intact P6-D posture evidence")
    if (
        not hmac.compare_digest(posture.posture_evidence_sha256.casefold(), policy.expected_posture_evidence_sha256.casefold())
        or not hmac.compare_digest(request.posture_evidence_sha256.casefold(), posture.posture_evidence_sha256.casefold())
        or not hmac.compare_digest(p7a_assessment.posture_evidence_sha256.casefold(), posture.posture_evidence_sha256.casefold())
        or not hmac.compare_digest(p7b_assessment.posture_evidence_sha256.casefold(), posture.posture_evidence_sha256.casefold())
    ):
        reject(DataPathRejectReason.POSTURE_DIGEST_MISMATCH, "P6-D posture evidence differs from P7-C policy or upstream assessments")
    if (
        not hmac.compare_digest(posture.control_catalog_sha256.casefold(), policy.expected_control_catalog_sha256.casefold())
        or not hmac.compare_digest(p7a_assessment.control_catalog_sha256.casefold(), posture.control_catalog_sha256.casefold())
        or not hmac.compare_digest(p7b_assessment.control_catalog_sha256.casefold(), posture.control_catalog_sha256.casefold())
    ):
        reject(DataPathRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog differs across P7-A/P7-B/P7-C evidence")

    controls: dict[str, ControlStatus] = {}
    for assessment in posture.assessments:
        if (
            not assessment.control_id
            or not isinstance(assessment.status, ControlStatus)
            or not is_sha256(assessment.evidence_sha256)
        ):
            reject(DataPathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control assessment is invalid", control_id=assessment.control_id or None)
        if assessment.control_id in controls:
            reject(DataPathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D posture contains duplicate control assessments", control_id=assessment.control_id)
        controls[assessment.control_id] = assessment.status
    if posture.control_count != len(controls):
        reject(DataPathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control count does not match assessment coverage")

    expected_satisfied = {control_id for control_id, status in controls.items() if status == ControlStatus.SATISFIED}
    expected_exceptioned = {control_id for control_id, status in controls.items() if status == ControlStatus.EXCEPTIONED}
    expected_not_evaluated = {control_id for control_id, status in controls.items() if status == ControlStatus.NOT_EVALUATED}
    if (
        set(posture.satisfied_control_ids) != expected_satisfied
        or set(posture.exceptioned_control_ids) != expected_exceptioned
        or set(posture.not_evaluated_control_ids) != expected_not_evaluated
    ):
        reject(DataPathRejectReason.CONTROL_STATUS_MISMATCH, "P6-D aggregate control-status lists do not match assessments")

    return controls
