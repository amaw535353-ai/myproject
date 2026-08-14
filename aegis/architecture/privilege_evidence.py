from __future__ import annotations

import hashlib
import hmac
import json
from typing import Mapping

from aegis.assurance.posture_reporting import (
    P6D_POSTURE_EVIDENCE_SCHEMA_VERSION,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)
from .attack_paths import (
    P7A_ARCHITECTURE_SCHEMA_VERSION,
    P7A_ASSESSMENT_SCHEMA_VERSION,
    ArchitectureFlow,
    ArchitectureManifest,
    VerifiedAttackPathAssessment,
)
from .privilege_types import *
from .privilege_core import _is_sha256, _reject

def _validate_architecture(
    architecture: ArchitectureManifest,
    assessment: VerifiedAttackPathAssessment,
    posture: VerifiedSecurityPosture,
    *,
    request: PrivilegePathRequest,
    policy: PrivilegePathPolicy,
) -> tuple[dict[str, object], dict[str, ArchitectureFlow]]:
    if (
        architecture.schema_version != P7A_ARCHITECTURE_SCHEMA_VERSION
        or not architecture.architecture_id
        or not architecture.version
        or not architecture.assets
        or not architecture.flows
    ):
        _reject(PrivilegePathRejectReason.ARCHITECTURE_INVALID, "P7-B requires a valid P7-A architecture manifest")
    architecture_document = {
        "architecture_id": architecture.architecture_id,
        "assets": [
            {
                "asset_id": asset.asset_id,
                "asset_type": asset.asset_type.value if hasattr(asset.asset_type, "value") else str(asset.asset_type),
                "description": asset.description,
                "owner_id": asset.owner_id,
                "sensitivity": asset.sensitivity.value if hasattr(asset.sensitivity, "value") else str(asset.sensitivity),
                "trust_zone": asset.trust_zone,
            }
            for asset in sorted(architecture.assets, key=lambda item: item.asset_id)
        ],
        "created_at_epoch": architecture.created_at_epoch,
        "flows": [
            {
                "description": flow.description,
                "flow_id": flow.flow_id,
                "flow_type": flow.flow_type.value if hasattr(flow.flow_type, "value") else str(flow.flow_type),
                "owner_id": flow.owner_id,
                "required_control_ids": sorted(flow.required_control_ids),
                "source_asset_id": flow.source_asset_id,
                "target_asset_id": flow.target_asset_id,
            }
            for flow in sorted(architecture.flows, key=lambda item: item.flow_id)
        ],
        "schema_version": architecture.schema_version,
        "version": architecture.version,
    }
    architecture_sha = hashlib.sha256(
        json.dumps(architecture_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if (
        not hmac.compare_digest(architecture_sha, policy.expected_architecture_sha256.casefold())
        or not hmac.compare_digest(request.architecture_sha256.casefold(), architecture_sha)
    ):
        _reject(PrivilegePathRejectReason.ARCHITECTURE_DIGEST_MISMATCH, "request/policy do not bind to exact P7-A architecture")

    if (
        assessment.schema_version != P7A_ASSESSMENT_SCHEMA_VERSION
        or not assessment.exact_architecture_binding_verified
        or not assessment.required_graph_coverage_verified
        or not assessment.trust_boundaries_policy_pinned
        or not assessment.exact_posture_binding_verified
        or not assessment.control_status_derived_from_p6d
        or not assessment.missing_and_exceptioned_controls_visible
        or assessment.caller_summary_trusted
        or assessment.network_operations != 0
        or not _is_sha256(assessment.assessment_evidence_sha256)
    ):
        _reject(PrivilegePathRejectReason.P7A_ASSESSMENT_UNVERIFIED, "P7-B requires intact P7-A attack-path evidence")
    if (
        assessment.architecture_id != architecture.architecture_id
        or assessment.architecture_version != architecture.version
        or not hmac.compare_digest(assessment.architecture_sha256.casefold(), architecture_sha)
        or not hmac.compare_digest(
            assessment.assessment_evidence_sha256.casefold(),
            policy.expected_p7a_assessment_evidence_sha256.casefold(),
        )
        or not hmac.compare_digest(
            request.p7a_assessment_evidence_sha256.casefold(),
            assessment.assessment_evidence_sha256.casefold(),
        )
    ):
        _reject(PrivilegePathRejectReason.P7A_ASSESSMENT_MISMATCH, "P7-A assessment does not bind to exact architecture/policy/request")

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
        or not _is_sha256(posture.posture_evidence_sha256)
        or not _is_sha256(posture.control_catalog_sha256)
    ):
        _reject(PrivilegePathRejectReason.POSTURE_UNVERIFIED, "P7-B requires intact P6-D posture evidence")
    if (
        not hmac.compare_digest(posture.posture_evidence_sha256.casefold(), policy.expected_posture_evidence_sha256.casefold())
        or not hmac.compare_digest(request.posture_evidence_sha256.casefold(), posture.posture_evidence_sha256.casefold())
        or not hmac.compare_digest(assessment.posture_evidence_sha256.casefold(), posture.posture_evidence_sha256.casefold())
    ):
        _reject(PrivilegePathRejectReason.POSTURE_DIGEST_MISMATCH, "P7-A/P7-B request/policy do not bind to exact P6-D posture evidence")
    if (
        not hmac.compare_digest(posture.control_catalog_sha256.casefold(), policy.expected_control_catalog_sha256.casefold())
        or not hmac.compare_digest(assessment.control_catalog_sha256.casefold(), posture.control_catalog_sha256.casefold())
    ):
        _reject(PrivilegePathRejectReason.CONTROL_CATALOG_MISMATCH, "P7-A/P7-B control catalog differs from policy")

    assets: dict[str, object] = {}
    for asset in architecture.assets:
        if not asset.asset_id or asset.asset_id in assets:
            _reject(PrivilegePathRejectReason.ARCHITECTURE_INVALID, "architecture asset IDs are empty or duplicate")
        assets[asset.asset_id] = asset
    flows: dict[str, ArchitectureFlow] = {}
    for flow in architecture.flows:
        if (
            not flow.flow_id
            or flow.flow_id in flows
            or flow.source_asset_id not in assets
            or flow.target_asset_id not in assets
        ):
            _reject(PrivilegePathRejectReason.ARCHITECTURE_INVALID, "architecture flows are invalid or duplicate")
        flows[flow.flow_id] = flow
    return assets, flows


def _posture_controls(posture: VerifiedSecurityPosture) -> dict[str, ControlStatus]:
    controls: dict[str, ControlStatus] = {}
    for assessment in posture.assessments:
        if (
            not assessment.control_id
            or not isinstance(assessment.status, ControlStatus)
            or not _is_sha256(assessment.evidence_sha256)
            or assessment.control_id in controls
        ):
            _reject(PrivilegePathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control assessment is invalid or duplicate", control_id=assessment.control_id or None)
        controls[assessment.control_id] = assessment.status
    if posture.control_count != len(controls):
        _reject(PrivilegePathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control count does not match assessment coverage")
    expected_satisfied = {key for key, value in controls.items() if value == ControlStatus.SATISFIED}
    expected_exceptioned = {key for key, value in controls.items() if value == ControlStatus.EXCEPTIONED}
    expected_not_evaluated = {key for key, value in controls.items() if value == ControlStatus.NOT_EVALUATED}
    if (
        set(posture.satisfied_control_ids) != expected_satisfied
        or set(posture.exceptioned_control_ids) != expected_exceptioned
        or set(posture.not_evaluated_control_ids) != expected_not_evaluated
    ):
        _reject(PrivilegePathRejectReason.CONTROL_STATUS_MISMATCH, "P6-D aggregate control status differs from per-control evidence")
    return controls
