from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from aegis.assurance.posture_reporting import (
    P6D_POSTURE_EVIDENCE_SCHEMA_VERSION,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)


P7A_ARCHITECTURE_POLICY_VERSION = "ai-security-trust-boundary-attack-path-v1"
P7A_ARCHITECTURE_SCHEMA_VERSION = "aegis-ai-security-architecture-v1"
P7A_ASSESSMENT_SCHEMA_VERSION = "aegis-attack-path-assessment-v1"
P7A_ASSESSMENT_MODE = "deterministic-evidence-bound-attack-path-analysis-v1"


class AssetType(StrEnum):
    EXTERNAL_ACTOR = "external_actor"
    API_GATEWAY = "api_gateway"
    AGENT_ORCHESTRATOR = "agent_orchestrator"
    RETRIEVER = "retriever"
    VECTOR_STORE = "vector_store"
    TOOL_GATEWAY = "tool_gateway"
    SECRET_STORE = "secret_store"
    MODEL_REGISTRY = "model_registry"
    MODEL_RUNTIME = "model_runtime"
    SECURITY_TELEMETRY = "security_telemetry"


class AssetSensitivity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FlowType(StrEnum):
    USER_INPUT = "user_input"
    AGENT_CONTROL = "agent_control"
    RETRIEVAL = "retrieval"
    DATA_ACCESS = "data_access"
    TOOL_CALL = "tool_call"
    SECRET_ACCESS = "secret_access"
    MODEL_ACQUISITION = "model_acquisition"
    INFERENCE = "inference"
    SECURITY_TELEMETRY = "security_telemetry"


class AttackPathRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    ASSET_DUPLICATE = "asset_duplicate"
    ASSET_REQUIRED_MISSING = "asset_required_missing"
    ASSET_OWNER_UNTRUSTED = "asset_owner_untrusted"
    TRUST_ZONE_INVALID = "trust_zone_invalid"
    TRUST_ZONE_DRIFT = "trust_zone_drift"
    SENSITIVITY_DOWNGRADE = "sensitivity_downgrade"
    FLOW_DUPLICATE = "flow_duplicate"
    FLOW_REQUIRED_MISSING = "flow_required_missing"
    FLOW_OWNER_UNTRUSTED = "flow_owner_untrusted"
    FLOW_REFERENCE_INVALID = "flow_reference_invalid"
    FLOW_SELF_LOOP = "flow_self_loop"
    FLOW_ENDPOINT_DRIFT = "flow_endpoint_drift"
    FLOW_CONTROL_DUPLICATE = "flow_control_duplicate"
    FLOW_CONTROL_DRIFT = "flow_control_drift"
    UNGUARDED_TRUST_BOUNDARY = "unguarded_trust_boundary"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    CONTROL_STATUS_MISMATCH = "control_status_mismatch"
    CONTROL_UNKNOWN = "control_unknown"
    ATTACKER_PROFILE_MISMATCH = "attacker_profile_mismatch"
    ENTRY_SCOPE_MISMATCH = "entry_scope_mismatch"
    TARGET_SCOPE_MISMATCH = "target_scope_mismatch"
    PATH_LIMIT_EXCEEDED = "path_limit_exceeded"
    DECLARED_PATH_MISMATCH = "declared_path_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class AttackPathRejected(ValueError):
    def __init__(
        self,
        reason: AttackPathRejectReason,
        message: str,
        *,
        asset_id: str | None = None,
        flow_id: str | None = None,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.asset_id = asset_id
        self.flow_id = flow_id
        self.control_id = control_id


@dataclass(frozen=True)
class ArchitectureAsset:
    asset_id: str
    asset_type: AssetType
    trust_zone: str
    owner_id: str
    sensitivity: AssetSensitivity
    description: str


@dataclass(frozen=True)
class ArchitectureFlow:
    flow_id: str
    source_asset_id: str
    target_asset_id: str
    flow_type: FlowType
    owner_id: str
    required_control_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class ArchitectureManifest:
    architecture_id: str
    version: str
    created_at_epoch: int
    assets: tuple[ArchitectureAsset, ...]
    flows: tuple[ArchitectureFlow, ...]
    schema_version: str = P7A_ARCHITECTURE_SCHEMA_VERSION


@dataclass(frozen=True)
class AttackPathRequest:
    architecture_id: str
    architecture_version: str
    architecture_sha256: str
    posture_evidence_sha256: str
    attacker_profile_id: str
    entry_asset_ids: tuple[str, ...]
    target_asset_ids: tuple[str, ...]
    evaluated_at_epoch: int
    declared_exposed_path_ids: tuple[str, ...]
    declared_max_exposed_risk_score: int


@dataclass(frozen=True)
class AttackPathPolicy:
    expected_architecture_id: str
    expected_architecture_version: str
    expected_architecture_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    attacker_profile_id: str
    required_asset_ids: frozenset[str]
    required_flow_ids: frozenset[str]
    required_entry_asset_ids: frozenset[str]
    required_target_asset_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    allowed_trust_zones: frozenset[str]
    expected_trust_zone_by_asset: Mapping[str, str]
    minimum_sensitivity_by_asset: Mapping[str, AssetSensitivity]
    expected_flow_endpoints: Mapping[str, tuple[str, str]]
    expected_control_ids_by_flow: Mapping[str, frozenset[str]]
    allow_unguarded_flow_ids: frozenset[str] = frozenset()
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30
    max_path_hops: int = 8
    max_paths: int = 128


@dataclass(frozen=True)
class AttackPathFact:
    path_id: str
    entry_asset_id: str
    target_asset_id: str
    asset_ids: tuple[str, ...]
    flow_ids: tuple[str, ...]
    trust_zone_sequence: tuple[str, ...]
    trust_boundary_crossings: int
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    unguarded_flow_ids: tuple[str, ...]
    exposed: bool
    target_sensitivity: AssetSensitivity
    risk_score: int
    exposure_reasons: tuple[str, ...]
    mitigating_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedAttackPathAssessment:
    architecture_id: str
    architecture_version: str
    architecture_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    attacker_profile_id: str
    entry_asset_ids: tuple[str, ...]
    target_asset_ids: tuple[str, ...]
    topology_path_count: int
    exposed_path_count: int
    controlled_path_count: int
    critical_exposed_path_count: int
    max_exposed_risk_score: int
    prioritized_exposed_path_ids: tuple[str, ...]
    paths: tuple[AttackPathFact, ...]
    assessment_evidence_sha256: str
    exact_architecture_binding_verified: bool = True
    required_graph_coverage_verified: bool = True
    trust_boundaries_policy_pinned: bool = True
    exact_posture_binding_verified: bool = True
    control_status_derived_from_p6d: bool = True
    missing_and_exceptioned_controls_visible: bool = True
    caller_summary_trusted: bool = False
    production_asset_discovery: bool = False
    production_exploitability_assessment: bool = False
    formal_reachability_proof: bool = False
    external_red_team_evidence: bool = False
    network_operations: int = 0
    schema_version: str = P7A_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7A_ARCHITECTURE_POLICY_VERSION
    assessment_mode: str = P7A_ASSESSMENT_MODE


def _reject(
    reason: AttackPathRejectReason,
    message: str,
    *,
    asset_id: str | None = None,
    flow_id: str | None = None,
    control_id: str | None = None,
) -> None:
    raise AttackPathRejected(
        reason,
        message,
        asset_id=asset_id,
        flow_id=flow_id,
        control_id=control_id,
    )


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _sensitivity_rank(sensitivity: AssetSensitivity) -> int:
    return {
        AssetSensitivity.LOW: 1,
        AssetSensitivity.MEDIUM: 2,
        AssetSensitivity.HIGH: 3,
        AssetSensitivity.CRITICAL: 4,
    }[sensitivity]


def _canonical_asset(asset: ArchitectureAsset) -> dict[str, object]:
    return {
        "asset_id": asset.asset_id,
        "asset_type": asset.asset_type.value if isinstance(asset.asset_type, AssetType) else str(asset.asset_type),
        "description": asset.description,
        "owner_id": asset.owner_id,
        "sensitivity": asset.sensitivity.value
        if isinstance(asset.sensitivity, AssetSensitivity)
        else str(asset.sensitivity),
        "trust_zone": asset.trust_zone,
    }


def _canonical_flow(flow: ArchitectureFlow) -> dict[str, object]:
    return {
        "description": flow.description,
        "flow_id": flow.flow_id,
        "flow_type": flow.flow_type.value if isinstance(flow.flow_type, FlowType) else str(flow.flow_type),
        "owner_id": flow.owner_id,
        "required_control_ids": sorted(flow.required_control_ids),
        "source_asset_id": flow.source_asset_id,
        "target_asset_id": flow.target_asset_id,
    }


def canonical_architecture_manifest_bytes(manifest: ArchitectureManifest) -> bytes:
    document = {
        "architecture_id": manifest.architecture_id,
        "assets": [
            _canonical_asset(asset)
            for asset in sorted(manifest.assets, key=lambda item: item.asset_id)
        ],
        "created_at_epoch": manifest.created_at_epoch,
        "flows": [
            _canonical_flow(flow)
            for flow in sorted(manifest.flows, key=lambda item: item.flow_id)
        ],
        "schema_version": manifest.schema_version,
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def architecture_manifest_digest(manifest: ArchitectureManifest) -> str:
    return hashlib.sha256(canonical_architecture_manifest_bytes(manifest)).hexdigest()


def attack_path_identifier(
    entry_asset_id: str,
    target_asset_id: str,
    asset_ids: tuple[str, ...],
    flow_ids: tuple[str, ...],
) -> str:
    document = {
        "asset_ids": list(asset_ids),
        "entry_asset_id": entry_asset_id,
        "flow_ids": list(flow_ids),
        "target_asset_id": target_asset_id,
    }
    digest = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"path-{digest[:20]}"


def _validate_policy(policy: AttackPathPolicy) -> None:
    if (
        not policy.expected_architecture_id
        or not policy.expected_architecture_version
        or not _is_sha256(policy.expected_architecture_sha256)
        or not _is_sha256(policy.expected_posture_evidence_sha256)
        or not _is_sha256(policy.expected_control_catalog_sha256)
        or not policy.attacker_profile_id
        or not policy.required_asset_ids
        or not policy.required_flow_ids
        or not policy.required_entry_asset_ids
        or not policy.required_target_asset_ids
        or not policy.trusted_owner_ids
        or not policy.allowed_trust_zones
        or policy.required_entry_asset_ids & policy.required_target_asset_ids
        or not policy.required_entry_asset_ids.issubset(policy.required_asset_ids)
        or not policy.required_target_asset_ids.issubset(policy.required_asset_ids)
        or policy.max_manifest_age_seconds < 0
        or policy.max_future_skew_seconds < 0
        or policy.max_path_hops <= 0
        or policy.max_paths <= 0
    ):
        _reject(AttackPathRejectReason.POLICY_INVALID, "attack-path policy metadata is invalid")

    if not policy.required_asset_ids.issubset(set(policy.expected_trust_zone_by_asset)):
        _reject(AttackPathRejectReason.POLICY_INVALID, "required assets lack policy-pinned trust zones")
    if not policy.required_flow_ids.issubset(set(policy.expected_flow_endpoints)):
        _reject(AttackPathRejectReason.POLICY_INVALID, "required flows lack policy-pinned endpoints")
    if not policy.required_flow_ids.issubset(set(policy.expected_control_ids_by_flow)):
        _reject(AttackPathRejectReason.POLICY_INVALID, "required flows lack policy-pinned control mappings")
    if not set(policy.minimum_sensitivity_by_asset).issubset(policy.required_asset_ids):
        _reject(AttackPathRejectReason.POLICY_INVALID, "minimum sensitivity policy references a non-required asset")
    if not policy.allow_unguarded_flow_ids.issubset(policy.required_flow_ids):
        _reject(AttackPathRejectReason.POLICY_INVALID, "unguarded flow allowlist references a non-required flow")
    for asset_id, zone in policy.expected_trust_zone_by_asset.items():
        if not asset_id or zone not in policy.allowed_trust_zones:
            _reject(AttackPathRejectReason.POLICY_INVALID, "policy-pinned trust-zone mapping is invalid")
    for asset_id, sensitivity in policy.minimum_sensitivity_by_asset.items():
        if not asset_id or not isinstance(sensitivity, AssetSensitivity):
            _reject(AttackPathRejectReason.POLICY_INVALID, "minimum sensitivity mapping is invalid")
    for flow_id, endpoints in policy.expected_flow_endpoints.items():
        if (
            not flow_id
            or len(endpoints) != 2
            or not endpoints[0]
            or not endpoints[1]
            or endpoints[0] == endpoints[1]
        ):
            _reject(AttackPathRejectReason.POLICY_INVALID, "policy-pinned flow endpoints are invalid")
    for flow_id, controls in policy.expected_control_ids_by_flow.items():
        if not flow_id or any(not control_id for control_id in controls):
            _reject(AttackPathRejectReason.POLICY_INVALID, "policy-pinned flow controls are invalid")


def _validate_request(request: AttackPathRequest, policy: AttackPathPolicy) -> None:
    if (
        not request.architecture_id
        or not request.architecture_version
        or not _is_sha256(request.architecture_sha256)
        or not _is_sha256(request.posture_evidence_sha256)
        or not request.attacker_profile_id
        or not request.entry_asset_ids
        or not request.target_asset_ids
        or request.evaluated_at_epoch <= 0
        or request.declared_max_exposed_risk_score < 0
        or len(set(request.entry_asset_ids)) != len(request.entry_asset_ids)
        or len(set(request.target_asset_ids)) != len(request.target_asset_ids)
        or len(set(request.declared_exposed_path_ids)) != len(request.declared_exposed_path_ids)
    ):
        _reject(AttackPathRejectReason.REQUEST_INVALID, "attack-path request metadata is invalid")
    if request.attacker_profile_id != policy.attacker_profile_id:
        _reject(AttackPathRejectReason.ATTACKER_PROFILE_MISMATCH, "attacker profile is not policy-authorized")
    if set(request.entry_asset_ids) != set(policy.required_entry_asset_ids):
        _reject(AttackPathRejectReason.ENTRY_SCOPE_MISMATCH, "attacker entry scope differs from policy")
    if set(request.target_asset_ids) != set(policy.required_target_asset_ids):
        _reject(AttackPathRejectReason.TARGET_SCOPE_MISMATCH, "sensitive target scope differs from policy")


def _validate_manifest(
    manifest: ArchitectureManifest,
    *,
    request: AttackPathRequest,
    policy: AttackPathPolicy,
) -> tuple[dict[str, ArchitectureAsset], dict[str, ArchitectureFlow], str]:
    if (
        manifest.schema_version != P7A_ARCHITECTURE_SCHEMA_VERSION
        or not manifest.architecture_id
        or not manifest.version
        or manifest.created_at_epoch <= 0
        or not manifest.assets
        or not manifest.flows
    ):
        _reject(AttackPathRejectReason.MANIFEST_INVALID, "architecture manifest metadata is invalid")
    manifest_sha = architecture_manifest_digest(manifest)
    if (
        manifest.architecture_id != policy.expected_architecture_id
        or manifest.version != policy.expected_architecture_version
        or request.architecture_id != manifest.architecture_id
        or request.architecture_version != manifest.version
        or not hmac.compare_digest(manifest_sha, policy.expected_architecture_sha256.casefold())
        or not hmac.compare_digest(request.architecture_sha256.casefold(), manifest_sha)
    ):
        _reject(AttackPathRejectReason.MANIFEST_DIGEST_MISMATCH, "request/policy do not bind to the exact architecture manifest")
    if manifest.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        _reject(AttackPathRejectReason.MANIFEST_FUTURE, "architecture manifest is future-dated")
    if request.evaluated_at_epoch - manifest.created_at_epoch > policy.max_manifest_age_seconds:
        _reject(AttackPathRejectReason.MANIFEST_STALE, "architecture manifest is older than policy permits")

    assets: dict[str, ArchitectureAsset] = {}
    for asset in manifest.assets:
        if (
            not asset.asset_id
            or not isinstance(asset.asset_type, AssetType)
            or not asset.trust_zone
            or not asset.owner_id
            or not isinstance(asset.sensitivity, AssetSensitivity)
            or not asset.description
        ):
            _reject(AttackPathRejectReason.MANIFEST_INVALID, "architecture contains an invalid asset", asset_id=asset.asset_id or None)
        if asset.asset_id in assets:
            _reject(AttackPathRejectReason.ASSET_DUPLICATE, "architecture contains duplicate asset IDs", asset_id=asset.asset_id)
        if asset.owner_id not in policy.trusted_owner_ids:
            _reject(AttackPathRejectReason.ASSET_OWNER_UNTRUSTED, "asset owner is not trusted by architecture policy", asset_id=asset.asset_id)
        if asset.trust_zone not in policy.allowed_trust_zones:
            _reject(AttackPathRejectReason.TRUST_ZONE_INVALID, "asset uses an unrecognized trust zone", asset_id=asset.asset_id)
        assets[asset.asset_id] = asset

    missing_assets = policy.required_asset_ids - set(assets)
    if missing_assets:
        _reject(AttackPathRejectReason.ASSET_REQUIRED_MISSING, "required architecture asset is missing", asset_id=sorted(missing_assets)[0])
    for asset_id, expected_zone in policy.expected_trust_zone_by_asset.items():
        asset = assets.get(asset_id)
        if asset is None or asset.trust_zone != expected_zone:
            _reject(AttackPathRejectReason.TRUST_ZONE_DRIFT, "asset trust zone differs from policy", asset_id=asset_id)
    for asset_id, minimum in policy.minimum_sensitivity_by_asset.items():
        asset = assets.get(asset_id)
        if asset is None or _sensitivity_rank(asset.sensitivity) < _sensitivity_rank(minimum):
            _reject(AttackPathRejectReason.SENSITIVITY_DOWNGRADE, "sensitive asset criticality is below policy minimum", asset_id=asset_id)

    flows: dict[str, ArchitectureFlow] = {}
    for flow in manifest.flows:
        if (
            not flow.flow_id
            or not flow.source_asset_id
            or not flow.target_asset_id
            or not isinstance(flow.flow_type, FlowType)
            or not flow.owner_id
            or not flow.description
        ):
            _reject(AttackPathRejectReason.MANIFEST_INVALID, "architecture contains an invalid flow", flow_id=flow.flow_id or None)
        if flow.flow_id in flows:
            _reject(AttackPathRejectReason.FLOW_DUPLICATE, "architecture contains duplicate flow IDs", flow_id=flow.flow_id)
        if flow.owner_id not in policy.trusted_owner_ids:
            _reject(AttackPathRejectReason.FLOW_OWNER_UNTRUSTED, "flow owner is not trusted by architecture policy", flow_id=flow.flow_id)
        if flow.source_asset_id not in assets or flow.target_asset_id not in assets:
            _reject(AttackPathRejectReason.FLOW_REFERENCE_INVALID, "flow references an unknown asset", flow_id=flow.flow_id)
        if flow.source_asset_id == flow.target_asset_id:
            _reject(AttackPathRejectReason.FLOW_SELF_LOOP, "architecture flow may not self-loop", flow_id=flow.flow_id)
        if len(set(flow.required_control_ids)) != len(flow.required_control_ids) or any(not item for item in flow.required_control_ids):
            _reject(AttackPathRejectReason.FLOW_CONTROL_DUPLICATE, "flow contains duplicate or empty control IDs", flow_id=flow.flow_id)
        crosses_boundary = assets[flow.source_asset_id].trust_zone != assets[flow.target_asset_id].trust_zone
        if crosses_boundary and not flow.required_control_ids and flow.flow_id not in policy.allow_unguarded_flow_ids:
            _reject(AttackPathRejectReason.UNGUARDED_TRUST_BOUNDARY, "cross-zone flow has no explicit control mapping", flow_id=flow.flow_id)
        flows[flow.flow_id] = flow

    missing_flows = policy.required_flow_ids - set(flows)
    if missing_flows:
        _reject(AttackPathRejectReason.FLOW_REQUIRED_MISSING, "required architecture flow is missing", flow_id=sorted(missing_flows)[0])
    for flow_id, endpoints in policy.expected_flow_endpoints.items():
        flow = flows.get(flow_id)
        if flow is None or (flow.source_asset_id, flow.target_asset_id) != tuple(endpoints):
            _reject(AttackPathRejectReason.FLOW_ENDPOINT_DRIFT, "flow endpoints differ from policy", flow_id=flow_id)
    for flow_id, controls in policy.expected_control_ids_by_flow.items():
        flow = flows.get(flow_id)
        if flow is None or frozenset(flow.required_control_ids) != frozenset(controls):
            _reject(AttackPathRejectReason.FLOW_CONTROL_DRIFT, "flow control mapping differs from policy", flow_id=flow_id)

    return assets, flows, manifest_sha


def _validate_posture(
    posture: VerifiedSecurityPosture,
    *,
    request: AttackPathRequest,
    policy: AttackPathPolicy,
    flows: Mapping[str, ArchitectureFlow],
) -> dict[str, ControlStatus]:
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
        _reject(AttackPathRejectReason.POSTURE_UNVERIFIED, "attack-path analysis requires intact P6-D posture evidence")
    if (
        not hmac.compare_digest(posture.posture_evidence_sha256.casefold(), policy.expected_posture_evidence_sha256.casefold())
        or not hmac.compare_digest(request.posture_evidence_sha256.casefold(), posture.posture_evidence_sha256.casefold())
    ):
        _reject(AttackPathRejectReason.POSTURE_DIGEST_MISMATCH, "request/policy do not bind to exact P6-D posture evidence")
    if not hmac.compare_digest(posture.control_catalog_sha256.casefold(), policy.expected_control_catalog_sha256.casefold()):
        _reject(AttackPathRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog differs from architecture policy")

    controls: dict[str, ControlStatus] = {}
    for assessment in posture.assessments:
        if (
            not assessment.control_id
            or not isinstance(assessment.status, ControlStatus)
            or not _is_sha256(assessment.evidence_sha256)
        ):
            _reject(AttackPathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control assessment is invalid", control_id=assessment.control_id or None)
        if assessment.control_id in controls:
            _reject(AttackPathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D posture contains duplicate control assessments", control_id=assessment.control_id)
        controls[assessment.control_id] = assessment.status
    if posture.control_count != len(controls):
        _reject(AttackPathRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control count does not match assessment coverage")

    expected_satisfied = {control_id for control_id, status in controls.items() if status == ControlStatus.SATISFIED}
    expected_exceptioned = {control_id for control_id, status in controls.items() if status == ControlStatus.EXCEPTIONED}
    expected_not_evaluated = {control_id for control_id, status in controls.items() if status == ControlStatus.NOT_EVALUATED}
    if (
        set(posture.satisfied_control_ids) != expected_satisfied
        or set(posture.exceptioned_control_ids) != expected_exceptioned
        or set(posture.not_evaluated_control_ids) != expected_not_evaluated
    ):
        _reject(AttackPathRejectReason.CONTROL_STATUS_MISMATCH, "P6-D aggregate control-status lists do not match assessments")

    for flow in flows.values():
        for control_id in flow.required_control_ids:
            if control_id not in controls:
                _reject(AttackPathRejectReason.CONTROL_UNKNOWN, "architecture flow references control absent from P6-D posture", flow_id=flow.flow_id, control_id=control_id)
    return controls


def _path_fact(
    asset_ids: tuple[str, ...],
    flow_ids: tuple[str, ...],
    *,
    assets: Mapping[str, ArchitectureAsset],
    flows: Mapping[str, ArchitectureFlow],
    controls: Mapping[str, ControlStatus],
) -> AttackPathFact:
    entry_asset_id = asset_ids[0]
    target_asset_id = asset_ids[-1]
    zones = tuple(assets[item].trust_zone for item in asset_ids)
    crossings = sum(left != right for left, right in zip(zones, zones[1:]))
    satisfied: set[str] = set()
    exceptioned: set[str] = set()
    not_evaluated: set[str] = set()
    unguarded: set[str] = set()
    for flow_id in flow_ids:
        flow = flows[flow_id]
        if assets[flow.source_asset_id].trust_zone != assets[flow.target_asset_id].trust_zone and not flow.required_control_ids:
            unguarded.add(flow_id)
        for control_id in flow.required_control_ids:
            status = controls[control_id]
            if status == ControlStatus.SATISFIED:
                satisfied.add(control_id)
            elif status == ControlStatus.EXCEPTIONED:
                exceptioned.add(control_id)
            else:
                not_evaluated.add(control_id)

    exposed = bool(exceptioned or not_evaluated or unguarded)
    sensitivity = assets[target_asset_id].sensitivity
    risk_score = (
        _sensitivity_rank(sensitivity) * 20
        + crossings * 3
        + len(exceptioned) * 10
        + len(not_evaluated) * 6
        + len(unguarded) * 12
        + max(0, 8 - len(flow_ids))
    )
    reasons = tuple(
        sorted(
            [f"exceptioned_control:{item}" for item in exceptioned]
            + [f"not_evaluated_control:{item}" for item in not_evaluated]
            + [f"unguarded_flow:{item}" for item in unguarded]
        )
    )
    return AttackPathFact(
        path_id=attack_path_identifier(entry_asset_id, target_asset_id, asset_ids, flow_ids),
        entry_asset_id=entry_asset_id,
        target_asset_id=target_asset_id,
        asset_ids=asset_ids,
        flow_ids=flow_ids,
        trust_zone_sequence=zones,
        trust_boundary_crossings=crossings,
        satisfied_control_ids=tuple(sorted(satisfied)),
        exceptioned_control_ids=tuple(sorted(exceptioned)),
        not_evaluated_control_ids=tuple(sorted(not_evaluated)),
        unguarded_flow_ids=tuple(sorted(unguarded)),
        exposed=exposed,
        target_sensitivity=sensitivity,
        risk_score=risk_score,
        exposure_reasons=reasons,
        mitigating_control_ids=tuple(sorted(satisfied)),
    )


def _enumerate_paths(
    *,
    assets: Mapping[str, ArchitectureAsset],
    flows: Mapping[str, ArchitectureFlow],
    controls: Mapping[str, ControlStatus],
    policy: AttackPathPolicy,
) -> tuple[AttackPathFact, ...]:
    adjacency: dict[str, list[ArchitectureFlow]] = {asset_id: [] for asset_id in assets}
    for flow in flows.values():
        adjacency[flow.source_asset_id].append(flow)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda item: item.flow_id)

    results: list[AttackPathFact] = []
    truncated = False

    def walk(current: str, target: str, asset_path: tuple[str, ...], flow_path: tuple[str, ...], visited: frozenset[str]) -> None:
        nonlocal truncated
        if current == target:
            if flow_path:
                results.append(
                    _path_fact(
                        asset_path,
                        flow_path,
                        assets=assets,
                        flows=flows,
                        controls=controls,
                    )
                )
                if len(results) > policy.max_paths:
                    _reject(AttackPathRejectReason.PATH_LIMIT_EXCEEDED, "topology produced more paths than policy permits")
            return
        outgoing = [flow for flow in adjacency.get(current, ()) if flow.target_asset_id not in visited]
        if len(flow_path) >= policy.max_path_hops:
            if outgoing:
                truncated = True
            return
        for flow in outgoing:
            walk(
                flow.target_asset_id,
                target,
                asset_path + (flow.target_asset_id,),
                flow_path + (flow.flow_id,),
                visited | frozenset({flow.target_asset_id}),
            )

    for entry in sorted(policy.required_entry_asset_ids):
        for target in sorted(policy.required_target_asset_ids):
            walk(entry, target, (entry,), (), frozenset({entry}))
    if truncated:
        _reject(AttackPathRejectReason.PATH_LIMIT_EXCEEDED, "path-hop bound truncated a reachable topology frontier")

    unique: dict[str, AttackPathFact] = {}
    for path in results:
        if path.path_id in unique:
            _reject(AttackPathRejectReason.PATH_LIMIT_EXCEEDED, "deterministic path identifier collision detected")
        unique[path.path_id] = path
    return tuple(sorted(unique.values(), key=lambda item: item.path_id))


class TrustBoundaryAttackPathAnalyzer:
    """Deterministically map policy-pinned architecture paths against P6-D control posture.

    The analyzer establishes topology, explicit trust-boundary crossings, attacker entries,
    sensitive targets, evidence-backed control gaps, and mitigating counterevidence. It does not
    discover production assets, prove exploitability, execute attacks, or provide formal graph
    reachability proof.
    """

    def __init__(self, policy: AttackPathPolicy) -> None:
        self._policy = policy

    def evaluate(
        self,
        request: AttackPathRequest,
        manifest: ArchitectureManifest,
        posture: VerifiedSecurityPosture,
    ) -> VerifiedAttackPathAssessment:
        _validate_policy(self._policy)
        _validate_request(request, self._policy)
        assets, flows, manifest_sha = _validate_manifest(
            manifest,
            request=request,
            policy=self._policy,
        )
        controls = _validate_posture(
            posture,
            request=request,
            policy=self._policy,
            flows=flows,
        )
        paths = _enumerate_paths(
            assets=assets,
            flows=flows,
            controls=controls,
            policy=self._policy,
        )
        exposed = tuple(path for path in paths if path.exposed)
        controlled = tuple(path for path in paths if not path.exposed)
        critical_exposed = tuple(
            path for path in exposed if path.target_sensitivity == AssetSensitivity.CRITICAL
        )
        prioritized = tuple(
            path.path_id
            for path in sorted(
                exposed,
                key=lambda item: (-item.risk_score, item.target_asset_id, item.path_id),
            )
        )
        max_risk = max((path.risk_score for path in exposed), default=0)

        if set(request.declared_exposed_path_ids) != set(prioritized):
            _reject(AttackPathRejectReason.DECLARED_PATH_MISMATCH, "caller-declared exposed paths differ from evidence-derived paths")
        if request.declared_max_exposed_risk_score != max_risk:
            _reject(AttackPathRejectReason.DECLARED_RISK_MISMATCH, "caller-declared maximum risk differs from evidence-derived risk")

        evidence_document = {
            "architecture_sha256": manifest_sha,
            "attacker_profile_id": request.attacker_profile_id,
            "control_catalog_sha256": posture.control_catalog_sha256.casefold(),
            "entry_asset_ids": sorted(request.entry_asset_ids),
            "exposed_path_ids": list(prioritized),
            "max_exposed_risk_score": max_risk,
            "path_facts": [asdict(path) for path in paths],
            "posture_evidence_sha256": posture.posture_evidence_sha256.casefold(),
            "target_asset_ids": sorted(request.target_asset_ids),
        }
        for item in evidence_document["path_facts"]:
            item["target_sensitivity"] = str(item["target_sensitivity"])
        evidence_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return VerifiedAttackPathAssessment(
            architecture_id=manifest.architecture_id,
            architecture_version=manifest.version,
            architecture_sha256=manifest_sha,
            posture_evidence_sha256=posture.posture_evidence_sha256.casefold(),
            control_catalog_sha256=posture.control_catalog_sha256.casefold(),
            attacker_profile_id=request.attacker_profile_id,
            entry_asset_ids=tuple(sorted(request.entry_asset_ids)),
            target_asset_ids=tuple(sorted(request.target_asset_ids)),
            topology_path_count=len(paths),
            exposed_path_count=len(exposed),
            controlled_path_count=len(controlled),
            critical_exposed_path_count=len(critical_exposed),
            max_exposed_risk_score=max_risk,
            prioritized_exposed_path_ids=prioritized,
            paths=paths,
            assessment_evidence_sha256=evidence_sha,
        )
