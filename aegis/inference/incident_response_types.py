from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P10I_POLICY_VERSION = "inference-incident-response-exit-gate-v1"
P10I_SCHEMA_VERSION = "aegis-inference-incident-response-manifest-v1"
P10I_ASSESSMENT_SCHEMA_VERSION = "aegis-inference-incident-response-assessment-v1"
P10I_ASSESSMENT_MODE = "deterministic-evidence-bound-compromise-recovery-exit-gate-v1"


class IncidentDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ExitGateStatus(str, Enum):
    PASS = "pass"
    PASS_WITH_DEFERRED = "pass_with_deferred"
    FAIL = "fail"


class IncidentRisk(str, Enum):
    UPSTREAM_P10H_INVALID = "upstream_p10h_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    REQUEST_ROUTE_MISMATCH = "request_route_mismatch"
    INCIDENT_IDENTITY_MISMATCH = "incident_identity_mismatch"
    SIGNAL_COVERAGE_MISMATCH = "signal_coverage_mismatch"
    SIGNAL_SEQUENCE_MISMATCH = "signal_sequence_mismatch"
    SIGNAL_CHAIN_MISMATCH = "signal_chain_mismatch"
    SIGNAL_BINDING_MISMATCH = "signal_binding_mismatch"
    DETECTION_LATENCY_EXCEEDED = "detection_latency_exceeded"
    CONTAINMENT_COVERAGE_MISMATCH = "containment_coverage_mismatch"
    CONTAINMENT_SEQUENCE_MISMATCH = "containment_sequence_mismatch"
    CONTAINMENT_CHAIN_MISMATCH = "containment_chain_mismatch"
    CONTAINMENT_AUTHORIZATION_MISMATCH = "containment_authorization_mismatch"
    CONTAINMENT_TARGET_MISMATCH = "containment_target_mismatch"
    CONTAINMENT_LATENCY_EXCEEDED = "containment_latency_exceeded"
    RECOVERY_COVERAGE_MISMATCH = "recovery_coverage_mismatch"
    RECOVERY_SEQUENCE_MISMATCH = "recovery_sequence_mismatch"
    RECOVERY_CHAIN_MISMATCH = "recovery_chain_mismatch"
    RECOVERY_GENERATION_ROLLBACK = "recovery_generation_rollback"
    RECOVERY_NOT_VERIFIED = "recovery_not_verified"
    FORENSIC_COVERAGE_MISMATCH = "forensic_coverage_mismatch"
    FORENSIC_ARTIFACT_DIGEST_MISMATCH = "forensic_artifact_digest_mismatch"
    FORENSIC_CHAIN_MISMATCH = "forensic_chain_mismatch"
    FORENSIC_IMMUTABILITY_UNPROVEN = "forensic_immutability_unproven"
    EXIT_GATE_CONTROL_COVERAGE_MISMATCH = "exit_gate_control_coverage_mismatch"
    EXIT_GATE_STATUS_MISMATCH = "exit_gate_status_mismatch"
    DEFERRED_MASTERY_DEBT_MISSING = "deferred_mastery_debt_missing"
    HOSTED_CI_CLAIM_UNSUPPORTED = "hosted_ci_claim_unsupported"
    PRODUCTION_CLAIM_UNSUPPORTED = "production_claim_unsupported"
    PROFESSIONAL_MASTERY_CLAIM_UNSUPPORTED = "professional_mastery_claim_unsupported"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class IncidentRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class InferenceIncidentResponseRejected(ValueError):
    def __init__(self, reason: IncidentRejectReason, message: str):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason.value}: {message}")


def reject(reason: IncidentRejectReason, message: str) -> None:
    raise InferenceIncidentResponseRejected(reason, message)


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(key.value if isinstance(key, Enum) else key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json_text(value) -> str:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value) -> str:
    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IncidentSignalEvidence:
    signal_id: str
    sequence_no: int
    signal_type: str
    source_id: str
    request_id: str
    tenant_id: str
    session_id: str
    observed_at_epoch: int
    severity: str
    artifact_sha256: str
    previous_signal_sha256: str


@dataclass(frozen=True)
class ContainmentActionEvidence:
    action_id: str
    sequence_no: int
    action_type: str
    target_id: str
    started_at_epoch: int
    completed_at_epoch: int
    authorization_sha256: str
    result_sha256: str
    previous_action_sha256: str


@dataclass(frozen=True)
class RecoveryStepEvidence:
    recovery_id: str
    sequence_no: int
    recovery_type: str
    target_id: str
    expected_generation: int
    observed_generation: int
    verified: bool
    completed_at_epoch: int
    evidence_sha256: str
    previous_recovery_sha256: str


@dataclass(frozen=True)
class ForensicArtifactEvidence:
    artifact_id: str
    artifact_kind: str
    source_id: str
    collected_at_epoch: int
    content_sha256: str
    immutable_snapshot: bool
    previous_artifact_sha256: str
    chain_of_custody_sha256: str


@dataclass(frozen=True)
class Phase10ExitGateEvidence:
    required_controls: tuple[str, ...]
    validated_controls: tuple[str, ...]
    local_runtime_gates: tuple[str, ...]
    deferred_mastery_items: tuple[str, ...]
    hosted_ci_execution_verified: bool
    production_validation_claimed: bool
    phase10_exit_eligible: bool
    professional_mastery_complete: bool
    status: ExitGateStatus


@dataclass(frozen=True)
class InferenceIncidentResponseManifest:
    schema_version: str
    manifest_id: str
    created_at_epoch: int
    p10h_assessment_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    stream_id: str
    router_id: str
    router_generation: int
    replica_ids: tuple[str, ...]
    routing_ids: tuple[str, ...]
    incident_id: str
    compromised_replica_id: str
    detection_started_at_epoch: int
    signals: tuple[IncidentSignalEvidence, ...]
    containment_actions: tuple[ContainmentActionEvidence, ...]
    recovery_steps: tuple[RecoveryStepEvidence, ...]
    forensic_artifacts: tuple[ForensicArtifactEvidence, ...]
    exit_gate: Phase10ExitGateEvidence
    network_operations: int = 0


@dataclass(frozen=True)
class InferenceIncidentResponsePolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_p10h_assessment_sha256: str
    expected_request_id: str
    expected_tenant_id: str
    expected_session_id: str
    expected_target_model_id: str
    expected_target_model_revision: str
    expected_adapter_ids: tuple[str, ...]
    expected_adapter_generation: int
    expected_partition_ids: tuple[str, ...]
    expected_stream_id: str
    expected_router_id: str
    minimum_router_generation: int
    expected_replica_ids: tuple[str, ...]
    expected_routing_ids: tuple[str, ...]
    expected_incident_id: str
    expected_compromised_replica_id: str
    expected_signal_ids: tuple[str, ...]
    required_signal_types: tuple[str, ...]
    expected_containment_action_ids: tuple[str, ...]
    required_containment_actions: tuple[str, ...]
    expected_recovery_ids: tuple[str, ...]
    required_recovery_types: tuple[str, ...]
    expected_forensic_artifact_ids: tuple[str, ...]
    required_forensic_kinds: tuple[str, ...]
    required_exit_controls: tuple[str, ...]
    required_local_runtime_gates: tuple[str, ...]
    required_deferred_mastery_items: tuple[str, ...]
    max_detection_latency_seconds: int
    max_containment_latency_seconds: int
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class InferenceIncidentResponseRequest:
    manifest_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_request_id: str
    declared_tenant_id: str
    declared_session_id: str
    declared_incident_id: str
    declared_compromised_replica_id: str
    declared_router_generation: int
    declared_upstream_p10h_bound: bool
    declared_detection_complete: bool
    declared_containment_complete: bool
    declared_recovery_complete: bool
    declared_forensics_complete: bool
    declared_exit_gate_safe: bool
    declared_gpu_debt_carried: bool
    declared_hosted_ci_verified: bool
    declared_production_validated: bool
    declared_professional_mastery_complete: bool
    declared_incident_response_safe: bool


@dataclass(frozen=True)
class VerifiedInferenceIncidentResponseAssessment:
    manifest_id: str
    manifest_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    decision: IncidentDecision
    risks: tuple[IncidentRisk, ...]
    p10h_assessment_sha256: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    stream_id: str
    router_id: str
    router_generation: int
    replica_ids: tuple[str, ...]
    routing_ids: tuple[str, ...]
    incident_id: str
    compromised_replica_id: str
    signal_ids: tuple[str, ...]
    containment_action_ids: tuple[str, ...]
    recovery_ids: tuple[str, ...]
    forensic_artifact_ids: tuple[str, ...]
    exit_gate_status: ExitGateStatus
    upstream_p10h_bound: bool
    detection_verified: bool
    containment_verified: bool
    recovery_verified: bool
    forensic_chain_verified: bool
    phase10_exit_gate_verified: bool
    deferred_mastery_debt_carried: bool
    caller_declared_safety_trusted: bool
    production_soc_integrated: bool
    production_siem_integrated: bool
    production_orchestrator_remediation_validated: bool
    cross_zone_recovery_validated: bool
    hosted_ci_execution_verified: bool
    production_validation_claimed: bool
    professional_mastery_complete: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def signal_digest(signal: IncidentSignalEvidence) -> str:
    return digest_json(signal)


def containment_digest(action: ContainmentActionEvidence) -> str:
    return digest_json(action)


def recovery_digest(step: RecoveryStepEvidence) -> str:
    return digest_json(step)


def forensic_chain_digest(
    artifact_id: str,
    artifact_kind: str,
    source_id: str,
    content_sha256: str,
    previous_artifact_sha256: str,
) -> str:
    return digest_json({
        "artifact_id": artifact_id,
        "artifact_kind": artifact_kind,
        "source_id": source_id,
        "content_sha256": content_sha256.casefold(),
        "previous_artifact_sha256": previous_artifact_sha256.casefold(),
    })


def containment_authorization_digest(
    incident_id: str,
    action_id: str,
    action_type: str,
    target_id: str,
) -> str:
    return digest_json({
        "incident_id": incident_id,
        "action_id": action_id,
        "action_type": action_type,
        "target_id": target_id,
    })


def incident_seed_digest(incident_id: str, request_id: str, tenant_id: str, session_id: str) -> str:
    return digest_json({
        "incident_id": incident_id,
        "request_id": request_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
    })


def inference_incident_response_manifest_digest(manifest: InferenceIncidentResponseManifest) -> str:
    return digest_json(manifest)
