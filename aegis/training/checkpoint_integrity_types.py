from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P9E_POLICY_VERSION = "training-checkpoint-lineage-v1"
P9E_SCHEMA_VERSION = "aegis-training-checkpoint-manifest-v1"
P9E_ASSESSMENT_SCHEMA_VERSION = "aegis-training-checkpoint-assessment-v1"
P9E_ASSESSMENT_MODE = "deterministic-evidence-bound-training-checkpoint-v1"


class CheckpointAction(str, Enum):
    SAVE = "save"
    RESUME = "resume"
    ROLLBACK = "rollback"


class CheckpointDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class CheckpointRisk(str, Enum):
    UPSTREAM_P9D_INVALID = "upstream_p9d_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    LINEAGE_IDENTITY_MISMATCH = "lineage_identity_mismatch"
    CHECKPOINT_COVERAGE_MISMATCH = "checkpoint_coverage_mismatch"
    CHECKPOINT_JOB_SCOPE_MISMATCH = "checkpoint_job_scope_mismatch"
    CHECKPOINT_STEP_INVALID = "checkpoint_step_invalid"
    CHECKPOINT_PARENT_MISMATCH = "checkpoint_parent_mismatch"
    CHECKPOINT_STATE_MISMATCH = "checkpoint_state_mismatch"
    CHECKPOINT_ARTIFACT_MISMATCH = "checkpoint_artifact_mismatch"
    CHECKPOINT_FORMAT_UNSAFE = "checkpoint_format_unsafe"
    CHECKPOINT_MUTABILITY_UNSAFE = "checkpoint_mutability_unsafe"
    CHECKPOINT_EXTERNAL_REFERENCE_UNSAFE = "checkpoint_external_reference_unsafe"
    ACTION_UNAUTHORIZED = "action_unauthorized"
    ACTION_SOURCE_MISMATCH = "action_source_mismatch"
    ACTION_TARGET_MISMATCH = "action_target_mismatch"
    NEXT_STEP_INVALID = "next_step_invalid"
    ROLLBACK_AUTHORIZATION_INVALID = "rollback_authorization_invalid"
    ROLLBACK_TARGET_UNAUTHORIZED = "rollback_target_unauthorized"
    AUTHORIZATION_EXPIRED = "authorization_expired"


class CheckpointRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class CheckpointSecurityRejected(ValueError):
    def __init__(self, reason: CheckpointRejectReason, message: str):
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message


def reject(reason: CheckpointRejectReason, message: str) -> None:
    raise CheckpointSecurityRejected(reason, message)


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {k: _jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(k.value if isinstance(k, Enum) else k): _jsonable(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    return value


def canonical_json_bytes(value) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_json(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class TrainingCheckpointEvidence:
    checkpoint_id: str
    execution_id: str
    job_id: str
    attempt: int
    step: int
    epoch_milli: int
    parent_checkpoint_id: str
    model_state_sha256: str
    optimizer_state_sha256: str
    rng_state_sha256: str
    data_cursor_sha256: str
    trainer_state_sha256: str
    artifact_sha256: str
    serialization_format: str
    immutable: bool
    external_reference: bool
    custom_deserializer: bool


@dataclass(frozen=True)
class CheckpointOperationAuthorization:
    authorization_id: str
    principal_id: str
    p9d_assessment_sha256: str
    action: CheckpointAction
    source_checkpoint_id: str
    target_checkpoint_id: str
    issued_at_epoch: int
    expires_at_epoch: int
    reason_code: str


@dataclass(frozen=True)
class TrainingCheckpointManifest:
    schema_version: str
    lineage_id: str
    created_at_epoch: int
    p9d_assessment_sha256: str
    execution_id: str
    job_id: str
    checkpoints: tuple[TrainingCheckpointEvidence, ...]
    active_checkpoint_id: str
    action: CheckpointAction
    source_checkpoint_id: str
    target_checkpoint_id: str
    next_step: int
    authorization: CheckpointOperationAuthorization


@dataclass(frozen=True)
class TrainingCheckpointPolicy:
    policy_version: str
    expected_lineage_id: str
    expected_manifest_sha256: str
    expected_p9d_assessment_sha256: str
    expected_execution_id: str
    expected_job_id: str
    expected_principal_id: str
    expected_checkpoint_order: tuple[str, ...]
    expected_checkpoint_step_by_id: Mapping[str, int]
    expected_checkpoint_parent_by_id: Mapping[str, str]
    expected_checkpoint_artifact_sha256_by_id: Mapping[str, str]
    expected_model_state_sha256_by_id: Mapping[str, str]
    expected_optimizer_state_sha256_by_id: Mapping[str, str]
    expected_rng_state_sha256_by_id: Mapping[str, str]
    expected_data_cursor_sha256_by_id: Mapping[str, str]
    expected_trainer_state_sha256_by_id: Mapping[str, str]
    allowed_serialization_formats: tuple[str, ...]
    allowed_actions: tuple[CheckpointAction, ...]
    allowed_rollback_targets: tuple[str, ...]
    max_checkpoint_step: int
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class TrainingCheckpointRequest:
    lineage_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_checkpoint_ids: tuple[str, ...]
    declared_active_checkpoint_id: str
    declared_action: CheckpointAction
    declared_source_checkpoint_id: str
    declared_target_checkpoint_id: str
    declared_next_step: int
    declared_upstream_bound: bool
    declared_lineage_integrity: bool
    declared_state_integrity: bool
    declared_operation_authorized: bool
    declared_checkpoint_safe: bool


@dataclass(frozen=True)
class VerifiedTrainingCheckpointAssessment:
    lineage_id: str
    execution_id: str
    job_id: str
    decision: CheckpointDecision
    risks: tuple[CheckpointRisk, ...]
    p9d_assessment_sha256: str
    checkpoint_ids: tuple[str, ...]
    active_checkpoint_id: str
    action: CheckpointAction
    source_checkpoint_id: str
    target_checkpoint_id: str
    next_step: int
    upstream_p9d_bound: bool
    checkpoint_lineage_verified: bool
    checkpoint_state_integrity_verified: bool
    operation_authorization_verified: bool
    rollback_safe: bool
    caller_declared_safety_trusted: bool
    production_checkpoint_store_integrated: bool
    cryptographic_checkpoint_signature_verified: bool
    proof_of_resume_execution: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def training_checkpoint_manifest_digest(manifest: TrainingCheckpointManifest) -> str:
    return digest_json(manifest)
