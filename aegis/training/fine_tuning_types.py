from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P9C_POLICY_VERSION = "fine-tuning-authorization-base-binding-v1"
P9C_SCHEMA_VERSION = "aegis-fine-tuning-admission-manifest-v1"
P9C_ASSESSMENT_SCHEMA_VERSION = "aegis-fine-tuning-admission-assessment-v1"
P9C_ASSESSMENT_MODE = "deterministic-evidence-bound-fine-tuning-admission-v1"
ZERO_SHA256 = "0" * 64


class FineTuneMode(str, Enum):
    FULL = "full"
    LORA = "lora"
    ADAPTER = "adapter"


class FineTuneDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class FineTuneRisk(str, Enum):
    UPSTREAM_P9B_INVALID = "upstream_p9b_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    SELECTED_DATA_MISMATCH = "selected_data_mismatch"
    AUTHORIZATION_INVALID = "authorization_invalid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    PRINCIPAL_TASK_MISMATCH = "principal_task_mismatch"
    BASE_MODEL_IDENTITY_MISMATCH = "base_model_identity_mismatch"
    BASE_MODEL_DIGEST_MISMATCH = "base_model_digest_mismatch"
    BASE_MODEL_RUNTIME_MISMATCH = "base_model_runtime_mismatch"
    MODE_UNAUTHORIZED = "mode_unauthorized"
    ADAPTER_COVERAGE_MISMATCH = "adapter_coverage_mismatch"
    ADAPTER_FORMAT_UNSAFE = "adapter_format_unsafe"
    ADAPTER_RANK_INVALID = "adapter_rank_invalid"
    ADAPTER_ALPHA_INVALID = "adapter_alpha_invalid"
    ADAPTER_TARGET_UNAUTHORIZED = "adapter_target_unauthorized"
    ADAPTER_INIT_MISMATCH = "adapter_init_mismatch"
    ADAPTER_STACK_INVALID = "adapter_stack_invalid"
    REMOTE_OR_CUSTOM_CODE = "remote_or_custom_code"
    HYPERPARAMETER_OUT_OF_POLICY = "hyperparameter_out_of_policy"
    OUTPUT_IDENTITY_MISMATCH = "output_identity_mismatch"


class FineTuneRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class FineTuningSecurityRejected(ValueError):
    def __init__(self, reason: FineTuneRejectReason, message: str):
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message


def reject(reason: FineTuneRejectReason, message: str) -> None:
    raise FineTuningSecurityRejected(reason, message)


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
class FineTuneBaseModelEvidence:
    model_id: str
    revision: str
    artifact_sha256: str
    package_sha256: str
    tokenizer_sha256: str
    runtime_profile: str


@dataclass(frozen=True)
class FineTuneAdapterSpec:
    adapter_id: str
    mode: FineTuneMode
    serialization_format: str
    rank: int
    alpha_bps: int
    target_modules: tuple[str, ...]
    init_sha256: str
    parent_adapter_ids: tuple[str, ...]
    remote_code: bool = False
    custom_code: bool = False
    native_extensions: bool = False


@dataclass(frozen=True)
class FineTuneHyperparameters:
    learning_rate_micros: int
    epochs_milli: int
    batch_size: int
    max_steps: int
    seed: int
    gradient_accumulation_steps: int


@dataclass(frozen=True)
class FineTuneAuthorizationEvidence:
    grant_id: str
    principal_id: str
    task_id: str
    p9b_assessment_sha256: str
    base_model_artifact_sha256: str
    selected_data_sha256: str
    issued_at_epoch: int
    expires_at_epoch: int
    allowed_modes: tuple[FineTuneMode, ...]


@dataclass(frozen=True)
class FineTuningAdmissionManifest:
    schema_version: str
    manifest_id: str
    dataset_id: str
    dataset_version: str
    created_at_epoch: int
    p9b_assessment_sha256: str
    selected_record_ids: tuple[str, ...]
    selected_data_sha256: str
    principal_id: str
    task_id: str
    base_model: FineTuneBaseModelEvidence
    adapters: tuple[FineTuneAdapterSpec, ...]
    hyperparameters: FineTuneHyperparameters
    authorization: FineTuneAuthorizationEvidence
    planned_output_artifact_id: str


@dataclass(frozen=True)
class FineTuningAdmissionPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_dataset_id: str
    expected_dataset_version: str
    expected_manifest_sha256: str
    expected_p9b_assessment_sha256: str
    expected_selected_record_ids: tuple[str, ...]
    expected_selected_data_sha256: str
    expected_principal_id: str
    expected_task_id: str
    expected_grant_id: str
    expected_base_model_id: str
    expected_base_model_revision: str
    expected_base_model_artifact_sha256: str
    expected_base_model_package_sha256: str
    expected_tokenizer_sha256: str
    expected_runtime_profile: str
    expected_adapter_order: tuple[str, ...]
    allowed_modes: tuple[FineTuneMode, ...]
    allowed_serialization_formats: tuple[str, ...]
    expected_adapter_init_sha256_by_id: Mapping[str, str]
    allowed_target_modules: tuple[str, ...]
    max_adapter_rank: int
    max_adapter_alpha_bps: int
    max_adapter_stack_depth: int
    min_learning_rate_micros: int
    max_learning_rate_micros: int
    min_epochs_milli: int
    max_epochs_milli: int
    max_batch_size: int
    max_steps: int
    allowed_seeds: tuple[int, ...]
    max_gradient_accumulation_steps: int
    expected_output_artifact_id: str
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class FineTuningAdmissionRequest:
    manifest_id: str
    manifest_sha256: str
    dataset_id: str
    dataset_version: str
    evaluated_at_epoch: int
    declared_selected_record_ids: tuple[str, ...]
    declared_selected_data_sha256: str
    declared_base_model_artifact_sha256: str
    declared_adapter_ids: tuple[str, ...]
    declared_authorized: bool
    declared_base_model_bound: bool
    declared_adapter_policy_safe: bool
    declared_training_admission_safe: bool


@dataclass(frozen=True)
class VerifiedFineTuningAdmissionAssessment:
    manifest_id: str
    dataset_id: str
    dataset_version: str
    decision: FineTuneDecision
    risks: tuple[FineTuneRisk, ...]
    principal_id: str
    task_id: str
    selected_record_ids: tuple[str, ...]
    selected_data_sha256: str
    base_model_id: str
    base_model_revision: str
    base_model_artifact_sha256: str
    adapter_ids: tuple[str, ...]
    planned_output_artifact_id: str
    upstream_p9b_bound: bool
    authorization_verified: bool
    base_model_binding_verified: bool
    adapter_policy_verified: bool
    hyperparameter_policy_verified: bool
    caller_declared_safety_trusted: bool
    production_training_runtime_integrated: bool
    production_identity_provider_integrated: bool
    proof_of_training_execution: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def selected_training_data_digest(p9b_assessment_sha256: str, record_ids: tuple[str, ...]) -> str:
    return digest_json({"p9b_assessment_sha256": p9b_assessment_sha256.casefold(), "record_ids": tuple(sorted(record_ids))})


def fine_tuning_manifest_digest(manifest: FineTuningAdmissionManifest) -> str:
    return digest_json(manifest)
