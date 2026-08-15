from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P9D_POLICY_VERSION = "training-execution-provenance-v1"
P9D_SCHEMA_VERSION = "aegis-training-execution-manifest-v1"
P9D_ASSESSMENT_SCHEMA_VERSION = "aegis-training-execution-assessment-v1"
P9D_ASSESSMENT_MODE = "deterministic-evidence-bound-training-execution-v1"


class TrainingExecutionDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class TrainingExecutionRisk(str, Enum):
    UPSTREAM_P9C_INVALID = "upstream_p9c_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    JOB_IDENTITY_MISMATCH = "job_identity_mismatch"
    SCHEDULER_IDENTITY_MISMATCH = "scheduler_identity_mismatch"
    CODE_IDENTITY_MISMATCH = "code_identity_mismatch"
    CODE_INTEGRITY_MISMATCH = "code_integrity_mismatch"
    CONFIG_MISMATCH = "config_mismatch"
    DYNAMIC_OR_REMOTE_CODE = "dynamic_or_remote_code"
    ENVIRONMENT_IDENTITY_MISMATCH = "environment_identity_mismatch"
    PRIVILEGED_RUNTIME = "privileged_runtime"
    NETWORK_POLICY_MISMATCH = "network_policy_mismatch"
    FILESYSTEM_POLICY_MISMATCH = "filesystem_policy_mismatch"
    DEVICE_POLICY_MISMATCH = "device_policy_mismatch"
    ENV_ALLOWLIST_MISMATCH = "env_allowlist_mismatch"
    SECRET_COVERAGE_MISMATCH = "secret_coverage_mismatch"
    SECRET_SCOPE_EXCESSIVE = "secret_scope_excessive"
    SECRET_LEASE_INVALID = "secret_lease_invalid"
    SECRET_EXPOSURE_UNSAFE = "secret_exposure_unsafe"
    CAPABILITY_COVERAGE_MISMATCH = "capability_coverage_mismatch"
    CAPABILITY_EXCESSIVE = "capability_excessive"
    OUTPUT_IDENTITY_MISMATCH = "output_identity_mismatch"


class TrainingExecutionRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class TrainingExecutionSecurityRejected(ValueError):
    def __init__(self, reason: TrainingExecutionRejectReason, message: str):
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message


def reject(reason: TrainingExecutionRejectReason, message: str) -> None:
    raise TrainingExecutionSecurityRejected(reason, message)


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
class TrainingJobIdentityEvidence:
    job_id: str
    scheduler: str
    namespace: str
    queue: str
    service_account: str
    executor_principal: str
    identity_token_audience: str
    attempt: int
    launch_nonce_sha256: str


@dataclass(frozen=True)
class TrainingCodeEvidence:
    repository_id: str
    commit_sha: str
    tree_sha: str
    entrypoint: str
    entrypoint_sha256: str
    config_sha256: str
    dependency_lock_sha256: str
    source_read_only: bool
    remote_fetch_allowed: bool
    dynamic_dependency_install: bool
    custom_startup_script: bool


@dataclass(frozen=True)
class TrainingRuntimeEnvironmentEvidence:
    image_ref: str
    image_sha256: str
    python_version: str
    framework_version: str
    accelerator_runtime: str
    device_profile: str
    environment_variable_names: tuple[str, ...]
    network_egress: tuple[str, ...]
    writable_paths: tuple[str, ...]
    host_mounts: tuple[str, ...]
    root_filesystem_read_only: bool
    privileged: bool
    host_network: bool
    allow_privilege_escalation: bool
    docker_socket_mounted: bool


@dataclass(frozen=True)
class TrainingSecretLeaseEvidence:
    secret_id: str
    provider: str
    version: str
    purpose: str
    scope: str
    mount_path: str
    issued_to_principal: str
    issued_at_epoch: int
    expires_at_epoch: int
    exportable: bool
    injected_as_environment_variable: bool


@dataclass(frozen=True)
class TrainingCapabilityEvidence:
    capability_id: str
    resource: str
    actions: tuple[str, ...]


@dataclass(frozen=True)
class TrainingExecutionManifest:
    schema_version: str
    execution_id: str
    created_at_epoch: int
    p9c_assessment_sha256: str
    admission_manifest_id: str
    job: TrainingJobIdentityEvidence
    code: TrainingCodeEvidence
    environment: TrainingRuntimeEnvironmentEvidence
    secrets: tuple[TrainingSecretLeaseEvidence, ...]
    capabilities: tuple[TrainingCapabilityEvidence, ...]
    planned_output_artifact_id: str


@dataclass(frozen=True)
class TrainingExecutionPolicy:
    policy_version: str
    expected_execution_id: str
    expected_manifest_sha256: str
    expected_p9c_assessment_sha256: str
    expected_admission_manifest_id: str
    expected_principal_id: str
    expected_task_id: str
    expected_output_artifact_id: str
    expected_job_id: str
    expected_scheduler: str
    expected_namespace: str
    expected_queue: str
    expected_service_account: str
    expected_executor_principal: str
    expected_identity_token_audience: str
    expected_attempt: int
    expected_launch_nonce_sha256: str
    expected_repository_id: str
    expected_commit_sha: str
    expected_tree_sha: str
    expected_entrypoint: str
    expected_entrypoint_sha256: str
    expected_config_sha256: str
    expected_dependency_lock_sha256: str
    expected_image_ref: str
    expected_image_sha256: str
    expected_python_version: str
    expected_framework_version: str
    expected_accelerator_runtime: str
    expected_device_profile: str
    allowed_environment_variable_names: tuple[str, ...]
    allowed_network_egress: tuple[str, ...]
    allowed_writable_paths: tuple[str, ...]
    expected_secret_order: tuple[str, ...]
    expected_secret_provider_by_id: Mapping[str, str]
    expected_secret_version_by_id: Mapping[str, str]
    expected_secret_purpose_by_id: Mapping[str, str]
    expected_secret_scope_by_id: Mapping[str, str]
    expected_secret_mount_path_by_id: Mapping[str, str]
    expected_capability_order: tuple[str, ...]
    expected_capability_resource_by_id: Mapping[str, str]
    expected_capability_actions_by_id: Mapping[str, tuple[str, ...]]
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class TrainingExecutionRequest:
    execution_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_job_id: str
    declared_commit_sha: str
    declared_config_sha256: str
    declared_image_sha256: str
    declared_secret_ids: tuple[str, ...]
    declared_capability_ids: tuple[str, ...]
    declared_admission_bound: bool
    declared_job_identity_bound: bool
    declared_code_config_bound: bool
    declared_environment_safe: bool
    declared_secrets_least_privilege: bool
    declared_capabilities_least_privilege: bool
    declared_execution_safe: bool


@dataclass(frozen=True)
class VerifiedTrainingExecutionAssessment:
    execution_id: str
    job_id: str
    decision: TrainingExecutionDecision
    risks: tuple[TrainingExecutionRisk, ...]
    p9c_assessment_sha256: str
    admission_manifest_id: str
    principal_id: str
    task_id: str
    code_commit_sha: str
    code_tree_sha: str
    config_sha256: str
    image_sha256: str
    secret_ids: tuple[str, ...]
    secret_scopes: tuple[str, ...]
    capability_ids: tuple[str, ...]
    planned_output_artifact_id: str
    upstream_p9c_bound: bool
    job_identity_verified: bool
    code_config_provenance_verified: bool
    environment_policy_verified: bool
    secret_least_privilege_verified: bool
    capability_least_privilege_verified: bool
    caller_declared_safety_trusted: bool
    production_scheduler_integrated: bool
    production_secret_manager_integrated: bool
    production_container_runtime_integrated: bool
    proof_of_training_execution: bool
    hardware_attestation_verified: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def training_execution_manifest_digest(manifest: TrainingExecutionManifest) -> str:
    return digest_json(manifest)
