from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.training.fine_tuning_types import (
    P9C_ASSESSMENT_MODE,
    P9C_ASSESSMENT_SCHEMA_VERSION,
    FineTuneDecision,
    VerifiedFineTuningAdmissionAssessment,
)
from aegis.training.training_execution_types import *

NOW = 1_800_030_000
EXECUTION_ID = "p9d-training-execution-001"
P9C_MANIFEST_ID = "p9c-fine-tuning-manifest-001"
P9C_ASSESSMENT_SHA = "0c2091bc9f2e50842f2d4642c3aca39ff4e444cc15a41d639579d7b98ec77729"
PRINCIPAL_ID = "trainer-security"
TASK_ID = "fine-tune-helpdesk-security-v1"
OUTPUT_ID = "adapter://aegisdesk/helpdesk-security-v1"
JOB_ID = "training-job-p9d-001"
EXECUTOR_PRINCIPAL = "spiffe://aegisdesk/training/executor-p9d"
SECRET_IDS = ("secret-base-model-read", "secret-output-artifact-write", "secret-metrics-write")
CAPABILITY_IDS = ("cap-dataset-read", "cap-base-model-read", "cap-checkpoint-write", "cap-output-write")


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_sha(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def build_p9c_assessment() -> VerifiedFineTuningAdmissionAssessment:
    return VerifiedFineTuningAdmissionAssessment(
        manifest_id=P9C_MANIFEST_ID,
        dataset_id="aegisdesk-helpdesk-training",
        dataset_version="2026.08-p9a",
        decision=FineTuneDecision.ALLOW,
        risks=(),
        principal_id=PRINCIPAL_ID,
        task_id=TASK_ID,
        selected_record_ids=tuple(f"record-{i:02d}" for i in range(1, 9)),
        selected_data_sha256=h("p9c-selected-data"),
        base_model_id="aegisdesk-base-7b",
        base_model_revision="r42",
        base_model_artifact_sha256=h("base-model:artifact:aegisdesk-base-7b@r42"),
        adapter_ids=("adapter-helpdesk-lora", "adapter-security-policy"),
        planned_output_artifact_id=OUTPUT_ID,
        upstream_p9b_bound=True,
        authorization_verified=True,
        base_model_binding_verified=True,
        adapter_policy_verified=True,
        hyperparameter_policy_verified=True,
        caller_declared_safety_trusted=False,
        production_training_runtime_integrated=False,
        production_identity_provider_integrated=False,
        proof_of_training_execution=False,
        assessment_schema_version=P9C_ASSESSMENT_SCHEMA_VERSION,
        assessment_mode=P9C_ASSESSMENT_MODE,
        assessment_evidence_sha256=P9C_ASSESSMENT_SHA,
    )


def build_fixture() -> dict[str, object]:
    job = TrainingJobIdentityEvidence(
        job_id=JOB_ID,
        scheduler="synthetic-scheduler-v1",
        namespace="training-security",
        queue="gpu-restricted",
        service_account="trainer-executor",
        executor_principal=EXECUTOR_PRINCIPAL,
        identity_token_audience="aegisdesk-training-control",
        attempt=1,
        launch_nonce_sha256=h("p9d-launch-nonce-001"),
    )
    code = TrainingCodeEvidence(
        repository_id="aegisdesk-training",
        commit_sha=git_sha("training-code-commit:p9d:v1"),
        tree_sha=git_sha("training-code-tree:p9d:v1"),
        entrypoint="trainer/run_finetune.py",
        entrypoint_sha256=h("trainer/run_finetune.py:p9d:v1"),
        config_sha256=h("training-config:p9d:v1"),
        dependency_lock_sha256=h("training-lock:p9d:v1"),
        source_read_only=True,
        remote_fetch_allowed=False,
        dynamic_dependency_install=False,
        custom_startup_script=False,
    )
    environment = TrainingRuntimeEnvironmentEvidence(
        image_ref="registry.internal/aegisdesk/trainer@sha256:" + h("trainer-image:p9d:v1"),
        image_sha256=h("trainer-image:p9d:v1"),
        python_version="3.12.8",
        framework_version="transformers-4.57.0",
        accelerator_runtime="cuda-12.8",
        device_profile="gpu-a100-1x",
        environment_variable_names=("AEGIS_JOB_ID", "AEGIS_OUTPUT_ID", "PYTHONHASHSEED"),
        network_egress=("artifact-store.internal:443", "metrics.internal:443"),
        writable_paths=("/workspace/checkpoints", "/workspace/output"),
        host_mounts=(),
        root_filesystem_read_only=True,
        privileged=False,
        host_network=False,
        allow_privilege_escalation=False,
        docker_socket_mounted=False,
    )
    secrets = (
        TrainingSecretLeaseEvidence(
            secret_id="secret-base-model-read",
            provider="synthetic-secret-broker",
            version="v7",
            purpose="read-pinned-base-model",
            scope="model:aegisdesk-base-7b:r42:read",
            mount_path="/run/secrets/base-model",
            issued_to_principal=EXECUTOR_PRINCIPAL,
            issued_at_epoch=NOW - 30,
            expires_at_epoch=NOW + 300,
            exportable=False,
            injected_as_environment_variable=False,
        ),
        TrainingSecretLeaseEvidence(
            secret_id="secret-output-artifact-write",
            provider="synthetic-secret-broker",
            version="v3",
            purpose="write-planned-adapter-output",
            scope="artifact:aegisdesk/helpdesk-security-v1:write",
            mount_path="/run/secrets/output-artifact",
            issued_to_principal=EXECUTOR_PRINCIPAL,
            issued_at_epoch=NOW - 30,
            expires_at_epoch=NOW + 300,
            exportable=False,
            injected_as_environment_variable=False,
        ),
        TrainingSecretLeaseEvidence(
            secret_id="secret-metrics-write",
            provider="synthetic-secret-broker",
            version="v2",
            purpose="write-training-metrics",
            scope="metrics:training-job-p9d-001:write",
            mount_path="/run/secrets/metrics",
            issued_to_principal=EXECUTOR_PRINCIPAL,
            issued_at_epoch=NOW - 30,
            expires_at_epoch=NOW + 300,
            exportable=False,
            injected_as_environment_variable=False,
        ),
    )
    capabilities = (
        TrainingCapabilityEvidence(
            capability_id="cap-dataset-read",
            resource="dataset:aegisdesk-helpdesk-training:2026.08-p9a",
            actions=("read",),
        ),
        TrainingCapabilityEvidence(
            capability_id="cap-base-model-read",
            resource="model:aegisdesk-base-7b:r42",
            actions=("read",),
        ),
        TrainingCapabilityEvidence(
            capability_id="cap-checkpoint-write",
            resource="checkpoint:training-job-p9d-001",
            actions=("create", "write"),
        ),
        TrainingCapabilityEvidence(
            capability_id="cap-output-write",
            resource=OUTPUT_ID,
            actions=("create", "write"),
        ),
    )
    manifest = TrainingExecutionManifest(
        schema_version=P9D_SCHEMA_VERSION,
        execution_id=EXECUTION_ID,
        created_at_epoch=NOW,
        p9c_assessment_sha256=P9C_ASSESSMENT_SHA,
        admission_manifest_id=P9C_MANIFEST_ID,
        job=job,
        code=code,
        environment=environment,
        secrets=secrets,
        capabilities=capabilities,
        planned_output_artifact_id=OUTPUT_ID,
    )
    policy = TrainingExecutionPolicy(
        policy_version=P9D_POLICY_VERSION,
        expected_execution_id=EXECUTION_ID,
        expected_manifest_sha256=training_execution_manifest_digest(manifest),
        expected_p9c_assessment_sha256=P9C_ASSESSMENT_SHA,
        expected_admission_manifest_id=P9C_MANIFEST_ID,
        expected_principal_id=PRINCIPAL_ID,
        expected_task_id=TASK_ID,
        expected_output_artifact_id=OUTPUT_ID,
        expected_job_id=job.job_id,
        expected_scheduler=job.scheduler,
        expected_namespace=job.namespace,
        expected_queue=job.queue,
        expected_service_account=job.service_account,
        expected_executor_principal=job.executor_principal,
        expected_identity_token_audience=job.identity_token_audience,
        expected_attempt=job.attempt,
        expected_launch_nonce_sha256=job.launch_nonce_sha256,
        expected_repository_id=code.repository_id,
        expected_commit_sha=code.commit_sha,
        expected_tree_sha=code.tree_sha,
        expected_entrypoint=code.entrypoint,
        expected_entrypoint_sha256=code.entrypoint_sha256,
        expected_config_sha256=code.config_sha256,
        expected_dependency_lock_sha256=code.dependency_lock_sha256,
        expected_image_ref=environment.image_ref,
        expected_image_sha256=environment.image_sha256,
        expected_python_version=environment.python_version,
        expected_framework_version=environment.framework_version,
        expected_accelerator_runtime=environment.accelerator_runtime,
        expected_device_profile=environment.device_profile,
        allowed_environment_variable_names=environment.environment_variable_names,
        allowed_network_egress=environment.network_egress,
        allowed_writable_paths=environment.writable_paths,
        expected_secret_order=SECRET_IDS,
        expected_secret_provider_by_id={secret.secret_id: secret.provider for secret in secrets},
        expected_secret_version_by_id={secret.secret_id: secret.version for secret in secrets},
        expected_secret_purpose_by_id={secret.secret_id: secret.purpose for secret in secrets},
        expected_secret_scope_by_id={secret.secret_id: secret.scope for secret in secrets},
        expected_secret_mount_path_by_id={secret.secret_id: secret.mount_path for secret in secrets},
        expected_capability_order=CAPABILITY_IDS,
        expected_capability_resource_by_id={cap.capability_id: cap.resource for cap in capabilities},
        expected_capability_actions_by_id={cap.capability_id: cap.actions for cap in capabilities},
        max_manifest_age_seconds=300,
        max_future_skew_seconds=5,
    )
    request = TrainingExecutionRequest(
        execution_id=EXECUTION_ID,
        manifest_sha256=training_execution_manifest_digest(manifest),
        evaluated_at_epoch=NOW,
        declared_job_id=job.job_id,
        declared_commit_sha=code.commit_sha,
        declared_config_sha256=code.config_sha256,
        declared_image_sha256=environment.image_sha256,
        declared_secret_ids=SECRET_IDS,
        declared_capability_ids=CAPABILITY_IDS,
        declared_admission_bound=True,
        declared_job_identity_bound=True,
        declared_code_config_bound=True,
        declared_environment_safe=True,
        declared_secrets_least_privilege=True,
        declared_capabilities_least_privilege=True,
        declared_execution_safe=True,
    )
    return {
        "manifest": manifest,
        "policy": policy,
        "request": request,
        "p9c": build_p9c_assessment(),
    }


def rebind(
    fixture: dict[str, object],
    *,
    manifest=None,
    p9c=None,
    **request_updates,
) -> dict[str, object]:
    manifest = manifest or fixture["manifest"]
    p9c = p9c or fixture["p9c"]
    policy = fixture["policy"]
    request = fixture["request"]
    assert isinstance(manifest, TrainingExecutionManifest)
    assert isinstance(policy, TrainingExecutionPolicy)
    assert isinstance(request, TrainingExecutionRequest)
    digest = training_execution_manifest_digest(manifest)
    out = dict(fixture)
    out["manifest"] = manifest
    out["p9c"] = p9c
    out["policy"] = replace(policy, expected_manifest_sha256=digest)
    out["request"] = replace(
        request,
        manifest_sha256=digest,
        declared_job_id=manifest.job.job_id,
        declared_commit_sha=manifest.code.commit_sha,
        declared_config_sha256=manifest.code.config_sha256,
        declared_image_sha256=manifest.environment.image_sha256,
        declared_secret_ids=tuple(secret.secret_id for secret in manifest.secrets),
        declared_capability_ids=tuple(cap.capability_id for cap in manifest.capabilities),
        **request_updates,
    )
    return out
