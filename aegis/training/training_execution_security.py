from __future__ import annotations

import re

from .fine_tuning_types import (
    P9C_ASSESSMENT_MODE,
    P9C_ASSESSMENT_SCHEMA_VERSION,
    FineTuneDecision,
)
from .training_execution_types import *

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class TrainingExecutionProvenanceAnalyzer:
    def __init__(self, policy: TrainingExecutionPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha256(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    @staticmethod
    def _git_sha(value: str) -> bool:
        return bool(_GIT_SHA_RE.fullmatch(str(value)))

    @staticmethod
    def _unique(values: tuple[str, ...]) -> bool:
        return len(values) == len(set(values))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9D_POLICY_VERSION:
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "unexpected policy version")
        identities = (
            p.expected_execution_id,
            p.expected_admission_manifest_id,
            p.expected_principal_id,
            p.expected_task_id,
            p.expected_output_artifact_id,
            p.expected_job_id,
            p.expected_scheduler,
            p.expected_namespace,
            p.expected_queue,
            p.expected_service_account,
            p.expected_executor_principal,
            p.expected_identity_token_audience,
            p.expected_repository_id,
            p.expected_entrypoint,
            p.expected_image_ref,
            p.expected_python_version,
            p.expected_framework_version,
            p.expected_accelerator_runtime,
            p.expected_device_profile,
        )
        if not all(identities):
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "identity pins are required")
        sha256_values = (
            p.expected_manifest_sha256,
            p.expected_p9c_assessment_sha256,
            p.expected_launch_nonce_sha256,
            p.expected_entrypoint_sha256,
            p.expected_config_sha256,
            p.expected_dependency_lock_sha256,
            p.expected_image_sha256,
        )
        if not all(self._sha256(value) for value in sha256_values):
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "sha256 pins are invalid")
        if not self._git_sha(p.expected_commit_sha) or not self._git_sha(p.expected_tree_sha):
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "git object pins must be 40-hex")
        if p.expected_attempt <= 0:
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "expected attempt must be positive")
        if p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "freshness bounds invalid")
        for values, label in (
            (p.allowed_environment_variable_names, "environment variables"),
            (p.allowed_network_egress, "network egress"),
            (p.allowed_writable_paths, "writable paths"),
            (p.expected_secret_order, "secret order"),
            (p.expected_capability_order, "capability order"),
        ):
            if not self._unique(values):
                reject(TrainingExecutionRejectReason.POLICY_INVALID, f"{label} must be unique")
        if any("*" in value for value in (*p.allowed_network_egress, *p.allowed_writable_paths)):
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "wildcard runtime policy is forbidden")
        secret_ids = set(p.expected_secret_order)
        secret_maps = (
            p.expected_secret_provider_by_id,
            p.expected_secret_version_by_id,
            p.expected_secret_purpose_by_id,
            p.expected_secret_scope_by_id,
            p.expected_secret_mount_path_by_id,
        )
        if any(set(mapping) != secret_ids for mapping in secret_maps):
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "secret policy maps must exactly cover secret order")
        if any(not str(value) or "*" in str(value) for mapping in secret_maps for value in mapping.values()):
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "secret policy values must be explicit")
        capability_ids = set(p.expected_capability_order)
        if set(p.expected_capability_resource_by_id) != capability_ids or set(p.expected_capability_actions_by_id) != capability_ids:
            reject(TrainingExecutionRejectReason.POLICY_INVALID, "capability policy maps must exactly cover capability order")
        for capability_id in p.expected_capability_order:
            resource = p.expected_capability_resource_by_id[capability_id]
            actions = p.expected_capability_actions_by_id[capability_id]
            if not resource or "*" in resource or not actions or len(actions) != len(set(actions)) or any("*" in action for action in actions):
                reject(TrainingExecutionRejectReason.POLICY_INVALID, "capability policy must be explicit and least-privilege")

    def _validate_manifest(self, manifest: TrainingExecutionManifest) -> None:
        if manifest.schema_version != P9D_SCHEMA_VERSION:
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "unexpected execution manifest schema")
        if manifest.execution_id != self.policy.expected_execution_id:
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "execution identity mismatch")
        if not self._sha256(manifest.p9c_assessment_sha256):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "P9-C assessment digest invalid")
        if not manifest.admission_manifest_id or not manifest.planned_output_artifact_id:
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "admission/output identity required")

        job = manifest.job
        if not all((
            job.job_id,
            job.scheduler,
            job.namespace,
            job.queue,
            job.service_account,
            job.executor_principal,
            job.identity_token_audience,
        )):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "job identity evidence incomplete")
        if job.attempt <= 0 or not self._sha256(job.launch_nonce_sha256):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "invalid job attempt/launch nonce")

        code = manifest.code
        if not all((code.repository_id, code.entrypoint)):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "code identity evidence incomplete")
        if not self._git_sha(code.commit_sha) or not self._git_sha(code.tree_sha):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "invalid git object identity")
        if not all(self._sha256(value) for value in (
            code.entrypoint_sha256,
            code.config_sha256,
            code.dependency_lock_sha256,
        )):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "code/config digests invalid")

        env = manifest.environment
        if not all((
            env.image_ref,
            env.python_version,
            env.framework_version,
            env.accelerator_runtime,
            env.device_profile,
        )) or not self._sha256(env.image_sha256):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "runtime environment evidence incomplete")
        for values, label in (
            (env.environment_variable_names, "environment variable names"),
            (env.network_egress, "network egress"),
            (env.writable_paths, "writable paths"),
            (env.host_mounts, "host mounts"),
        ):
            if not self._unique(values):
                reject(TrainingExecutionRejectReason.MANIFEST_INVALID, f"duplicate {label}")

        secret_ids = tuple(secret.secret_id for secret in manifest.secrets)
        if len(secret_ids) != len(set(secret_ids)):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "duplicate secret IDs")
        for secret in manifest.secrets:
            if not all((
                secret.secret_id,
                secret.provider,
                secret.version,
                secret.purpose,
                secret.scope,
                secret.mount_path,
                secret.issued_to_principal,
            )):
                reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "secret lease evidence incomplete")
            if secret.issued_at_epoch > secret.expires_at_epoch:
                reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "secret lease validity window invalid")

        capability_ids = tuple(capability.capability_id for capability in manifest.capabilities)
        if len(capability_ids) != len(set(capability_ids)):
            reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "duplicate capability IDs")
        for capability in manifest.capabilities:
            if not capability.capability_id or not capability.resource or not capability.actions:
                reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "capability evidence incomplete")
            if len(capability.actions) != len(set(capability.actions)):
                reject(TrainingExecutionRejectReason.MANIFEST_INVALID, "duplicate capability actions")

    def _upstream_ok(self, assessment) -> bool:
        return (
            getattr(assessment, "decision", None) == FineTuneDecision.ALLOW
            and not getattr(assessment, "risks", ())
            and getattr(assessment, "upstream_p9b_bound", False)
            and getattr(assessment, "authorization_verified", False)
            and getattr(assessment, "base_model_binding_verified", False)
            and getattr(assessment, "adapter_policy_verified", False)
            and getattr(assessment, "hyperparameter_policy_verified", False)
            and not getattr(assessment, "caller_declared_safety_trusted", True)
            and not getattr(assessment, "production_training_runtime_integrated", True)
            and not getattr(assessment, "production_identity_provider_integrated", True)
            and not getattr(assessment, "proof_of_training_execution", True)
            and getattr(assessment, "assessment_schema_version", None) == P9C_ASSESSMENT_SCHEMA_VERSION
            and getattr(assessment, "assessment_mode", None) == P9C_ASSESSMENT_MODE
        )

    def derive(self, manifest: TrainingExecutionManifest, p9c_assessment, now: int) -> tuple[TrainingExecutionRisk, ...]:
        self._validate_manifest(manifest)
        p = self.policy
        risks: set[TrainingExecutionRisk] = set()

        if not self._upstream_ok(p9c_assessment):
            risks.add(TrainingExecutionRisk.UPSTREAM_P9C_INVALID)
        if (
            manifest.p9c_assessment_sha256.casefold() != p.expected_p9c_assessment_sha256.casefold()
            or getattr(p9c_assessment, "assessment_evidence_sha256", "").casefold()
            != p.expected_p9c_assessment_sha256.casefold()
            or manifest.admission_manifest_id != p.expected_admission_manifest_id
            or getattr(p9c_assessment, "manifest_id", None) != p.expected_admission_manifest_id
            or getattr(p9c_assessment, "principal_id", None) != p.expected_principal_id
            or getattr(p9c_assessment, "task_id", None) != p.expected_task_id
        ):
            risks.add(TrainingExecutionRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            manifest.planned_output_artifact_id != p.expected_output_artifact_id
            or getattr(p9c_assessment, "planned_output_artifact_id", None) != p.expected_output_artifact_id
        ):
            risks.add(TrainingExecutionRisk.OUTPUT_IDENTITY_MISMATCH)

        job = manifest.job
        if job.job_id != p.expected_job_id or job.attempt != p.expected_attempt or job.launch_nonce_sha256.casefold() != p.expected_launch_nonce_sha256.casefold():
            risks.add(TrainingExecutionRisk.JOB_IDENTITY_MISMATCH)
        if (
            job.scheduler != p.expected_scheduler
            or job.namespace != p.expected_namespace
            or job.queue != p.expected_queue
            or job.service_account != p.expected_service_account
            or job.executor_principal != p.expected_executor_principal
            or job.identity_token_audience != p.expected_identity_token_audience
        ):
            risks.add(TrainingExecutionRisk.SCHEDULER_IDENTITY_MISMATCH)

        code = manifest.code
        if (
            code.repository_id != p.expected_repository_id
            or code.commit_sha.casefold() != p.expected_commit_sha.casefold()
            or code.tree_sha.casefold() != p.expected_tree_sha.casefold()
            or code.entrypoint != p.expected_entrypoint
        ):
            risks.add(TrainingExecutionRisk.CODE_IDENTITY_MISMATCH)
        if code.entrypoint_sha256.casefold() != p.expected_entrypoint_sha256.casefold() or code.dependency_lock_sha256.casefold() != p.expected_dependency_lock_sha256.casefold():
            risks.add(TrainingExecutionRisk.CODE_INTEGRITY_MISMATCH)
        if code.config_sha256.casefold() != p.expected_config_sha256.casefold():
            risks.add(TrainingExecutionRisk.CONFIG_MISMATCH)
        if (
            not code.source_read_only
            or code.remote_fetch_allowed
            or code.dynamic_dependency_install
            or code.custom_startup_script
        ):
            risks.add(TrainingExecutionRisk.DYNAMIC_OR_REMOTE_CODE)

        env = manifest.environment
        if (
            env.image_ref != p.expected_image_ref
            or env.image_sha256.casefold() != p.expected_image_sha256.casefold()
            or env.python_version != p.expected_python_version
            or env.framework_version != p.expected_framework_version
            or env.accelerator_runtime != p.expected_accelerator_runtime
        ):
            risks.add(TrainingExecutionRisk.ENVIRONMENT_IDENTITY_MISMATCH)
        if (
            env.privileged
            or env.host_network
            or env.allow_privilege_escalation
            or env.docker_socket_mounted
        ):
            risks.add(TrainingExecutionRisk.PRIVILEGED_RUNTIME)
        if tuple(env.network_egress) != tuple(p.allowed_network_egress) or any("*" in endpoint for endpoint in env.network_egress):
            risks.add(TrainingExecutionRisk.NETWORK_POLICY_MISMATCH)
        if (
            tuple(env.writable_paths) != tuple(p.allowed_writable_paths)
            or env.host_mounts
            or not env.root_filesystem_read_only
            or any("*" in path for path in env.writable_paths)
        ):
            risks.add(TrainingExecutionRisk.FILESYSTEM_POLICY_MISMATCH)
        if env.device_profile != p.expected_device_profile:
            risks.add(TrainingExecutionRisk.DEVICE_POLICY_MISMATCH)
        if tuple(env.environment_variable_names) != tuple(p.allowed_environment_variable_names):
            risks.add(TrainingExecutionRisk.ENV_ALLOWLIST_MISMATCH)

        secret_ids = tuple(secret.secret_id for secret in manifest.secrets)
        if secret_ids != p.expected_secret_order:
            risks.add(TrainingExecutionRisk.SECRET_COVERAGE_MISMATCH)
        for secret in manifest.secrets:
            if (
                p.expected_secret_provider_by_id.get(secret.secret_id) != secret.provider
                or p.expected_secret_version_by_id.get(secret.secret_id) != secret.version
                or p.expected_secret_purpose_by_id.get(secret.secret_id) != secret.purpose
                or p.expected_secret_mount_path_by_id.get(secret.secret_id) != secret.mount_path
            ):
                risks.add(TrainingExecutionRisk.SECRET_COVERAGE_MISMATCH)
            if p.expected_secret_scope_by_id.get(secret.secret_id) != secret.scope or "*" in secret.scope:
                risks.add(TrainingExecutionRisk.SECRET_SCOPE_EXCESSIVE)
            if (
                secret.issued_to_principal != p.expected_executor_principal
                or now < secret.issued_at_epoch - p.max_future_skew_seconds
                or now > secret.expires_at_epoch
            ):
                risks.add(TrainingExecutionRisk.SECRET_LEASE_INVALID)
            if secret.exportable or secret.injected_as_environment_variable:
                risks.add(TrainingExecutionRisk.SECRET_EXPOSURE_UNSAFE)

        capability_ids = tuple(capability.capability_id for capability in manifest.capabilities)
        if capability_ids != p.expected_capability_order:
            risks.add(TrainingExecutionRisk.CAPABILITY_COVERAGE_MISMATCH)
        for capability in manifest.capabilities:
            expected_resource = p.expected_capability_resource_by_id.get(capability.capability_id)
            expected_actions = p.expected_capability_actions_by_id.get(capability.capability_id)
            if expected_resource is None or expected_actions is None:
                risks.add(TrainingExecutionRisk.CAPABILITY_COVERAGE_MISMATCH)
                continue
            if capability.resource != expected_resource or "*" in capability.resource:
                risks.add(TrainingExecutionRisk.CAPABILITY_EXCESSIVE)
            if capability.actions != expected_actions or any("*" in action for action in capability.actions):
                risks.add(TrainingExecutionRisk.CAPABILITY_EXCESSIVE)

        return tuple(sorted(risks, key=lambda risk: risk.value))

    def evaluate(
        self,
        request: TrainingExecutionRequest,
        manifest: TrainingExecutionManifest,
        p9c_assessment,
    ) -> VerifiedTrainingExecutionAssessment:
        self._validate_manifest(manifest)
        actual_manifest_sha = training_execution_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(
                TrainingExecutionRejectReason.MANIFEST_DIGEST_MISMATCH,
                "execution manifest differs from policy-pinned evidence",
            )
        if request.execution_id != manifest.execution_id or request.manifest_sha256.casefold() != actual_manifest_sha.casefold():
            reject(TrainingExecutionRejectReason.REQUEST_INVALID, "request execution-manifest binding mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(TrainingExecutionRejectReason.REQUEST_INVALID, "evaluation predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(TrainingExecutionRejectReason.REQUEST_INVALID, "execution manifest is stale")

        risks = self.derive(manifest, p9c_assessment, request.evaluated_at_epoch)
        decision = TrainingExecutionDecision.DENY if risks else TrainingExecutionDecision.ALLOW
        risk_set = set(risks)

        admission_ok = not bool(risk_set & {
            TrainingExecutionRisk.UPSTREAM_P9C_INVALID,
            TrainingExecutionRisk.UPSTREAM_BINDING_MISMATCH,
            TrainingExecutionRisk.OUTPUT_IDENTITY_MISMATCH,
        })
        job_ok = not bool(risk_set & {
            TrainingExecutionRisk.JOB_IDENTITY_MISMATCH,
            TrainingExecutionRisk.SCHEDULER_IDENTITY_MISMATCH,
        })
        code_ok = not bool(risk_set & {
            TrainingExecutionRisk.CODE_IDENTITY_MISMATCH,
            TrainingExecutionRisk.CODE_INTEGRITY_MISMATCH,
            TrainingExecutionRisk.CONFIG_MISMATCH,
            TrainingExecutionRisk.DYNAMIC_OR_REMOTE_CODE,
        })
        environment_ok = not bool(risk_set & {
            TrainingExecutionRisk.ENVIRONMENT_IDENTITY_MISMATCH,
            TrainingExecutionRisk.PRIVILEGED_RUNTIME,
            TrainingExecutionRisk.NETWORK_POLICY_MISMATCH,
            TrainingExecutionRisk.FILESYSTEM_POLICY_MISMATCH,
            TrainingExecutionRisk.DEVICE_POLICY_MISMATCH,
            TrainingExecutionRisk.ENV_ALLOWLIST_MISMATCH,
        })
        secrets_ok = not bool(risk_set & {
            TrainingExecutionRisk.SECRET_COVERAGE_MISMATCH,
            TrainingExecutionRisk.SECRET_SCOPE_EXCESSIVE,
            TrainingExecutionRisk.SECRET_LEASE_INVALID,
            TrainingExecutionRisk.SECRET_EXPOSURE_UNSAFE,
        })
        capabilities_ok = not bool(risk_set & {
            TrainingExecutionRisk.CAPABILITY_COVERAGE_MISMATCH,
            TrainingExecutionRisk.CAPABILITY_EXCESSIVE,
        })
        execution_ok = decision == TrainingExecutionDecision.ALLOW

        expected_declared = (
            (request.declared_job_id, manifest.job.job_id, "job ID"),
            (request.declared_commit_sha.casefold(), manifest.code.commit_sha.casefold(), "commit SHA"),
            (request.declared_config_sha256.casefold(), manifest.code.config_sha256.casefold(), "config digest"),
            (request.declared_image_sha256.casefold(), manifest.environment.image_sha256.casefold(), "image digest"),
            (request.declared_secret_ids, tuple(secret.secret_id for secret in manifest.secrets), "secret IDs"),
            (request.declared_capability_ids, tuple(capability.capability_id for capability in manifest.capabilities), "capability IDs"),
            (request.declared_admission_bound, admission_ok, "admission binding"),
            (request.declared_job_identity_bound, job_ok, "job identity"),
            (request.declared_code_config_bound, code_ok, "code/config"),
            (request.declared_environment_safe, environment_ok, "environment"),
            (request.declared_secrets_least_privilege, secrets_ok, "secret least privilege"),
            (request.declared_capabilities_least_privilege, capabilities_ok, "capability least privilege"),
            (request.declared_execution_safe, execution_ok, "execution safety"),
        )
        for declared, derived, label in expected_declared:
            if declared != derived:
                reject(
                    TrainingExecutionRejectReason.DECLARED_SUMMARY_MISMATCH,
                    f"caller-declared {label} differs from evidence",
                )

        assessment_sha = digest_json({
            "execution_id": manifest.execution_id,
            "job_id": manifest.job.job_id,
            "p9c_assessment_sha256": manifest.p9c_assessment_sha256,
            "decision": decision,
            "risks": risks,
            "commit_sha": manifest.code.commit_sha,
            "tree_sha": manifest.code.tree_sha,
            "config_sha256": manifest.code.config_sha256,
            "image_sha256": manifest.environment.image_sha256,
            "secret_ids": tuple(secret.secret_id for secret in manifest.secrets),
            "capability_ids": tuple(capability.capability_id for capability in manifest.capabilities),
            "planned_output_artifact_id": manifest.planned_output_artifact_id,
            "schema": P9D_ASSESSMENT_SCHEMA_VERSION,
            "mode": P9D_ASSESSMENT_MODE,
        })
        return VerifiedTrainingExecutionAssessment(
            execution_id=manifest.execution_id,
            job_id=manifest.job.job_id,
            decision=decision,
            risks=risks,
            p9c_assessment_sha256=manifest.p9c_assessment_sha256,
            admission_manifest_id=manifest.admission_manifest_id,
            principal_id=getattr(p9c_assessment, "principal_id", ""),
            task_id=getattr(p9c_assessment, "task_id", ""),
            code_commit_sha=manifest.code.commit_sha,
            code_tree_sha=manifest.code.tree_sha,
            config_sha256=manifest.code.config_sha256,
            image_sha256=manifest.environment.image_sha256,
            secret_ids=tuple(secret.secret_id for secret in manifest.secrets),
            secret_scopes=tuple(secret.scope for secret in manifest.secrets),
            capability_ids=tuple(capability.capability_id for capability in manifest.capabilities),
            planned_output_artifact_id=manifest.planned_output_artifact_id,
            upstream_p9c_bound=admission_ok,
            job_identity_verified=job_ok,
            code_config_provenance_verified=code_ok,
            environment_policy_verified=environment_ok,
            secret_least_privilege_verified=secrets_ok,
            capability_least_privilege_verified=capabilities_ok,
            caller_declared_safety_trusted=False,
            production_scheduler_integrated=False,
            production_secret_manager_integrated=False,
            production_container_runtime_integrated=False,
            proof_of_training_execution=False,
            hardware_attestation_verified=False,
            assessment_schema_version=P9D_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P9D_ASSESSMENT_MODE,
            assessment_evidence_sha256=assessment_sha,
        )
