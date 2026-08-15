from __future__ import annotations

import re

from .training_execution_types import (
    P9D_ASSESSMENT_MODE,
    P9D_ASSESSMENT_SCHEMA_VERSION,
    TrainingExecutionDecision,
)
from .checkpoint_integrity_types import *

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class TrainingCheckpointIntegrityAnalyzer:
    def __init__(self, policy: TrainingCheckpointPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9E_POLICY_VERSION:
            reject(CheckpointRejectReason.POLICY_INVALID, "unexpected policy version")
        if not all((p.expected_lineage_id, p.expected_execution_id, p.expected_job_id, p.expected_principal_id)):
            reject(CheckpointRejectReason.POLICY_INVALID, "identity pins are required")
        if not self._sha(p.expected_manifest_sha256) or not self._sha(p.expected_p9d_assessment_sha256):
            reject(CheckpointRejectReason.POLICY_INVALID, "manifest/upstream digest pins must be sha256")
        ids = p.expected_checkpoint_order
        if not ids or len(ids) != len(set(ids)):
            reject(CheckpointRejectReason.POLICY_INVALID, "checkpoint order must be non-empty and unique")
        maps = (
            p.expected_checkpoint_step_by_id,
            p.expected_checkpoint_parent_by_id,
            p.expected_checkpoint_artifact_sha256_by_id,
            p.expected_model_state_sha256_by_id,
            p.expected_optimizer_state_sha256_by_id,
            p.expected_rng_state_sha256_by_id,
            p.expected_data_cursor_sha256_by_id,
            p.expected_trainer_state_sha256_by_id,
        )
        if any(set(m) != set(ids) for m in maps):
            reject(CheckpointRejectReason.POLICY_INVALID, "checkpoint pin maps must exactly cover checkpoint order")
        digest_maps = maps[2:]
        if any(not self._sha(v) for m in digest_maps for v in m.values()):
            reject(CheckpointRejectReason.POLICY_INVALID, "checkpoint digest pins must be sha256")
        if any(step < 0 or step > p.max_checkpoint_step for step in p.expected_checkpoint_step_by_id.values()):
            reject(CheckpointRejectReason.POLICY_INVALID, "checkpoint step pin outside policy")
        if not p.allowed_serialization_formats or not p.allowed_actions:
            reject(CheckpointRejectReason.POLICY_INVALID, "format/action allowlists are required")
        if any(target not in ids for target in p.allowed_rollback_targets):
            reject(CheckpointRejectReason.POLICY_INVALID, "rollback target not in checkpoint order")
        if p.max_checkpoint_step <= 0 or p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(CheckpointRejectReason.POLICY_INVALID, "invalid policy bounds")

    def _validate_manifest(self, manifest: TrainingCheckpointManifest) -> None:
        if manifest.schema_version != P9E_SCHEMA_VERSION:
            reject(CheckpointRejectReason.MANIFEST_INVALID, "unexpected manifest schema")
        if not all((manifest.lineage_id, manifest.execution_id, manifest.job_id, manifest.active_checkpoint_id)):
            reject(CheckpointRejectReason.MANIFEST_INVALID, "lineage/execution/job identity incomplete")
        if not self._sha(manifest.p9d_assessment_sha256):
            reject(CheckpointRejectReason.MANIFEST_INVALID, "upstream digest invalid")
        ids = [c.checkpoint_id for c in manifest.checkpoints]
        if not ids or len(ids) != len(set(ids)):
            reject(CheckpointRejectReason.MANIFEST_INVALID, "checkpoint IDs must be non-empty and unique")
        for checkpoint in manifest.checkpoints:
            if not all((checkpoint.checkpoint_id, checkpoint.execution_id, checkpoint.job_id, checkpoint.serialization_format)):
                reject(CheckpointRejectReason.MANIFEST_INVALID, "checkpoint identity incomplete")
            if checkpoint.attempt <= 0 or checkpoint.step < 0 or checkpoint.epoch_milli < 0:
                reject(CheckpointRejectReason.MANIFEST_INVALID, "checkpoint counters invalid")
            digests = (
                checkpoint.model_state_sha256,
                checkpoint.optimizer_state_sha256,
                checkpoint.rng_state_sha256,
                checkpoint.data_cursor_sha256,
                checkpoint.trainer_state_sha256,
                checkpoint.artifact_sha256,
            )
            if not all(self._sha(v) for v in digests):
                reject(CheckpointRejectReason.MANIFEST_INVALID, "checkpoint digest invalid")
        auth = manifest.authorization
        if not all((auth.authorization_id, auth.principal_id, auth.reason_code)):
            reject(CheckpointRejectReason.MANIFEST_INVALID, "operation authorization identity incomplete")
        if not self._sha(auth.p9d_assessment_sha256) or auth.issued_at_epoch > auth.expires_at_epoch:
            reject(CheckpointRejectReason.MANIFEST_INVALID, "operation authorization invalid")
        if manifest.next_step < 0:
            reject(CheckpointRejectReason.MANIFEST_INVALID, "next step invalid")

    def _upstream_ok(self, assessment) -> bool:
        flags = (
            getattr(assessment, "upstream_p9c_bound", False),
            getattr(assessment, "job_identity_verified", False),
            getattr(assessment, "code_config_provenance_verified", False),
            getattr(assessment, "environment_policy_verified", False),
            getattr(assessment, "secret_least_privilege_verified", False),
            getattr(assessment, "capability_least_privilege_verified", False),
        )
        return (
            getattr(assessment, "decision", None) == TrainingExecutionDecision.ALLOW
            and not getattr(assessment, "risks", ())
            and all(flags)
            and not getattr(assessment, "caller_declared_safety_trusted", True)
            and not getattr(assessment, "production_scheduler_integrated", True)
            and not getattr(assessment, "production_secret_manager_integrated", True)
            and not getattr(assessment, "production_container_runtime_integrated", True)
            and not getattr(assessment, "proof_of_training_execution", True)
            and not getattr(assessment, "hardware_attestation_verified", True)
            and getattr(assessment, "assessment_schema_version", None) == P9D_ASSESSMENT_SCHEMA_VERSION
            and getattr(assessment, "assessment_mode", None) == P9D_ASSESSMENT_MODE
        )

    def derive(self, manifest: TrainingCheckpointManifest, p9d_assessment, now: int) -> tuple[CheckpointRisk, ...]:
        self._validate_manifest(manifest)
        p = self.policy
        risks: set[CheckpointRisk] = set()

        if not self._upstream_ok(p9d_assessment):
            risks.add(CheckpointRisk.UPSTREAM_P9D_INVALID)
        actual_upstream_sha = getattr(p9d_assessment, "assessment_evidence_sha256", "")
        if (
            manifest.p9d_assessment_sha256.casefold() != p.expected_p9d_assessment_sha256.casefold()
            or actual_upstream_sha.casefold() != p.expected_p9d_assessment_sha256.casefold()
        ):
            risks.add(CheckpointRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            manifest.execution_id != p.expected_execution_id
            or manifest.job_id != p.expected_job_id
            or getattr(p9d_assessment, "execution_id", None) != p.expected_execution_id
            or getattr(p9d_assessment, "job_id", None) != p.expected_job_id
        ):
            risks.add(CheckpointRisk.LINEAGE_IDENTITY_MISMATCH)

        ids = tuple(c.checkpoint_id for c in manifest.checkpoints)
        if ids != p.expected_checkpoint_order:
            risks.add(CheckpointRisk.CHECKPOINT_COVERAGE_MISMATCH)

        previous = None
        by_id = {c.checkpoint_id: c for c in manifest.checkpoints}
        for checkpoint in manifest.checkpoints:
            if checkpoint.execution_id != manifest.execution_id or checkpoint.job_id != manifest.job_id or checkpoint.attempt != 1:
                risks.add(CheckpointRisk.CHECKPOINT_JOB_SCOPE_MISMATCH)
            expected_step = p.expected_checkpoint_step_by_id.get(checkpoint.checkpoint_id)
            if expected_step is None or checkpoint.step != expected_step or checkpoint.step > p.max_checkpoint_step:
                risks.add(CheckpointRisk.CHECKPOINT_STEP_INVALID)
            if previous is not None and checkpoint.step <= previous.step:
                risks.add(CheckpointRisk.CHECKPOINT_STEP_INVALID)
            expected_parent = p.expected_checkpoint_parent_by_id.get(checkpoint.checkpoint_id)
            if expected_parent is None or checkpoint.parent_checkpoint_id != expected_parent:
                risks.add(CheckpointRisk.CHECKPOINT_PARENT_MISMATCH)
            if previous is None:
                if checkpoint.parent_checkpoint_id:
                    risks.add(CheckpointRisk.CHECKPOINT_PARENT_MISMATCH)
            elif checkpoint.parent_checkpoint_id != previous.checkpoint_id:
                risks.add(CheckpointRisk.CHECKPOINT_PARENT_MISMATCH)

            state_expected = (
                p.expected_model_state_sha256_by_id.get(checkpoint.checkpoint_id),
                p.expected_optimizer_state_sha256_by_id.get(checkpoint.checkpoint_id),
                p.expected_rng_state_sha256_by_id.get(checkpoint.checkpoint_id),
                p.expected_data_cursor_sha256_by_id.get(checkpoint.checkpoint_id),
                p.expected_trainer_state_sha256_by_id.get(checkpoint.checkpoint_id),
            )
            state_actual = (
                checkpoint.model_state_sha256,
                checkpoint.optimizer_state_sha256,
                checkpoint.rng_state_sha256,
                checkpoint.data_cursor_sha256,
                checkpoint.trainer_state_sha256,
            )
            if any(e is None or a.casefold() != e.casefold() for a, e in zip(state_actual, state_expected)):
                risks.add(CheckpointRisk.CHECKPOINT_STATE_MISMATCH)
            artifact_expected = p.expected_checkpoint_artifact_sha256_by_id.get(checkpoint.checkpoint_id)
            if artifact_expected is None or checkpoint.artifact_sha256.casefold() != artifact_expected.casefold():
                risks.add(CheckpointRisk.CHECKPOINT_ARTIFACT_MISMATCH)
            if checkpoint.serialization_format not in p.allowed_serialization_formats:
                risks.add(CheckpointRisk.CHECKPOINT_FORMAT_UNSAFE)
            if not checkpoint.immutable:
                risks.add(CheckpointRisk.CHECKPOINT_MUTABILITY_UNSAFE)
            if checkpoint.external_reference or checkpoint.custom_deserializer:
                risks.add(CheckpointRisk.CHECKPOINT_EXTERNAL_REFERENCE_UNSAFE)
            previous = checkpoint

        if manifest.active_checkpoint_id not in by_id:
            risks.add(CheckpointRisk.ACTION_SOURCE_MISMATCH)
        if manifest.action not in p.allowed_actions:
            risks.add(CheckpointRisk.ACTION_UNAUTHORIZED)

        source = by_id.get(manifest.source_checkpoint_id)
        target = by_id.get(manifest.target_checkpoint_id)
        if source is None or manifest.source_checkpoint_id != manifest.active_checkpoint_id:
            risks.add(CheckpointRisk.ACTION_SOURCE_MISMATCH)

        auth = manifest.authorization
        if (
            auth.principal_id != p.expected_principal_id
            or auth.p9d_assessment_sha256.casefold() != manifest.p9d_assessment_sha256.casefold()
            or auth.action != manifest.action
            or auth.source_checkpoint_id != manifest.source_checkpoint_id
            or auth.target_checkpoint_id != manifest.target_checkpoint_id
        ):
            risks.add(CheckpointRisk.ROLLBACK_AUTHORIZATION_INVALID)
        if now < auth.issued_at_epoch - p.max_future_skew_seconds or now > auth.expires_at_epoch:
            risks.add(CheckpointRisk.AUTHORIZATION_EXPIRED)

        if manifest.action == CheckpointAction.RESUME:
            if target is None or target.checkpoint_id != manifest.source_checkpoint_id:
                risks.add(CheckpointRisk.ACTION_TARGET_MISMATCH)
            if source is None or manifest.next_step != source.step + 1:
                risks.add(CheckpointRisk.NEXT_STEP_INVALID)
        elif manifest.action == CheckpointAction.ROLLBACK:
            if target is None or target.checkpoint_id not in p.allowed_rollback_targets:
                risks.add(CheckpointRisk.ROLLBACK_TARGET_UNAUTHORIZED)
            if source is None or target is None or target.step >= source.step:
                risks.add(CheckpointRisk.ACTION_TARGET_MISMATCH)
            if target is None or manifest.next_step != target.step + 1:
                risks.add(CheckpointRisk.NEXT_STEP_INVALID)
            if not auth.reason_code.startswith("approved-rollback:"):
                risks.add(CheckpointRisk.ROLLBACK_AUTHORIZATION_INVALID)
        elif manifest.action == CheckpointAction.SAVE:
            if target is not None:
                risks.add(CheckpointRisk.ACTION_TARGET_MISMATCH)
            if source is None or manifest.next_step <= source.step:
                risks.add(CheckpointRisk.NEXT_STEP_INVALID)

        return tuple(sorted(risks, key=lambda r: r.value))

    def evaluate(self, request: TrainingCheckpointRequest, manifest: TrainingCheckpointManifest, p9d_assessment) -> VerifiedTrainingCheckpointAssessment:
        self._validate_manifest(manifest)
        actual_manifest_sha = training_checkpoint_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(CheckpointRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest differs from policy-pinned evidence")
        if request.lineage_id != manifest.lineage_id or request.manifest_sha256.casefold() != actual_manifest_sha.casefold():
            reject(CheckpointRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(CheckpointRejectReason.REQUEST_INVALID, "evaluation predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(CheckpointRejectReason.REQUEST_INVALID, "manifest is stale")

        risks = self.derive(manifest, p9d_assessment, request.evaluated_at_epoch)
        decision = CheckpointDecision.DENY if risks else CheckpointDecision.ALLOW
        risk_set = set(risks)
        checkpoint_ids = tuple(c.checkpoint_id for c in manifest.checkpoints)

        upstream_ok = not bool(risk_set & {CheckpointRisk.UPSTREAM_P9D_INVALID, CheckpointRisk.UPSTREAM_BINDING_MISMATCH, CheckpointRisk.LINEAGE_IDENTITY_MISMATCH})
        lineage_ok = not bool(risk_set & {
            CheckpointRisk.CHECKPOINT_COVERAGE_MISMATCH,
            CheckpointRisk.CHECKPOINT_JOB_SCOPE_MISMATCH,
            CheckpointRisk.CHECKPOINT_STEP_INVALID,
            CheckpointRisk.CHECKPOINT_PARENT_MISMATCH,
        })
        state_ok = not bool(risk_set & {
            CheckpointRisk.CHECKPOINT_STATE_MISMATCH,
            CheckpointRisk.CHECKPOINT_ARTIFACT_MISMATCH,
            CheckpointRisk.CHECKPOINT_FORMAT_UNSAFE,
            CheckpointRisk.CHECKPOINT_MUTABILITY_UNSAFE,
            CheckpointRisk.CHECKPOINT_EXTERNAL_REFERENCE_UNSAFE,
        })
        operation_ok = not bool(risk_set & {
            CheckpointRisk.ACTION_UNAUTHORIZED,
            CheckpointRisk.ACTION_SOURCE_MISMATCH,
            CheckpointRisk.ACTION_TARGET_MISMATCH,
            CheckpointRisk.NEXT_STEP_INVALID,
            CheckpointRisk.ROLLBACK_AUTHORIZATION_INVALID,
            CheckpointRisk.ROLLBACK_TARGET_UNAUTHORIZED,
            CheckpointRisk.AUTHORIZATION_EXPIRED,
        })
        rollback_safe = operation_ok and (
            manifest.action != CheckpointAction.ROLLBACK
            or manifest.target_checkpoint_id in self.policy.allowed_rollback_targets
        )
        safe = decision == CheckpointDecision.ALLOW

        declared = (
            request.declared_checkpoint_ids == checkpoint_ids,
            request.declared_active_checkpoint_id == manifest.active_checkpoint_id,
            request.declared_action == manifest.action,
            request.declared_source_checkpoint_id == manifest.source_checkpoint_id,
            request.declared_target_checkpoint_id == manifest.target_checkpoint_id,
            request.declared_next_step == manifest.next_step,
            request.declared_upstream_bound == upstream_ok,
            request.declared_lineage_integrity == lineage_ok,
            request.declared_state_integrity == state_ok,
            request.declared_operation_authorized == operation_ok,
            request.declared_checkpoint_safe == safe,
        )
        if not all(declared):
            reject(CheckpointRejectReason.DECLARED_SUMMARY_MISMATCH, "caller summary differs from derived checkpoint evidence")

        assessment_sha = digest_json({
            "lineage_id": manifest.lineage_id,
            "execution_id": manifest.execution_id,
            "job_id": manifest.job_id,
            "p9d_assessment_sha256": manifest.p9d_assessment_sha256,
            "checkpoint_ids": checkpoint_ids,
            "active_checkpoint_id": manifest.active_checkpoint_id,
            "action": manifest.action,
            "source_checkpoint_id": manifest.source_checkpoint_id,
            "target_checkpoint_id": manifest.target_checkpoint_id,
            "next_step": manifest.next_step,
            "decision": decision,
            "risks": risks,
            "schema": P9E_ASSESSMENT_SCHEMA_VERSION,
            "mode": P9E_ASSESSMENT_MODE,
        })
        return VerifiedTrainingCheckpointAssessment(
            lineage_id=manifest.lineage_id,
            execution_id=manifest.execution_id,
            job_id=manifest.job_id,
            decision=decision,
            risks=risks,
            p9d_assessment_sha256=manifest.p9d_assessment_sha256,
            checkpoint_ids=checkpoint_ids,
            active_checkpoint_id=manifest.active_checkpoint_id,
            action=manifest.action,
            source_checkpoint_id=manifest.source_checkpoint_id,
            target_checkpoint_id=manifest.target_checkpoint_id,
            next_step=manifest.next_step,
            upstream_p9d_bound=upstream_ok,
            checkpoint_lineage_verified=lineage_ok,
            checkpoint_state_integrity_verified=state_ok,
            operation_authorization_verified=operation_ok,
            rollback_safe=rollback_safe,
            caller_declared_safety_trusted=False,
            production_checkpoint_store_integrated=False,
            cryptographic_checkpoint_signature_verified=False,
            proof_of_resume_execution=False,
            assessment_schema_version=P9E_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P9E_ASSESSMENT_MODE,
            assessment_evidence_sha256=assessment_sha,
        )
