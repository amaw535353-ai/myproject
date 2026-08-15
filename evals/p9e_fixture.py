from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.training.training_execution_types import (
    P9D_ASSESSMENT_MODE,
    P9D_ASSESSMENT_SCHEMA_VERSION,
    TrainingExecutionDecision,
    VerifiedTrainingExecutionAssessment,
)
from aegis.training.checkpoint_integrity_types import *

NOW = 1_800_030_000
LINEAGE_ID = "p9e-checkpoint-lineage-001"
EXECUTION_ID = "p9d-training-execution-001"
JOB_ID = "train-job-helpdesk-security-001"
PRINCIPAL_ID = "trainer-security"
CHECKPOINT_IDS = ("ckpt-000000", "ckpt-000400", "ckpt-000800")


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


P9D_ASSESSMENT_SHA = h("p9d-clean-assessment:p9e-bound")


def build_p9d_assessment() -> VerifiedTrainingExecutionAssessment:
    return VerifiedTrainingExecutionAssessment(
        execution_id=EXECUTION_ID,
        job_id=JOB_ID,
        decision=TrainingExecutionDecision.ALLOW,
        risks=(),
        p9c_assessment_sha256=h("p9c-assessment"),
        admission_manifest_id="p9c-fine-tuning-manifest-001",
        principal_id=PRINCIPAL_ID,
        task_id="fine-tune-helpdesk-security-v1",
        code_commit_sha="1" * 40,
        code_tree_sha="2" * 40,
        config_sha256=h("train-config"),
        image_sha256=h("trainer-image"),
        secret_ids=("dataset-read", "base-read", "output-write"),
        secret_scopes=("dataset:read", "model:read", "artifact:write"),
        capability_ids=("dataset-read", "base-read", "checkpoint-write", "output-write"),
        planned_output_artifact_id="adapter://aegisdesk/helpdesk-security-v1",
        upstream_p9c_bound=True,
        job_identity_verified=True,
        code_config_provenance_verified=True,
        environment_policy_verified=True,
        secret_least_privilege_verified=True,
        capability_least_privilege_verified=True,
        caller_declared_safety_trusted=False,
        production_scheduler_integrated=False,
        production_secret_manager_integrated=False,
        production_container_runtime_integrated=False,
        proof_of_training_execution=False,
        hardware_attestation_verified=False,
        assessment_schema_version=P9D_ASSESSMENT_SCHEMA_VERSION,
        assessment_mode=P9D_ASSESSMENT_MODE,
        assessment_evidence_sha256=P9D_ASSESSMENT_SHA,
    )


def checkpoint(checkpoint_id: str, step: int, parent: str) -> TrainingCheckpointEvidence:
    return TrainingCheckpointEvidence(
        checkpoint_id=checkpoint_id,
        execution_id=EXECUTION_ID,
        job_id=JOB_ID,
        attempt=1,
        step=step,
        epoch_milli=step * 3,
        parent_checkpoint_id=parent,
        model_state_sha256=h(f"{checkpoint_id}:model"),
        optimizer_state_sha256=h(f"{checkpoint_id}:optimizer"),
        rng_state_sha256=h(f"{checkpoint_id}:rng"),
        data_cursor_sha256=h(f"{checkpoint_id}:cursor"),
        trainer_state_sha256=h(f"{checkpoint_id}:trainer"),
        artifact_sha256=h(f"{checkpoint_id}:artifact"),
        serialization_format="safetensors-checkpoint-v1",
        immutable=True,
        external_reference=False,
        custom_deserializer=False,
    )


def build_fixture() -> dict[str, object]:
    checkpoints = (
        checkpoint(CHECKPOINT_IDS[0], 0, ""),
        checkpoint(CHECKPOINT_IDS[1], 400, CHECKPOINT_IDS[0]),
        checkpoint(CHECKPOINT_IDS[2], 800, CHECKPOINT_IDS[1]),
    )
    auth = CheckpointOperationAuthorization(
        authorization_id="checkpoint-op-auth-001",
        principal_id=PRINCIPAL_ID,
        p9d_assessment_sha256=P9D_ASSESSMENT_SHA,
        action=CheckpointAction.RESUME,
        source_checkpoint_id=CHECKPOINT_IDS[2],
        target_checkpoint_id=CHECKPOINT_IDS[2],
        issued_at_epoch=NOW - 30,
        expires_at_epoch=NOW + 300,
        reason_code="resume-after-preemption",
    )
    manifest = TrainingCheckpointManifest(
        schema_version=P9E_SCHEMA_VERSION,
        lineage_id=LINEAGE_ID,
        created_at_epoch=NOW,
        p9d_assessment_sha256=P9D_ASSESSMENT_SHA,
        execution_id=EXECUTION_ID,
        job_id=JOB_ID,
        checkpoints=checkpoints,
        active_checkpoint_id=CHECKPOINT_IDS[2],
        action=CheckpointAction.RESUME,
        source_checkpoint_id=CHECKPOINT_IDS[2],
        target_checkpoint_id=CHECKPOINT_IDS[2],
        next_step=801,
        authorization=auth,
    )
    policy = TrainingCheckpointPolicy(
        policy_version=P9E_POLICY_VERSION,
        expected_lineage_id=LINEAGE_ID,
        expected_manifest_sha256=training_checkpoint_manifest_digest(manifest),
        expected_p9d_assessment_sha256=P9D_ASSESSMENT_SHA,
        expected_execution_id=EXECUTION_ID,
        expected_job_id=JOB_ID,
        expected_principal_id=PRINCIPAL_ID,
        expected_checkpoint_order=CHECKPOINT_IDS,
        expected_checkpoint_step_by_id={c.checkpoint_id: c.step for c in checkpoints},
        expected_checkpoint_parent_by_id={c.checkpoint_id: c.parent_checkpoint_id for c in checkpoints},
        expected_checkpoint_artifact_sha256_by_id={c.checkpoint_id: c.artifact_sha256 for c in checkpoints},
        expected_model_state_sha256_by_id={c.checkpoint_id: c.model_state_sha256 for c in checkpoints},
        expected_optimizer_state_sha256_by_id={c.checkpoint_id: c.optimizer_state_sha256 for c in checkpoints},
        expected_rng_state_sha256_by_id={c.checkpoint_id: c.rng_state_sha256 for c in checkpoints},
        expected_data_cursor_sha256_by_id={c.checkpoint_id: c.data_cursor_sha256 for c in checkpoints},
        expected_trainer_state_sha256_by_id={c.checkpoint_id: c.trainer_state_sha256 for c in checkpoints},
        allowed_serialization_formats=("safetensors-checkpoint-v1",),
        allowed_actions=(CheckpointAction.SAVE, CheckpointAction.RESUME, CheckpointAction.ROLLBACK),
        allowed_rollback_targets=(CHECKPOINT_IDS[1],),
        max_checkpoint_step=2_000,
        max_manifest_age_seconds=300,
        max_future_skew_seconds=5,
    )
    request = TrainingCheckpointRequest(
        lineage_id=LINEAGE_ID,
        manifest_sha256=training_checkpoint_manifest_digest(manifest),
        evaluated_at_epoch=NOW,
        declared_checkpoint_ids=CHECKPOINT_IDS,
        declared_active_checkpoint_id=CHECKPOINT_IDS[2],
        declared_action=CheckpointAction.RESUME,
        declared_source_checkpoint_id=CHECKPOINT_IDS[2],
        declared_target_checkpoint_id=CHECKPOINT_IDS[2],
        declared_next_step=801,
        declared_upstream_bound=True,
        declared_lineage_integrity=True,
        declared_state_integrity=True,
        declared_operation_authorized=True,
        declared_checkpoint_safe=True,
    )
    return {"manifest": manifest, "policy": policy, "request": request, "p9d": build_p9d_assessment()}


def rebind(fixture: dict[str, object], *, manifest=None, p9d=None, request_updates=None, policy_updates=None) -> dict[str, object]:
    manifest = manifest or fixture["manifest"]
    p9d = p9d or fixture["p9d"]
    policy = fixture["policy"]
    request = fixture["request"]
    request_updates = request_updates or {}
    policy_updates = policy_updates or {}
    assert isinstance(manifest, TrainingCheckpointManifest)
    assert isinstance(policy, TrainingCheckpointPolicy)
    assert isinstance(request, TrainingCheckpointRequest)
    digest = training_checkpoint_manifest_digest(manifest)
    out = dict(fixture)
    out["manifest"] = manifest
    out["p9d"] = p9d
    out["policy"] = replace(policy, expected_manifest_sha256=digest, **policy_updates)
    defaults = dict(
        manifest_sha256=digest,
        declared_checkpoint_ids=tuple(c.checkpoint_id for c in manifest.checkpoints),
        declared_active_checkpoint_id=manifest.active_checkpoint_id,
        declared_action=manifest.action,
        declared_source_checkpoint_id=manifest.source_checkpoint_id,
        declared_target_checkpoint_id=manifest.target_checkpoint_id,
        declared_next_step=manifest.next_step,
    )
    defaults.update(request_updates)
    out["request"] = replace(request, **defaults)
    return out
