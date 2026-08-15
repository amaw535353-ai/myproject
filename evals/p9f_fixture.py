from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.training.checkpoint_integrity_types import (
    P9E_ASSESSMENT_MODE,
    P9E_ASSESSMENT_SCHEMA_VERSION,
    CheckpointDecision,
    VerifiedTrainingCheckpointAssessment,
)
from aegis.training.evaluation_governance_types import *

NOW = 1_800_040_000
EVALUATION_ID = "p9f-evaluation-001"
LINEAGE_ID = "p9e-checkpoint-lineage-001"
CHECKPOINT_ID = "ckpt-0800"
BENCHMARK_ID = "aegisdesk-heldout-security"
BENCHMARK_VERSION = "2026.08-p9f"
BENCHMARK_SPLIT = "test"
RESULT_ID = "p9f-result-001"
TRAINING_RECORD_IDS = tuple(f"record-{i:02d}" for i in range(1, 9))
EVAL_RECORD_IDS = tuple(f"eval-{i:02d}" for i in range(1, 7))
FEWSHOT_IDS = ("fewshot-clean-01", "fewshot-clean-02")


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


P9E_ASSESSMENT_SHA = h("p9e-clean-assessment:p9f-bound")
TRAIN_CANON = tuple(h(f"train-canonical:{rid}") for rid in TRAINING_RECORD_IDS)
TRAIN_TRANSFORM = tuple(h(f"train-transform:{rid}") for rid in TRAINING_RECORD_IDS)
TRAINING_EXPOSURE_SHA = training_exposure_digest(
    P9E_ASSESSMENT_SHA,
    TRAINING_RECORD_IDS,
    TRAIN_CANON,
    TRAIN_TRANSFORM,
)


def build_p9e_assessment() -> VerifiedTrainingCheckpointAssessment:
    return VerifiedTrainingCheckpointAssessment(
        lineage_id=LINEAGE_ID,
        execution_id="p9d-training-execution-001",
        job_id="train-job-p9d-001",
        decision=CheckpointDecision.ALLOW,
        risks=(),
        p9d_assessment_sha256=h("p9d-clean-assessment:p9e-bound"),
        checkpoint_ids=("ckpt-0000", "ckpt-0400", CHECKPOINT_ID),
        active_checkpoint_id=CHECKPOINT_ID,
        action="resume",
        source_checkpoint_id=CHECKPOINT_ID,
        target_checkpoint_id=CHECKPOINT_ID,
        next_step=801,
        upstream_p9d_bound=True,
        checkpoint_lineage_verified=True,
        checkpoint_state_integrity_verified=True,
        operation_authorization_verified=True,
        rollback_safe=True,
        caller_declared_safety_trusted=False,
        production_checkpoint_store_integrated=False,
        cryptographic_checkpoint_signature_verified=False,
        proof_of_resume_execution=False,
        assessment_schema_version=P9E_ASSESSMENT_SCHEMA_VERSION,
        assessment_mode=P9E_ASSESSMENT_MODE,
        assessment_evidence_sha256=P9E_ASSESSMENT_SHA,
    )


def _records() -> tuple[BenchmarkRecordEvidence, ...]:
    return tuple(
        BenchmarkRecordEvidence(
            record_id=rid,
            payload_sha256=h(f"eval-payload:{rid}:v1"),
            label_sha256=h(f"eval-label:{rid}:v1"),
            canonical_fingerprint_sha256=h(f"eval-canonical:{rid}:v1"),
            transform_fingerprint_sha256=h(f"eval-transform:{rid}:v1"),
        )
        for rid in EVAL_RECORD_IDS
    )


def build_fixture() -> dict[str, object]:
    records = _records()
    benchmark0 = BenchmarkSourceEvidence(
        benchmark_id=BENCHMARK_ID,
        benchmark_version=BENCHMARK_VERSION,
        split=BENCHMARK_SPLIT,
        owner="benchmark-curation",
        uri="dataset://benchmarks/aegisdesk/heldout-security",
        immutable_revision="snapshot-2026-08-15-r1",
        snapshot_sha256="0" * 64,
        records=records,
    )
    benchmark = replace(benchmark0, snapshot_sha256=benchmark_snapshot_digest(benchmark0))
    protocol = EvaluationProtocolEvidence(
        scoring_code_sha256=h("scoring-code:p9f:v1"),
        prompt_template_sha256=h("prompt-template:p9f:v1"),
        metric_ids=("accuracy", "policy_violation_rate"),
        fewshot_example_ids=FEWSHOT_IDS,
        fewshot_examples_sha256=h("fewshot-clean:p9f:v1"),
        shuffle_seed=29,
        sample_limit=len(records),
        temperature_milli=0,
        max_output_tokens=64,
        network_operations=0,
    )
    result = EvaluationResultEvidence(
        result_id=RESULT_ID,
        checkpoint_id=CHECKPOINT_ID,
        evaluated_record_ids=EVAL_RECORD_IDS,
        output_records_sha256=h("evaluation-output-records:p9f:v1"),
        score_basis_points=8333,
    )
    manifest = EvaluationBenchmarkManifest(
        schema_version=P9F_SCHEMA_VERSION,
        evaluation_id=EVALUATION_ID,
        created_at_epoch=NOW,
        p9e_assessment_sha256=P9E_ASSESSMENT_SHA,
        checkpoint_lineage_id=LINEAGE_ID,
        checkpoint_id=CHECKPOINT_ID,
        training_exposure_sha256=TRAINING_EXPOSURE_SHA,
        training_record_ids=TRAINING_RECORD_IDS,
        training_canonical_fingerprint_sha256s=TRAIN_CANON,
        training_transform_fingerprint_sha256s=TRAIN_TRANSFORM,
        benchmark=benchmark,
        protocol=protocol,
        result=result,
    )
    policy = EvaluationBenchmarkPolicy(
        policy_version=P9F_POLICY_VERSION,
        expected_evaluation_id=EVALUATION_ID,
        expected_manifest_sha256=evaluation_benchmark_manifest_digest(manifest),
        expected_p9e_assessment_sha256=P9E_ASSESSMENT_SHA,
        expected_checkpoint_lineage_id=LINEAGE_ID,
        expected_checkpoint_id=CHECKPOINT_ID,
        expected_training_exposure_sha256=TRAINING_EXPOSURE_SHA,
        expected_training_record_ids=TRAINING_RECORD_IDS,
        expected_training_canonical_fingerprint_sha256s=TRAIN_CANON,
        expected_training_transform_fingerprint_sha256s=TRAIN_TRANSFORM,
        expected_benchmark_id=BENCHMARK_ID,
        expected_benchmark_version=BENCHMARK_VERSION,
        expected_benchmark_split=BENCHMARK_SPLIT,
        expected_benchmark_owner=benchmark.owner,
        expected_benchmark_uri_prefix="dataset://benchmarks/aegisdesk/",
        expected_benchmark_revision=benchmark.immutable_revision,
        expected_benchmark_snapshot_sha256=benchmark.snapshot_sha256,
        expected_record_order=EVAL_RECORD_IDS,
        expected_payload_sha256_by_record_id={r.record_id: r.payload_sha256 for r in records},
        expected_label_sha256_by_record_id={r.record_id: r.label_sha256 for r in records},
        expected_canonical_fingerprint_sha256_by_record_id={r.record_id: r.canonical_fingerprint_sha256 for r in records},
        expected_transform_fingerprint_sha256_by_record_id={r.record_id: r.transform_fingerprint_sha256 for r in records},
        expected_scoring_code_sha256=protocol.scoring_code_sha256,
        expected_prompt_template_sha256=protocol.prompt_template_sha256,
        expected_metric_ids=protocol.metric_ids,
        expected_fewshot_example_ids=protocol.fewshot_example_ids,
        expected_fewshot_examples_sha256=protocol.fewshot_examples_sha256,
        expected_shuffle_seed=protocol.shuffle_seed,
        expected_sample_limit=protocol.sample_limit,
        expected_temperature_milli=protocol.temperature_milli,
        expected_max_output_tokens=protocol.max_output_tokens,
        expected_result_id=result.result_id,
        expected_result_checkpoint_id=result.checkpoint_id,
        expected_result_record_ids=result.evaluated_record_ids,
        expected_output_records_sha256=result.output_records_sha256,
        expected_score_basis_points=result.score_basis_points,
        max_manifest_age_seconds=300,
        max_future_skew_seconds=5,
    )
    request = EvaluationBenchmarkRequest(
        evaluation_id=EVALUATION_ID,
        manifest_sha256=evaluation_benchmark_manifest_digest(manifest),
        evaluated_at_epoch=NOW,
        declared_checkpoint_id=CHECKPOINT_ID,
        declared_benchmark_id=BENCHMARK_ID,
        declared_benchmark_version=BENCHMARK_VERSION,
        declared_benchmark_split=BENCHMARK_SPLIT,
        declared_evaluated_record_ids=EVAL_RECORD_IDS,
        declared_score_basis_points=result.score_basis_points,
        declared_upstream_bound=True,
        declared_benchmark_provenance_valid=True,
        declared_contamination_free=True,
        declared_protocol_valid=True,
        declared_performance_claim_trusted=True,
    )
    return {"manifest": manifest, "policy": policy, "request": request, "p9e": build_p9e_assessment()}


def rebind(
    fixture: dict[str, object],
    *,
    manifest=None,
    p9e=None,
    preserve_declarations: bool = True,
    **request_updates,
) -> dict[str, object]:
    manifest = manifest or fixture["manifest"]
    p9e = p9e or fixture["p9e"]
    policy = fixture["policy"]
    request = fixture["request"]
    assert isinstance(manifest, EvaluationBenchmarkManifest)
    assert isinstance(policy, EvaluationBenchmarkPolicy)
    assert isinstance(request, EvaluationBenchmarkRequest)
    digest = evaluation_benchmark_manifest_digest(manifest)
    out = dict(fixture)
    out["manifest"] = manifest
    out["p9e"] = p9e
    out["policy"] = replace(policy, expected_manifest_sha256=digest)
    identity_updates = {}
    if not preserve_declarations:
        identity_updates = dict(
            declared_checkpoint_id=manifest.checkpoint_id,
            declared_benchmark_id=manifest.benchmark.benchmark_id,
            declared_benchmark_version=manifest.benchmark.benchmark_version,
            declared_benchmark_split=manifest.benchmark.split,
            declared_evaluated_record_ids=manifest.result.evaluated_record_ids,
            declared_score_basis_points=manifest.result.score_basis_points,
        )
    identity_updates.update(request_updates)
    out["request"] = replace(request, manifest_sha256=digest, **identity_updates)
    return out
