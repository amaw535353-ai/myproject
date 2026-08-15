from __future__ import annotations

import re

from .checkpoint_integrity_types import (
    P9E_ASSESSMENT_MODE,
    P9E_ASSESSMENT_SCHEMA_VERSION,
    CheckpointDecision,
)
from .evaluation_governance_types import *

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class EvaluationBenchmarkGovernanceAnalyzer:
    def __init__(self, policy: EvaluationBenchmarkPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9F_POLICY_VERSION:
            reject(EvaluationRejectReason.POLICY_INVALID, "unexpected policy version")
        identities = (
            p.expected_evaluation_id,
            p.expected_checkpoint_lineage_id,
            p.expected_checkpoint_id,
            p.expected_benchmark_id,
            p.expected_benchmark_version,
            p.expected_benchmark_split,
            p.expected_benchmark_owner,
            p.expected_benchmark_uri_prefix,
            p.expected_benchmark_revision,
            p.expected_result_id,
            p.expected_result_checkpoint_id,
        )
        if not all(identities):
            reject(EvaluationRejectReason.POLICY_INVALID, "identity pins are required")
        digest_values = (
            p.expected_manifest_sha256,
            p.expected_p9e_assessment_sha256,
            p.expected_training_exposure_sha256,
            p.expected_benchmark_snapshot_sha256,
            p.expected_scoring_code_sha256,
            p.expected_prompt_template_sha256,
            p.expected_fewshot_examples_sha256,
            p.expected_output_records_sha256,
            *p.expected_training_canonical_fingerprint_sha256s,
            *p.expected_training_transform_fingerprint_sha256s,
            *p.expected_payload_sha256_by_record_id.values(),
            *p.expected_label_sha256_by_record_id.values(),
            *p.expected_canonical_fingerprint_sha256_by_record_id.values(),
            *p.expected_transform_fingerprint_sha256_by_record_id.values(),
        )
        if not all(self._sha(v) for v in digest_values):
            reject(EvaluationRejectReason.POLICY_INVALID, "digest pins must be sha256")
        if len(p.expected_training_record_ids) != len(set(p.expected_training_record_ids)):
            reject(EvaluationRejectReason.POLICY_INVALID, "training record IDs must be unique")
        if len(p.expected_training_canonical_fingerprint_sha256s) != len(set(p.expected_training_canonical_fingerprint_sha256s)):
            reject(EvaluationRejectReason.POLICY_INVALID, "training canonical fingerprints must be unique")
        if len(p.expected_training_transform_fingerprint_sha256s) != len(set(p.expected_training_transform_fingerprint_sha256s)):
            reject(EvaluationRejectReason.POLICY_INVALID, "training transform fingerprints must be unique")
        ids = p.expected_record_order
        if not ids or len(ids) != len(set(ids)):
            reject(EvaluationRejectReason.POLICY_INVALID, "benchmark record order must be non-empty and unique")
        maps = (
            p.expected_payload_sha256_by_record_id,
            p.expected_label_sha256_by_record_id,
            p.expected_canonical_fingerprint_sha256_by_record_id,
            p.expected_transform_fingerprint_sha256_by_record_id,
        )
        if any(set(m) != set(ids) for m in maps):
            reject(EvaluationRejectReason.POLICY_INVALID, "record pin maps must exactly cover benchmark record order")
        if not p.expected_metric_ids or len(p.expected_metric_ids) != len(set(p.expected_metric_ids)):
            reject(EvaluationRejectReason.POLICY_INVALID, "metric IDs must be non-empty and unique")
        if len(p.expected_fewshot_example_ids) != len(set(p.expected_fewshot_example_ids)):
            reject(EvaluationRejectReason.POLICY_INVALID, "few-shot IDs must be unique")
        if p.expected_sample_limit != len(ids) or p.expected_sample_limit <= 0:
            reject(EvaluationRejectReason.POLICY_INVALID, "sample limit must exactly cover benchmark records")
        if p.expected_temperature_milli < 0 or p.expected_max_output_tokens <= 0:
            reject(EvaluationRejectReason.POLICY_INVALID, "inference bounds invalid")
        if not (0 <= p.expected_score_basis_points <= 10_000):
            reject(EvaluationRejectReason.POLICY_INVALID, "score basis points invalid")
        if p.expected_result_record_ids != ids:
            reject(EvaluationRejectReason.POLICY_INVALID, "result record order must equal benchmark order")
        if p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(EvaluationRejectReason.POLICY_INVALID, "freshness bounds invalid")

    def _validate_manifest(self, manifest: EvaluationBenchmarkManifest) -> None:
        if manifest.schema_version != P9F_SCHEMA_VERSION:
            reject(EvaluationRejectReason.MANIFEST_INVALID, "unexpected manifest schema")
        if not all((
            manifest.evaluation_id,
            manifest.checkpoint_lineage_id,
            manifest.checkpoint_id,
            manifest.benchmark.benchmark_id,
            manifest.benchmark.benchmark_version,
            manifest.benchmark.split,
            manifest.result.result_id,
        )):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "evaluation identity incomplete")
        if not self._sha(manifest.p9e_assessment_sha256) or not self._sha(manifest.training_exposure_sha256):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "upstream/training exposure digests invalid")
        if len(manifest.training_record_ids) != len(set(manifest.training_record_ids)):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "duplicate training record IDs")
        if not all(self._sha(v) for v in manifest.training_canonical_fingerprint_sha256s + manifest.training_transform_fingerprint_sha256s):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "training fingerprints invalid")
        benchmark = manifest.benchmark
        if not all((benchmark.owner, benchmark.uri, benchmark.immutable_revision)) or not self._sha(benchmark.snapshot_sha256):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "benchmark source evidence incomplete")
        record_ids = tuple(r.record_id for r in benchmark.records)
        if not record_ids or len(record_ids) != len(set(record_ids)):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "benchmark record IDs must be non-empty and unique")
        for record in benchmark.records:
            if not record.record_id:
                reject(EvaluationRejectReason.MANIFEST_INVALID, "record ID required")
            if not all(self._sha(v) for v in (
                record.payload_sha256,
                record.label_sha256,
                record.canonical_fingerprint_sha256,
                record.transform_fingerprint_sha256,
            )):
                reject(EvaluationRejectReason.MANIFEST_INVALID, "benchmark record digest invalid")
        protocol = manifest.protocol
        if not all(self._sha(v) for v in (
            protocol.scoring_code_sha256,
            protocol.prompt_template_sha256,
            protocol.fewshot_examples_sha256,
        )):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "protocol digest invalid")
        if not protocol.metric_ids or len(protocol.metric_ids) != len(set(protocol.metric_ids)):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "protocol metrics invalid")
        if len(protocol.fewshot_example_ids) != len(set(protocol.fewshot_example_ids)):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "duplicate few-shot examples")
        if protocol.sample_limit <= 0 or protocol.temperature_milli < 0 or protocol.max_output_tokens <= 0 or protocol.network_operations < 0:
            reject(EvaluationRejectReason.MANIFEST_INVALID, "protocol bounds invalid")
        result = manifest.result
        if not self._sha(result.output_records_sha256) or not (0 <= result.score_basis_points <= 10_000):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "result evidence invalid")
        if len(result.evaluated_record_ids) != len(set(result.evaluated_record_ids)):
            reject(EvaluationRejectReason.MANIFEST_INVALID, "result records must be unique")

    def _upstream_ok(self, assessment) -> bool:
        flags = (
            getattr(assessment, "upstream_p9d_bound", False),
            getattr(assessment, "checkpoint_lineage_verified", False),
            getattr(assessment, "checkpoint_state_integrity_verified", False),
            getattr(assessment, "operation_authorization_verified", False),
            getattr(assessment, "rollback_safe", False),
        )
        return (
            getattr(assessment, "decision", None) == CheckpointDecision.ALLOW
            and not getattr(assessment, "risks", ())
            and all(flags)
            and not getattr(assessment, "caller_declared_safety_trusted", True)
            and not getattr(assessment, "production_checkpoint_store_integrated", True)
            and not getattr(assessment, "cryptographic_checkpoint_signature_verified", True)
            and not getattr(assessment, "proof_of_resume_execution", True)
            and getattr(assessment, "assessment_schema_version", None) == P9E_ASSESSMENT_SCHEMA_VERSION
            and getattr(assessment, "assessment_mode", None) == P9E_ASSESSMENT_MODE
        )

    def derive(self, manifest: EvaluationBenchmarkManifest, p9e_assessment) -> tuple[EvaluationRisk, ...]:
        self._validate_manifest(manifest)
        p = self.policy
        risks: set[EvaluationRisk] = set()

        if not self._upstream_ok(p9e_assessment):
            risks.add(EvaluationRisk.UPSTREAM_P9E_INVALID)
        actual_upstream_sha = getattr(p9e_assessment, "assessment_evidence_sha256", "")
        if (
            manifest.p9e_assessment_sha256.casefold() != p.expected_p9e_assessment_sha256.casefold()
            or actual_upstream_sha.casefold() != p.expected_p9e_assessment_sha256.casefold()
        ):
            risks.add(EvaluationRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            manifest.checkpoint_lineage_id != p.expected_checkpoint_lineage_id
            or manifest.checkpoint_id != p.expected_checkpoint_id
            or getattr(p9e_assessment, "lineage_id", None) != p.expected_checkpoint_lineage_id
            or getattr(p9e_assessment, "active_checkpoint_id", None) != p.expected_checkpoint_id
        ):
            risks.add(EvaluationRisk.CHECKPOINT_IDENTITY_MISMATCH)

        exposure_sha = training_exposure_digest(
            manifest.p9e_assessment_sha256,
            manifest.training_record_ids,
            manifest.training_canonical_fingerprint_sha256s,
            manifest.training_transform_fingerprint_sha256s,
        )
        if (
            manifest.training_exposure_sha256.casefold() != exposure_sha.casefold()
            or manifest.training_exposure_sha256.casefold() != p.expected_training_exposure_sha256.casefold()
            or tuple(sorted(manifest.training_record_ids)) != tuple(sorted(p.expected_training_record_ids))
            or tuple(sorted(v.casefold() for v in manifest.training_canonical_fingerprint_sha256s))
               != tuple(sorted(v.casefold() for v in p.expected_training_canonical_fingerprint_sha256s))
            or tuple(sorted(v.casefold() for v in manifest.training_transform_fingerprint_sha256s))
               != tuple(sorted(v.casefold() for v in p.expected_training_transform_fingerprint_sha256s))
        ):
            risks.add(EvaluationRisk.TRAINING_EXPOSURE_BINDING_MISMATCH)

        b = manifest.benchmark
        if (
            b.benchmark_id != p.expected_benchmark_id
            or b.benchmark_version != p.expected_benchmark_version
            or b.split != p.expected_benchmark_split
        ):
            risks.add(EvaluationRisk.BENCHMARK_IDENTITY_MISMATCH)
        if (
            b.owner != p.expected_benchmark_owner
            or not b.uri.startswith(p.expected_benchmark_uri_prefix)
            or b.immutable_revision != p.expected_benchmark_revision
        ):
            risks.add(EvaluationRisk.BENCHMARK_SOURCE_MISMATCH)
        computed_snapshot = benchmark_snapshot_digest(b)
        if (
            b.snapshot_sha256.casefold() != computed_snapshot.casefold()
            or b.snapshot_sha256.casefold() != p.expected_benchmark_snapshot_sha256.casefold()
        ):
            risks.add(EvaluationRisk.BENCHMARK_SNAPSHOT_MISMATCH)

        record_ids = tuple(r.record_id for r in b.records)
        if record_ids != p.expected_record_order:
            risks.add(EvaluationRisk.EVAL_RECORD_COVERAGE_MISMATCH)

        training_ids = set(manifest.training_record_ids)
        training_canon = {v.casefold() for v in manifest.training_canonical_fingerprint_sha256s}
        training_transform = {v.casefold() for v in manifest.training_transform_fingerprint_sha256s}
        for record in b.records:
            expected = (
                p.expected_payload_sha256_by_record_id.get(record.record_id),
                p.expected_label_sha256_by_record_id.get(record.record_id),
                p.expected_canonical_fingerprint_sha256_by_record_id.get(record.record_id),
                p.expected_transform_fingerprint_sha256_by_record_id.get(record.record_id),
            )
            actual = (
                record.payload_sha256,
                record.label_sha256,
                record.canonical_fingerprint_sha256,
                record.transform_fingerprint_sha256,
            )
            if any(e is None or a.casefold() != e.casefold() for a, e in zip(actual, expected)):
                risks.add(EvaluationRisk.EVAL_RECORD_DIGEST_MISMATCH)
            if record.record_id in training_ids:
                risks.add(EvaluationRisk.RECORD_ID_OVERLAP)
            if record.canonical_fingerprint_sha256.casefold() in training_canon:
                risks.add(EvaluationRisk.CANONICAL_FINGERPRINT_OVERLAP)
            if record.transform_fingerprint_sha256.casefold() in training_transform:
                risks.add(EvaluationRisk.TRANSFORM_FINGERPRINT_OVERLAP)
            if record.derived_from_training_record_id:
                risks.add(EvaluationRisk.TRAINING_DERIVATION_LEAK)

        if b.labels_exposed_to_training:
            risks.add(EvaluationRisk.HIDDEN_LABEL_EXPOSURE)
        if b.dynamic_generation or b.external_fetch:
            risks.add(EvaluationRisk.DYNAMIC_OR_EXTERNAL_DATA)

        proto = manifest.protocol
        if proto.scoring_code_sha256.casefold() != p.expected_scoring_code_sha256.casefold():
            risks.add(EvaluationRisk.SCORING_CODE_MISMATCH)
        if proto.prompt_template_sha256.casefold() != p.expected_prompt_template_sha256.casefold():
            risks.add(EvaluationRisk.PROMPT_TEMPLATE_MISMATCH)
        if proto.metric_ids != p.expected_metric_ids:
            risks.add(EvaluationRisk.METRIC_MISMATCH)
        if (
            proto.fewshot_example_ids != p.expected_fewshot_example_ids
            or proto.fewshot_examples_sha256.casefold() != p.expected_fewshot_examples_sha256.casefold()
            or any(example_id in set(record_ids) for example_id in proto.fewshot_example_ids)
        ):
            risks.add(EvaluationRisk.FEWSHOT_CONFIG_MISMATCH)
        if proto.shuffle_seed != p.expected_shuffle_seed:
            risks.add(EvaluationRisk.SHUFFLE_SEED_MISMATCH)
        if proto.sample_limit != p.expected_sample_limit or proto.sample_limit != len(record_ids):
            risks.add(EvaluationRisk.SAMPLE_COUNT_MISMATCH)
        if (
            proto.temperature_milli != p.expected_temperature_milli
            or proto.max_output_tokens != p.expected_max_output_tokens
        ):
            risks.add(EvaluationRisk.INFERENCE_CONFIG_MISMATCH)
        if proto.network_operations != 0:
            risks.add(EvaluationRisk.NETWORK_OPERATION_UNEXPECTED)

        result = manifest.result
        if (
            result.result_id != p.expected_result_id
            or result.checkpoint_id != p.expected_result_checkpoint_id
            or result.checkpoint_id != manifest.checkpoint_id
            or result.evaluated_record_ids != p.expected_result_record_ids
            or result.evaluated_record_ids != record_ids
            or result.output_records_sha256.casefold() != p.expected_output_records_sha256.casefold()
            or result.score_basis_points != p.expected_score_basis_points
        ):
            risks.add(EvaluationRisk.RESULT_EVIDENCE_MISMATCH)

        return tuple(sorted(risks, key=lambda r: r.value))

    def evaluate(
        self,
        request: EvaluationBenchmarkRequest,
        manifest: EvaluationBenchmarkManifest,
        p9e_assessment,
    ) -> VerifiedEvaluationBenchmarkAssessment:
        self._validate_manifest(manifest)
        actual_manifest_sha = evaluation_benchmark_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(EvaluationRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest differs from policy-pinned evidence")
        if request.evaluation_id != manifest.evaluation_id or request.manifest_sha256.casefold() != actual_manifest_sha.casefold():
            reject(EvaluationRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(EvaluationRejectReason.REQUEST_INVALID, "evaluation predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(EvaluationRejectReason.REQUEST_INVALID, "manifest is stale")

        risks = self.derive(manifest, p9e_assessment)
        decision = EvaluationDecision.DENY if risks else EvaluationDecision.ALLOW
        risk_set = set(risks)
        upstream_ok = not bool(risk_set & {
            EvaluationRisk.UPSTREAM_P9E_INVALID,
            EvaluationRisk.UPSTREAM_BINDING_MISMATCH,
            EvaluationRisk.CHECKPOINT_IDENTITY_MISMATCH,
        })
        provenance_ok = not bool(risk_set & {
            EvaluationRisk.BENCHMARK_IDENTITY_MISMATCH,
            EvaluationRisk.BENCHMARK_SOURCE_MISMATCH,
            EvaluationRisk.BENCHMARK_SNAPSHOT_MISMATCH,
            EvaluationRisk.EVAL_RECORD_COVERAGE_MISMATCH,
            EvaluationRisk.EVAL_RECORD_DIGEST_MISMATCH,
        })
        contamination_ok = not bool(risk_set & {
            EvaluationRisk.TRAINING_EXPOSURE_BINDING_MISMATCH,
            EvaluationRisk.RECORD_ID_OVERLAP,
            EvaluationRisk.CANONICAL_FINGERPRINT_OVERLAP,
            EvaluationRisk.TRANSFORM_FINGERPRINT_OVERLAP,
            EvaluationRisk.TRAINING_DERIVATION_LEAK,
            EvaluationRisk.HIDDEN_LABEL_EXPOSURE,
            EvaluationRisk.DYNAMIC_OR_EXTERNAL_DATA,
        })
        protocol_ok = not bool(risk_set & {
            EvaluationRisk.SCORING_CODE_MISMATCH,
            EvaluationRisk.PROMPT_TEMPLATE_MISMATCH,
            EvaluationRisk.METRIC_MISMATCH,
            EvaluationRisk.FEWSHOT_CONFIG_MISMATCH,
            EvaluationRisk.SHUFFLE_SEED_MISMATCH,
            EvaluationRisk.SAMPLE_COUNT_MISMATCH,
            EvaluationRisk.INFERENCE_CONFIG_MISMATCH,
            EvaluationRisk.NETWORK_OPERATION_UNEXPECTED,
        })
        result_ok = EvaluationRisk.RESULT_EVIDENCE_MISMATCH not in risk_set
        expected_safe = decision == EvaluationDecision.ALLOW

        declared_identity = (
            request.declared_checkpoint_id == manifest.checkpoint_id
            and request.declared_benchmark_id == manifest.benchmark.benchmark_id
            and request.declared_benchmark_version == manifest.benchmark.benchmark_version
            and request.declared_benchmark_split == manifest.benchmark.split
            and request.declared_evaluated_record_ids == manifest.result.evaluated_record_ids
            and request.declared_score_basis_points == manifest.result.score_basis_points
        )
        if not declared_identity:
            reject(EvaluationRejectReason.DECLARED_SUMMARY_MISMATCH, "declared benchmark/result identity differs from evidence")
        if request.declared_upstream_bound != upstream_ok:
            reject(EvaluationRejectReason.DECLARED_SUMMARY_MISMATCH, "declared upstream binding differs from evidence")
        if request.declared_benchmark_provenance_valid != provenance_ok:
            reject(EvaluationRejectReason.DECLARED_SUMMARY_MISMATCH, "declared benchmark provenance differs from evidence")
        if request.declared_contamination_free != contamination_ok:
            reject(EvaluationRejectReason.DECLARED_SUMMARY_MISMATCH, "declared contamination status differs from evidence")
        if request.declared_protocol_valid != protocol_ok:
            reject(EvaluationRejectReason.DECLARED_SUMMARY_MISMATCH, "declared protocol status differs from evidence")
        if request.declared_performance_claim_trusted != expected_safe:
            reject(EvaluationRejectReason.DECLARED_SUMMARY_MISMATCH, "declared performance claim status differs from evidence")

        assessment_sha = digest_json({
            "evaluation_id": manifest.evaluation_id,
            "p9e_assessment_sha256": manifest.p9e_assessment_sha256,
            "checkpoint_lineage_id": manifest.checkpoint_lineage_id,
            "checkpoint_id": manifest.checkpoint_id,
            "benchmark_id": manifest.benchmark.benchmark_id,
            "benchmark_version": manifest.benchmark.benchmark_version,
            "benchmark_split": manifest.benchmark.split,
            "record_ids": tuple(r.record_id for r in manifest.benchmark.records),
            "score_basis_points": manifest.result.score_basis_points,
            "decision": decision,
            "risks": risks,
            "schema": P9F_ASSESSMENT_SCHEMA_VERSION,
            "mode": P9F_ASSESSMENT_MODE,
        })
        return VerifiedEvaluationBenchmarkAssessment(
            evaluation_id=manifest.evaluation_id,
            checkpoint_lineage_id=manifest.checkpoint_lineage_id,
            checkpoint_id=manifest.checkpoint_id,
            decision=decision,
            risks=risks,
            p9e_assessment_sha256=manifest.p9e_assessment_sha256,
            benchmark_id=manifest.benchmark.benchmark_id,
            benchmark_version=manifest.benchmark.benchmark_version,
            benchmark_split=manifest.benchmark.split,
            evaluated_record_ids=manifest.result.evaluated_record_ids,
            score_basis_points=manifest.result.score_basis_points,
            upstream_p9e_bound=upstream_ok,
            benchmark_provenance_verified=provenance_ok,
            contamination_checks_clear=contamination_ok,
            protocol_verified=protocol_ok,
            result_evidence_bound=result_ok,
            performance_claim_admissible=expected_safe,
            caller_declared_safety_trusted=False,
            production_benchmark_registry_integrated=False,
            semantic_near_duplicate_detection_validated=False,
            score_recomputed_from_model_outputs=False,
            hidden_benchmark_secrecy_proven=False,
            assessment_schema_version=P9F_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P9F_ASSESSMENT_MODE,
            assessment_evidence_sha256=assessment_sha,
        )
