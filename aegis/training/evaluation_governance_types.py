from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P9F_POLICY_VERSION = "evaluation-benchmark-contamination-governance-v1"
P9F_SCHEMA_VERSION = "aegis-evaluation-benchmark-manifest-v1"
P9F_ASSESSMENT_SCHEMA_VERSION = "aegis-evaluation-benchmark-assessment-v1"
P9F_ASSESSMENT_MODE = "deterministic-evidence-bound-evaluation-governance-v1"


class EvaluationDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class EvaluationRisk(str, Enum):
    UPSTREAM_P9E_INVALID = "upstream_p9e_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    CHECKPOINT_IDENTITY_MISMATCH = "checkpoint_identity_mismatch"
    TRAINING_EXPOSURE_BINDING_MISMATCH = "training_exposure_binding_mismatch"
    BENCHMARK_IDENTITY_MISMATCH = "benchmark_identity_mismatch"
    BENCHMARK_SOURCE_MISMATCH = "benchmark_source_mismatch"
    BENCHMARK_SNAPSHOT_MISMATCH = "benchmark_snapshot_mismatch"
    EVAL_RECORD_COVERAGE_MISMATCH = "eval_record_coverage_mismatch"
    EVAL_RECORD_DIGEST_MISMATCH = "eval_record_digest_mismatch"
    RECORD_ID_OVERLAP = "record_id_overlap"
    CANONICAL_FINGERPRINT_OVERLAP = "canonical_fingerprint_overlap"
    TRANSFORM_FINGERPRINT_OVERLAP = "transform_fingerprint_overlap"
    TRAINING_DERIVATION_LEAK = "training_derivation_leak"
    HIDDEN_LABEL_EXPOSURE = "hidden_label_exposure"
    DYNAMIC_OR_EXTERNAL_DATA = "dynamic_or_external_data"
    SCORING_CODE_MISMATCH = "scoring_code_mismatch"
    PROMPT_TEMPLATE_MISMATCH = "prompt_template_mismatch"
    METRIC_MISMATCH = "metric_mismatch"
    FEWSHOT_CONFIG_MISMATCH = "fewshot_config_mismatch"
    SHUFFLE_SEED_MISMATCH = "shuffle_seed_mismatch"
    SAMPLE_COUNT_MISMATCH = "sample_count_mismatch"
    INFERENCE_CONFIG_MISMATCH = "inference_config_mismatch"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"
    RESULT_EVIDENCE_MISMATCH = "result_evidence_mismatch"


class EvaluationRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class EvaluationSecurityRejected(ValueError):
    def __init__(self, reason: EvaluationRejectReason, message: str):
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message


def reject(reason: EvaluationRejectReason, message: str) -> None:
    raise EvaluationSecurityRejected(reason, message)


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
class BenchmarkRecordEvidence:
    record_id: str
    payload_sha256: str
    label_sha256: str
    canonical_fingerprint_sha256: str
    transform_fingerprint_sha256: str
    derived_from_training_record_id: str = ""


@dataclass(frozen=True)
class BenchmarkSourceEvidence:
    benchmark_id: str
    benchmark_version: str
    split: str
    owner: str
    uri: str
    immutable_revision: str
    snapshot_sha256: str
    records: tuple[BenchmarkRecordEvidence, ...]
    labels_exposed_to_training: bool = False
    dynamic_generation: bool = False
    external_fetch: bool = False


@dataclass(frozen=True)
class EvaluationProtocolEvidence:
    scoring_code_sha256: str
    prompt_template_sha256: str
    metric_ids: tuple[str, ...]
    fewshot_example_ids: tuple[str, ...]
    fewshot_examples_sha256: str
    shuffle_seed: int
    sample_limit: int
    temperature_milli: int
    max_output_tokens: int
    network_operations: int = 0


@dataclass(frozen=True)
class EvaluationResultEvidence:
    result_id: str
    checkpoint_id: str
    evaluated_record_ids: tuple[str, ...]
    output_records_sha256: str
    score_basis_points: int


@dataclass(frozen=True)
class EvaluationBenchmarkManifest:
    schema_version: str
    evaluation_id: str
    created_at_epoch: int
    p9e_assessment_sha256: str
    checkpoint_lineage_id: str
    checkpoint_id: str
    training_exposure_sha256: str
    training_record_ids: tuple[str, ...]
    training_canonical_fingerprint_sha256s: tuple[str, ...]
    training_transform_fingerprint_sha256s: tuple[str, ...]
    benchmark: BenchmarkSourceEvidence
    protocol: EvaluationProtocolEvidence
    result: EvaluationResultEvidence


@dataclass(frozen=True)
class EvaluationBenchmarkPolicy:
    policy_version: str
    expected_evaluation_id: str
    expected_manifest_sha256: str
    expected_p9e_assessment_sha256: str
    expected_checkpoint_lineage_id: str
    expected_checkpoint_id: str
    expected_training_exposure_sha256: str
    expected_training_record_ids: tuple[str, ...]
    expected_training_canonical_fingerprint_sha256s: tuple[str, ...]
    expected_training_transform_fingerprint_sha256s: tuple[str, ...]
    expected_benchmark_id: str
    expected_benchmark_version: str
    expected_benchmark_split: str
    expected_benchmark_owner: str
    expected_benchmark_uri_prefix: str
    expected_benchmark_revision: str
    expected_benchmark_snapshot_sha256: str
    expected_record_order: tuple[str, ...]
    expected_payload_sha256_by_record_id: Mapping[str, str]
    expected_label_sha256_by_record_id: Mapping[str, str]
    expected_canonical_fingerprint_sha256_by_record_id: Mapping[str, str]
    expected_transform_fingerprint_sha256_by_record_id: Mapping[str, str]
    expected_scoring_code_sha256: str
    expected_prompt_template_sha256: str
    expected_metric_ids: tuple[str, ...]
    expected_fewshot_example_ids: tuple[str, ...]
    expected_fewshot_examples_sha256: str
    expected_shuffle_seed: int
    expected_sample_limit: int
    expected_temperature_milli: int
    expected_max_output_tokens: int
    expected_result_id: str
    expected_result_checkpoint_id: str
    expected_result_record_ids: tuple[str, ...]
    expected_output_records_sha256: str
    expected_score_basis_points: int
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class EvaluationBenchmarkRequest:
    evaluation_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_checkpoint_id: str
    declared_benchmark_id: str
    declared_benchmark_version: str
    declared_benchmark_split: str
    declared_evaluated_record_ids: tuple[str, ...]
    declared_score_basis_points: int
    declared_upstream_bound: bool
    declared_benchmark_provenance_valid: bool
    declared_contamination_free: bool
    declared_protocol_valid: bool
    declared_performance_claim_trusted: bool


@dataclass(frozen=True)
class VerifiedEvaluationBenchmarkAssessment:
    evaluation_id: str
    checkpoint_lineage_id: str
    checkpoint_id: str
    decision: EvaluationDecision
    risks: tuple[EvaluationRisk, ...]
    p9e_assessment_sha256: str
    benchmark_id: str
    benchmark_version: str
    benchmark_split: str
    evaluated_record_ids: tuple[str, ...]
    score_basis_points: int
    upstream_p9e_bound: bool
    benchmark_provenance_verified: bool
    contamination_checks_clear: bool
    protocol_verified: bool
    result_evidence_bound: bool
    performance_claim_admissible: bool
    caller_declared_safety_trusted: bool
    production_benchmark_registry_integrated: bool
    semantic_near_duplicate_detection_validated: bool
    score_recomputed_from_model_outputs: bool
    hidden_benchmark_secrecy_proven: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def training_exposure_digest(
    p9e_assessment_sha256: str,
    record_ids: tuple[str, ...],
    canonical_fingerprints: tuple[str, ...],
    transform_fingerprints: tuple[str, ...],
) -> str:
    return digest_json({
        "p9e_assessment_sha256": p9e_assessment_sha256.casefold(),
        "record_ids": tuple(sorted(record_ids)),
        "canonical_fingerprints": tuple(sorted(fp.casefold() for fp in canonical_fingerprints)),
        "transform_fingerprints": tuple(sorted(fp.casefold() for fp in transform_fingerprints)),
    })


def benchmark_snapshot_digest(benchmark: BenchmarkSourceEvidence) -> str:
    return digest_json({
        "benchmark_id": benchmark.benchmark_id,
        "benchmark_version": benchmark.benchmark_version,
        "split": benchmark.split,
        "owner": benchmark.owner,
        "uri": benchmark.uri,
        "immutable_revision": benchmark.immutable_revision,
        "records": benchmark.records,
    })


def evaluation_result_digest(result: EvaluationResultEvidence) -> str:
    return digest_json(result)


def evaluation_benchmark_manifest_digest(manifest: EvaluationBenchmarkManifest) -> str:
    return digest_json(manifest)
