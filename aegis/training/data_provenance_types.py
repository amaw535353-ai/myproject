from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping


P9A_DATASET_POLICY_VERSION = "training-dataset-provenance-lineage-v1"
P9A_DATASET_SCHEMA_VERSION = "aegis-training-dataset-manifest-v1"
P9A_ASSESSMENT_SCHEMA_VERSION = "aegis-training-dataset-assessment-v1"
P9A_ASSESSMENT_MODE = "deterministic-evidence-bound-training-data-provenance-v1"
ZERO_SHA256 = "0" * 64


class DatasetSplit(str, Enum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


class TransformKind(str, Enum):
    NORMALIZE_TEXT = "normalize_text"
    DEDUPLICATE_EXACT = "deduplicate_exact"
    CANONICALIZE_FIELDS = "canonicalize_fields"


class TrainingDataDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class TrainingDataRisk(str, Enum):
    SOURCE_IDENTITY_MISMATCH = "source_identity_mismatch"
    SOURCE_OWNER_UNTRUSTED = "source_owner_untrusted"
    SOURCE_URI_UNTRUSTED = "source_uri_untrusted"
    SOURCE_REVISION_MISMATCH = "source_revision_mismatch"
    SOURCE_DIGEST_MISMATCH = "source_digest_mismatch"
    SOURCE_TIME_INVALID = "source_time_invalid"
    RECORD_COVERAGE_MISMATCH = "record_coverage_mismatch"
    RECORD_DIGEST_MISMATCH = "record_digest_mismatch"
    RECORD_SOURCE_MISMATCH = "record_source_mismatch"
    RECORD_KEY_MISMATCH = "record_key_mismatch"
    RECORD_PARENT_MISMATCH = "record_parent_mismatch"
    RECORD_PARENT_MISSING = "record_parent_missing"
    SPLIT_COVERAGE_MISMATCH = "split_coverage_mismatch"
    SPLIT_ASSIGNMENT_MISMATCH = "split_assignment_mismatch"
    SPLIT_OVERLAP = "split_overlap"
    HOLDOUT_LEAKAGE = "holdout_leakage"
    TRANSFORM_COVERAGE_MISMATCH = "transform_coverage_mismatch"
    TRANSFORM_UNAUTHORIZED = "transform_unauthorized"
    TRANSFORM_OWNER_MISMATCH = "transform_owner_mismatch"
    TRANSFORM_CONFIG_MISMATCH = "transform_config_mismatch"
    TRANSFORM_CHAIN_BROKEN = "transform_chain_broken"
    FINAL_DATASET_DIGEST_MISMATCH = "final_dataset_digest_mismatch"
    NETWORK_SIDE_EFFECT_REPORTED = "network_side_effect_reported"


class TrainingDataRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class TrainingDataSecurityRejected(ValueError):
    def __init__(self, reason: TrainingDataRejectReason, message: str):
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message


def reject(reason: TrainingDataRejectReason, message: str) -> None:
    raise TrainingDataSecurityRejected(reason, message)


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {k: _jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(k.value if isinstance(k, Enum) else k): _jsonable(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    return value


def canonical_json_bytes(value) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_json(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class DatasetSourceSnapshot:
    source_id: str
    owner: str
    uri: str
    revision: str
    snapshot_sha256: str
    observed_at_epoch: int


@dataclass(frozen=True)
class DatasetRecordEvidence:
    record_id: str
    source_id: str
    source_record_key: str
    payload_sha256: str
    parent_record_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DatasetTransformEvidence:
    transform_id: str
    kind: TransformKind
    owner: str
    config_sha256: str
    input_dataset_sha256: str
    output_dataset_sha256: str
    predecessor_transform_sha256: str
    network_operations: int = 0


@dataclass(frozen=True)
class TrainingDatasetManifest:
    schema_version: str
    manifest_id: str
    dataset_id: str
    dataset_version: str
    created_at_epoch: int
    source_snapshots: tuple[DatasetSourceSnapshot, ...]
    records: tuple[DatasetRecordEvidence, ...]
    split_record_ids_by_split: Mapping[DatasetSplit, tuple[str, ...]]
    transforms: tuple[DatasetTransformEvidence, ...]
    final_dataset_sha256: str


@dataclass(frozen=True)
class TrainingDatasetPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_dataset_id: str
    expected_dataset_version: str
    expected_manifest_sha256: str
    trusted_source_owners: tuple[str, ...]
    allowed_source_uri_prefix_by_owner: Mapping[str, str]
    expected_source_revision_by_id: Mapping[str, str]
    expected_source_snapshot_sha256_by_id: Mapping[str, str]
    expected_record_sha256_by_id: Mapping[str, str]
    expected_record_source_by_id: Mapping[str, str]
    expected_record_key_by_id: Mapping[str, str]
    expected_parent_record_ids_by_id: Mapping[str, tuple[str, ...]]
    expected_split_by_record_id: Mapping[str, DatasetSplit]
    expected_transform_order: tuple[str, ...]
    expected_transform_kind_by_id: Mapping[str, TransformKind]
    expected_transform_owner_by_id: Mapping[str, str]
    expected_transform_config_sha256_by_id: Mapping[str, str]
    expected_final_dataset_sha256: str
    max_manifest_age_seconds: int
    max_future_skew_seconds: int
    max_source_age_seconds: int


@dataclass(frozen=True)
class TrainingDatasetRequest:
    manifest_id: str
    manifest_sha256: str
    dataset_id: str
    dataset_version: str
    evaluated_at_epoch: int
    declared_source_ids: tuple[str, ...]
    declared_record_count: int
    declared_split_counts: Mapping[DatasetSplit, int]
    declared_final_dataset_sha256: str
    declared_training_data_safe: bool
    declared_provenance_complete: bool


@dataclass(frozen=True)
class VerifiedTrainingDatasetAssessment:
    manifest_id: str
    dataset_id: str
    dataset_version: str
    decision: TrainingDataDecision
    risks: tuple[TrainingDataRisk, ...]
    source_count: int
    record_count: int
    split_counts: Mapping[DatasetSplit, int]
    transform_count: int
    final_dataset_sha256: str
    exact_manifest_binding_verified: bool
    trusted_source_snapshots_verified: bool
    record_hash_coverage_verified: bool
    split_isolation_verified: bool
    transform_lineage_verified: bool
    caller_declared_training_data_safety_trusted: bool
    production_data_lake_integration: bool
    production_training_pipeline_attestation: bool
    cryptographic_source_authentication: bool
    network_operations: int
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def canonical_training_dataset_manifest_bytes(manifest: TrainingDatasetManifest) -> bytes:
    return canonical_json_bytes(manifest)


def training_dataset_manifest_digest(manifest: TrainingDatasetManifest) -> str:
    return hashlib.sha256(canonical_training_dataset_manifest_bytes(manifest)).hexdigest()


def raw_dataset_digest(manifest: TrainingDatasetManifest) -> str:
    payload = {
        "source_snapshots": manifest.source_snapshots,
        "records": manifest.records,
        "split_record_ids_by_split": manifest.split_record_ids_by_split,
    }
    return digest_json(payload)


def transform_evidence_digest(transform: DatasetTransformEvidence) -> str:
    return digest_json(transform)


def deterministic_transform_output_digest(
    input_dataset_sha256: str,
    transform_id: str,
    kind: TransformKind,
    owner: str,
    config_sha256: str,
) -> str:
    return digest_json(
        {
            "input_dataset_sha256": input_dataset_sha256.casefold(),
            "transform_id": transform_id,
            "kind": kind,
            "owner": owner,
            "config_sha256": config_sha256.casefold(),
        }
    )
