from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P9G_POLICY_VERSION = "sensitive-data-governance-v1"
P9G_SCHEMA_VERSION = "aegis-sensitive-data-governance-manifest-v1"
P9G_ASSESSMENT_SCHEMA_VERSION = "aegis-sensitive-data-governance-assessment-v1"
P9G_ASSESSMENT_MODE = "deterministic-evidence-bound-sensitive-data-governance-v1"


class SensitiveDataDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class DataSurface(str, Enum):
    TRAINING_INPUT = "training_input"
    EVALUATION_INPUT = "evaluation_input"
    MODEL_OUTPUT = "model_output"


class SensitiveKind(str, Enum):
    PII_EMAIL = "pii_email"
    PII_PHONE = "pii_phone"
    API_SECRET = "api_secret"
    CANARY_TOKEN = "canary_token"


class SensitivityClass(str, Enum):
    PUBLIC = "public"
    PERSONAL = "personal"
    SECRET = "secret"
    CANARY = "canary"


class DataDisposition(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    QUARANTINE = "quarantine"
    DENY = "deny"


class SensitiveDataRisk(str, Enum):
    UPSTREAM_P9F_INVALID = "upstream_p9f_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    EVALUATION_IDENTITY_MISMATCH = "evaluation_identity_mismatch"
    SCANNER_PROFILE_MISMATCH = "scanner_profile_mismatch"
    CANARY_REGISTRY_MISMATCH = "canary_registry_mismatch"
    RECORD_COVERAGE_MISMATCH = "record_coverage_mismatch"
    RECORD_SURFACE_MISMATCH = "record_surface_mismatch"
    RECORD_DIGEST_MISMATCH = "record_digest_mismatch"
    CLASSIFICATION_MISMATCH = "classification_mismatch"
    FINDING_COVERAGE_MISMATCH = "finding_coverage_mismatch"
    FINDING_EVIDENCE_MISMATCH = "finding_evidence_mismatch"
    REDACTION_POLICY_MISMATCH = "redaction_policy_mismatch"
    QUARANTINE_POLICY_MISMATCH = "quarantine_policy_mismatch"
    TRAINING_INCLUSION_MISMATCH = "training_inclusion_mismatch"
    OUTPUT_SENSITIVE_REPRODUCTION = "output_sensitive_reproduction"
    OUTPUT_BATCH_MISMATCH = "output_batch_mismatch"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class SensitiveDataRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class SensitiveDataSecurityRejected(ValueError):
    def __init__(self, reason: SensitiveDataRejectReason, message: str):
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message


def reject(reason: SensitiveDataRejectReason, message: str) -> None:
    raise SensitiveDataSecurityRejected(reason, message)


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
class SensitiveFindingEvidence:
    finding_id: str
    kind: SensitiveKind
    detector_rule_id: str
    detector_rule_sha256: str
    token_fingerprint_sha256: str
    start_offset: int
    end_offset: int


@dataclass(frozen=True)
class SensitiveRecordEvidence:
    record_id: str
    surface: DataSurface
    content_sha256: str
    sanitized_content_sha256: str
    sensitivity: SensitivityClass
    findings: tuple[SensitiveFindingEvidence, ...]
    disposition: DataDisposition
    included: bool


@dataclass(frozen=True)
class SensitiveDataGovernanceManifest:
    schema_version: str
    governance_id: str
    created_at_epoch: int
    p9f_assessment_sha256: str
    evaluation_id: str
    checkpoint_id: str
    scanner_profile_sha256: str
    canary_registry_sha256: str
    records: tuple[SensitiveRecordEvidence, ...]
    included_training_record_ids: tuple[str, ...]
    output_record_ids: tuple[str, ...]
    output_batch_sha256: str
    network_operations: int = 0


@dataclass(frozen=True)
class SensitiveDataGovernancePolicy:
    policy_version: str
    expected_governance_id: str
    expected_manifest_sha256: str
    expected_p9f_assessment_sha256: str
    expected_evaluation_id: str
    expected_checkpoint_id: str
    expected_scanner_profile_sha256: str
    expected_canary_registry_sha256: str
    expected_record_order: tuple[str, ...]
    expected_surface_by_record_id: Mapping[str, DataSurface]
    expected_content_sha256_by_record_id: Mapping[str, str]
    expected_sanitized_content_sha256_by_record_id: Mapping[str, str]
    expected_sensitivity_by_record_id: Mapping[str, SensitivityClass]
    expected_disposition_by_record_id: Mapping[str, DataDisposition]
    expected_included_by_record_id: Mapping[str, bool]
    expected_finding_ids_by_record_id: Mapping[str, tuple[str, ...]]
    expected_finding_digest_by_id: Mapping[str, str]
    expected_included_training_record_ids: tuple[str, ...]
    expected_output_record_ids: tuple[str, ...]
    expected_output_batch_sha256: str
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class SensitiveDataGovernanceRequest:
    governance_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_evaluation_id: str
    declared_checkpoint_id: str
    declared_record_ids: tuple[str, ...]
    declared_included_training_record_ids: tuple[str, ...]
    declared_output_record_ids: tuple[str, ...]
    declared_upstream_bound: bool
    declared_input_governance_valid: bool
    declared_output_governance_valid: bool
    declared_canary_free: bool
    declared_sensitive_data_safe: bool


@dataclass(frozen=True)
class VerifiedSensitiveDataGovernanceAssessment:
    governance_id: str
    evaluation_id: str
    checkpoint_id: str
    decision: SensitiveDataDecision
    risks: tuple[SensitiveDataRisk, ...]
    p9f_assessment_sha256: str
    record_ids: tuple[str, ...]
    included_training_record_ids: tuple[str, ...]
    output_record_ids: tuple[str, ...]
    upstream_p9f_bound: bool
    input_governance_verified: bool
    output_governance_verified: bool
    canary_reproduction_clear: bool
    sensitive_data_policy_verified: bool
    caller_declared_safety_trusted: bool
    production_dlp_integrated: bool
    comprehensive_pii_detection_validated: bool
    legal_compliance_verified: bool
    differential_privacy_verified: bool
    memorization_absence_proven: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def sensitive_finding_digest(finding: SensitiveFindingEvidence) -> str:
    return digest_json(finding)


def sensitive_output_batch_digest(records: tuple[SensitiveRecordEvidence, ...]) -> str:
    outputs = tuple(
        (record.record_id, record.sanitized_content_sha256.casefold())
        for record in records
        if record.surface == DataSurface.MODEL_OUTPUT
    )
    return digest_json(outputs)


def sensitive_data_manifest_digest(manifest: SensitiveDataGovernanceManifest) -> str:
    return digest_json(manifest)
