from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Any, Mapping

P8L_EXIT_POLICY_VERSION = "phase8-integrated-agent-exit-policy-v1"
P8L_EXIT_SCHEMA_VERSION = "aegis-phase8-integrated-exit-manifest-v1"
P8L_ASSESSMENT_SCHEMA_VERSION = "aegis-phase8-integrated-exit-assessment-v1"
P8L_ASSESSMENT_MODE = "deterministic-evidence-lineage-and-verification-aware-phase8-exit-v1"
ZERO_SHA256 = "0" * 64

MILESTONE_ORDER = (
    "P8-A", "P8-B", "P8-C", "P8-D", "P8-E", "P8-F",
    "P8-G", "P8-H", "P8-I", "P8-J", "P8-K",
)

MILESTONE_DOMAINS = {
    "P8-A": "delegation-authority",
    "P8-B": "memory-context",
    "P8-C": "goal-plan-integrity",
    "P8-D": "tool-observation-integrity",
    "P8-E": "execution-budget",
    "P8-F": "human-approval-autonomy",
    "P8-G": "inter-agent-messaging",
    "P8-H": "state-concurrency",
    "P8-I": "artifact-workspace",
    "P8-J": "rollback-recovery",
    "P8-K": "incident-containment-forensics",
}

REQUIRED_SYNTHETIC_ASSUMPTIONS = (
    "deterministic-synthetic-fixtures",
    "single-process-local-evaluator",
    "no-production-agent-orchestrator",
    "no-production-secret-rotation",
    "no-production-siem-edr",
    "no-production-distributed-event-log",
    "no-trusted-distributed-clock",
    "no-cryptographic-attestation",
)

PRODUCTION_CLAIM_FIELDS = (
    "production_runtime_validated",
    "production_distributed_system_validated",
    "production_siem_edr_integrated",
    "production_secret_rotation_executed",
    "cryptographic_attestation_verified",
)


class VerificationStatus(str, Enum):
    LOCAL_FOCUSED_PASS = "LOCAL_FOCUSED_PASS"
    LOCAL_FULL_PASS = "LOCAL_FULL_PASS"
    REMOTE_CI_PASS = "REMOTE_CI_PASS"
    REMOTE_CI_BLOCKED = "REMOTE_CI_BLOCKED"
    REMOTE_CI_FAIL = "REMOTE_CI_FAIL"
    NOT_RUN = "NOT_RUN"


class Phase8ExitDecision(str, Enum):
    PASS = "PASS"
    PASS_WITH_EXTERNAL_CI_LIMITATION = "PASS_WITH_EXTERNAL_CI_LIMITATION"
    FAIL = "FAIL"


class ExitRisk(str, Enum):
    MILESTONE_COVERAGE_INVALID = "milestone_coverage_invalid"
    MILESTONE_ORDER_INVALID = "milestone_order_invalid"
    DOMAIN_BINDING_MISMATCH = "domain_binding_mismatch"
    LINEAGE_MISMATCH = "lineage_mismatch"
    EVIDENCE_CHAIN_BROKEN = "evidence_chain_broken"
    EVIDENCE_DIGEST_MISMATCH = "evidence_digest_mismatch"
    UPSTREAM_SAFETY_FAILED = "upstream_safety_failed"
    CALLER_DECLARED_SAFETY_TRUSTED = "caller_declared_safety_trusted"
    NETWORK_SIDE_EFFECT_REPORTED = "network_side_effect_reported"
    LOCAL_VERIFICATION_INCOMPLETE = "local_verification_incomplete"
    REMOTE_CI_INVALID = "remote_ci_invalid"
    REMOTE_CI_EXECUTION_FAILED = "remote_ci_execution_failed"
    SYNTHETIC_ASSUMPTION_MISSING = "synthetic_assumption_missing"
    UNSUPPORTED_PRODUCTION_CLAIM = "unsupported_production_claim"


class ExitRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_DECISION_MISMATCH = "declared_decision_mismatch"
    DECLARED_EVIDENCE_MISMATCH = "declared_evidence_mismatch"
    DECLARED_VERIFICATION_MISMATCH = "declared_verification_mismatch"


class Phase8ExitRejected(ValueError):
    def __init__(self, reason: ExitRejectReason, message: str):
        self.reason = reason
        super().__init__(f"{reason.value}: {message}")


@dataclass(frozen=True)
class MilestoneEvidence:
    milestone_id: str
    control_domain: str
    step_index: int
    execution_lineage_id: str
    manifest_sha256: str
    assessment_sha256: str
    predecessor_assessment_sha256: str
    input_state_sha256: str
    output_state_sha256: str
    assessment_schema_version: str
    assessment_mode: str
    safe: bool
    caller_declared_safety_trusted: bool
    network_operations: int


@dataclass(frozen=True)
class VerificationRecord:
    verification_id: str
    scope: str
    status: VerificationStatus
    evidence_sha256: str
    runner_started: bool
    steps_executed: int
    reason_code: str = ""


@dataclass(frozen=True)
class Phase8ClaimProfile:
    production_runtime_validated: bool = False
    production_distributed_system_validated: bool = False
    production_siem_edr_integrated: bool = False
    production_secret_rotation_executed: bool = False
    cryptographic_attestation_verified: bool = False


@dataclass(frozen=True)
class Phase8ExitManifest:
    manifest_id: str
    schema_version: str
    created_at_epoch: int
    execution_lineage_id: str
    milestone_evidence: tuple[MilestoneEvidence, ...]
    verification_records: tuple[VerificationRecord, ...]
    synthetic_assumptions: tuple[str, ...]
    claim_profile: Phase8ClaimProfile


@dataclass(frozen=True)
class Phase8ExitPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_execution_lineage_id: str
    expected_assessment_sha256_by_milestone: Mapping[str, str]
    expected_manifest_sha256_by_milestone: Mapping[str, str]
    expected_output_state_sha256_by_milestone: Mapping[str, str]
    expected_assessment_schema_by_milestone: Mapping[str, str]
    expected_assessment_mode_by_milestone: Mapping[str, str]
    required_local_verification_scopes: tuple[str, ...]
    allowed_external_ci_block_reasons: tuple[str, ...]
    max_manifest_age_seconds: int = 3600
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class Phase8ExitRequest:
    manifest_id: str
    manifest_sha256: str
    policy_version: str
    evaluated_at_epoch: int
    declared_exit_decision: Phase8ExitDecision
    declared_assessment_sha256_by_milestone: Mapping[str, str]
    declared_verification_status_by_id: Mapping[str, str]


@dataclass(frozen=True)
class Phase8ExitAssessment:
    manifest_id: str
    execution_lineage_id: str
    milestone_count: int
    local_verification_count: int
    remote_ci_status: str
    risks: tuple[ExitRisk, ...]
    decision: Phase8ExitDecision
    all_milestones_evidence_bound: bool
    upstream_safety_derived: bool
    caller_declared_safety_trusted: bool
    local_security_validation_passed: bool
    remote_ci_execution_verified: bool
    remote_ci_external_limitation: bool
    synthetic_assumptions_explicit: bool
    unsupported_production_claims_present: bool
    production_runtime_validated: bool
    production_distributed_system_validated: bool
    production_siem_edr_integrated: bool
    cryptographic_attestation_verified: bool
    network_operations: int
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {k: _jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    if isinstance(value, set):
        return sorted(_jsonable(v) for v in value)
    return value


def _digest_json(value: Any) -> str:
    payload = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_phase8_exit_manifest_bytes(manifest: Phase8ExitManifest) -> bytes:
    return json.dumps(_jsonable(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def phase8_exit_manifest_digest(manifest: Phase8ExitManifest) -> str:
    return hashlib.sha256(canonical_phase8_exit_manifest_bytes(manifest)).hexdigest()


def reject(reason: ExitRejectReason, message: str) -> None:
    raise Phase8ExitRejected(reason, message)
