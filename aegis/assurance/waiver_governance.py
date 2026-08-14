from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from .regression import (
    P6A_CORPUS_SCHEMA_VERSION,
    P6A_EVIDENCE_SCHEMA_VERSION,
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    CaseObservation,
    ReleaseAssuranceEvidence,
    case_definition_digest,
    corpus_digest,
    release_evidence_digest,
)


P6B_WAIVER_POLICY_VERSION = "security-invariant-waiver-governance-v1"
P6B_INVARIANT_REGISTRY_SCHEMA_VERSION = "aegis-security-invariant-registry-v1"
P6B_WAIVER_SCHEMA_VERSION = "aegis-security-waiver-v1"
P6B_GOVERNANCE_MODE = "deterministic-expiry-bound-waiver-governance-v1"


class WaiverGovernanceRejectReason(StrEnum):
    CORPUS_INVALID = "corpus_invalid"
    CORPUS_DIGEST_MISMATCH = "corpus_digest_mismatch"
    REGISTRY_INVALID = "registry_invalid"
    REGISTRY_DIGEST_MISMATCH = "registry_digest_mismatch"
    INVARIANT_DRIFT = "invariant_drift"
    INVARIANT_OWNER_MISMATCH = "invariant_owner_mismatch"
    CANDIDATE_EVIDENCE_INVALID = "candidate_evidence_invalid"
    CANDIDATE_IDENTITY_MISMATCH = "candidate_identity_mismatch"
    RUNNER_UNTRUSTED = "runner_untrusted"
    CASE_COVERAGE_MISMATCH = "case_coverage_mismatch"
    CASE_DEFINITION_MISMATCH = "case_definition_mismatch"
    WAIVER_INVALID = "waiver_invalid"
    WAIVER_DUPLICATE = "waiver_duplicate"
    WAIVER_SCOPE_MISMATCH = "waiver_scope_mismatch"
    WAIVER_EXPIRED = "waiver_expired"
    WAIVER_NOT_YET_VALID = "waiver_not_yet_valid"
    WAIVER_DURATION_EXCEEDED = "waiver_duration_exceeded"
    WAIVER_SEVERITY_DOWNGRADE = "waiver_severity_downgrade"
    WAIVER_NOT_PERMITTED = "waiver_not_permitted"
    APPROVER_UNTRUSTED = "approver_untrusted"
    OWNER_APPROVAL_MISMATCH = "owner_approval_mismatch"
    APPROVAL_INSUFFICIENT = "approval_insufficient"
    REGRESSION_UNWAIVED = "regression_unwaived"
    SAFE_TASK_REGRESSION = "safe_task_regression"


class WaiverGovernanceRejected(ValueError):
    def __init__(
        self,
        reason: WaiverGovernanceRejectReason,
        message: str,
        *,
        case_id: str | None = None,
        waiver_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.case_id = case_id
        self.waiver_id = waiver_id


@dataclass(frozen=True)
class InvariantRecord:
    case_id: str
    case_definition_sha256: str
    owner_id: str
    severity: AssuranceSeverity


@dataclass(frozen=True)
class InvariantRegistry:
    registry_id: str
    version: str
    corpus_sha256: str
    records: tuple[InvariantRecord, ...]
    schema_version: str = P6B_INVARIANT_REGISTRY_SCHEMA_VERSION


@dataclass(frozen=True)
class WaiverApproval:
    approver_id: str
    role: str
    approved_at_epoch: int


@dataclass(frozen=True)
class SecurityWaiver:
    waiver_id: str
    case_id: str
    case_definition_sha256: str
    owner_id: str
    severity: AssuranceSeverity
    candidate_release_id: str
    candidate_commit_sha: str
    candidate_package_version: str
    corpus_sha256: str
    candidate_evidence_sha256: str
    reason: str
    tracking_ref: str
    issued_at_epoch: int
    expires_at_epoch: int
    approvals: tuple[WaiverApproval, ...]
    schema_version: str = P6B_WAIVER_SCHEMA_VERSION


@dataclass(frozen=True)
class WaiverGovernanceRequest:
    candidate_release_id: str
    candidate_commit_sha: str
    candidate_package_version: str
    corpus_sha256: str
    candidate_evidence_sha256: str
    evaluated_at_epoch: int


@dataclass(frozen=True)
class WaiverGovernancePolicy:
    expected_corpus_sha256: str
    expected_registry_sha256: str
    expected_owner_by_case: Mapping[str, str]
    trusted_runner_ids: frozenset[str]
    trusted_approvers_by_role: Mapping[str, frozenset[str]]
    required_roles_by_severity: Mapping[AssuranceSeverity, frozenset[str]]
    max_waiver_seconds_by_severity: Mapping[AssuranceSeverity, int]
    waivable_severities: frozenset[AssuranceSeverity]


@dataclass(frozen=True)
class VerifiedWaiverGovernance:
    candidate_release_id: str
    candidate_commit_sha: str
    candidate_package_version: str
    corpus_sha256: str
    registry_sha256: str
    candidate_evidence_sha256: str
    regression_case_ids: tuple[str, ...]
    approved_waiver_ids: tuple[str, ...]
    approved_waived_case_ids: tuple[str, ...]
    waiver_count: int
    high_waiver_count: int
    medium_waiver_count: int
    low_waiver_count: int
    critical_waiver_count: int
    earliest_expiry_epoch: int | None
    governance_evidence_sha256: str
    invariant_definitions_verified: bool = True
    invariant_ownership_verified: bool = True
    exact_regression_scope_verified: bool = True
    expiry_verified: bool = True
    approval_roles_verified: bool = True
    severity_downgrade_prevented: bool = True
    critical_waivers_permitted: bool = False
    production_change_management: bool = False
    cryptographic_approval_attestation: bool = False
    external_ticket_verification: bool = False
    network_operations: int = 0
    policy_version: str = P6B_WAIVER_POLICY_VERSION
    governance_mode: str = P6B_GOVERNANCE_MODE


def _reject(
    reason: WaiverGovernanceRejectReason,
    message: str,
    *,
    case_id: str | None = None,
    waiver_id: str | None = None,
) -> None:
    raise WaiverGovernanceRejected(
        reason,
        message,
        case_id=case_id,
        waiver_id=waiver_id,
    )


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def canonical_invariant_registry_bytes(registry: InvariantRegistry) -> bytes:
    document = {
        "corpus_sha256": registry.corpus_sha256.casefold(),
        "records": [
            {
                "case_definition_sha256": record.case_definition_sha256.casefold(),
                "case_id": record.case_id,
                "owner_id": record.owner_id,
                "severity": record.severity.value
                if isinstance(record.severity, AssuranceSeverity)
                else str(record.severity),
            }
            for record in sorted(registry.records, key=lambda item: item.case_id)
        ],
        "registry_id": registry.registry_id,
        "schema_version": registry.schema_version,
        "version": registry.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def invariant_registry_digest(registry: InvariantRegistry) -> str:
    return hashlib.sha256(canonical_invariant_registry_bytes(registry)).hexdigest()


def canonical_waiver_bytes(waiver: SecurityWaiver) -> bytes:
    document = {
        "approvals": [
            {
                "approved_at_epoch": approval.approved_at_epoch,
                "approver_id": approval.approver_id,
                "role": approval.role,
            }
            for approval in sorted(
                waiver.approvals,
                key=lambda item: (item.role, item.approver_id, item.approved_at_epoch),
            )
        ],
        "candidate_commit_sha": waiver.candidate_commit_sha.casefold(),
        "candidate_evidence_sha256": waiver.candidate_evidence_sha256.casefold(),
        "candidate_package_version": waiver.candidate_package_version,
        "candidate_release_id": waiver.candidate_release_id,
        "case_definition_sha256": waiver.case_definition_sha256.casefold(),
        "case_id": waiver.case_id,
        "corpus_sha256": waiver.corpus_sha256.casefold(),
        "expires_at_epoch": waiver.expires_at_epoch,
        "issued_at_epoch": waiver.issued_at_epoch,
        "owner_id": waiver.owner_id,
        "reason": waiver.reason,
        "schema_version": waiver.schema_version,
        "severity": waiver.severity.value
        if isinstance(waiver.severity, AssuranceSeverity)
        else str(waiver.severity),
        "tracking_ref": waiver.tracking_ref,
        "waiver_id": waiver.waiver_id,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def waiver_digest(waiver: SecurityWaiver) -> str:
    return hashlib.sha256(canonical_waiver_bytes(waiver)).hexdigest()


def _validate_corpus(
    corpus: AssuranceCorpus,
    policy: WaiverGovernancePolicy,
) -> dict[str, AssuranceCase]:
    if (
        corpus.schema_version != P6A_CORPUS_SCHEMA_VERSION
        or not corpus.corpus_id
        or not corpus.version
        or not corpus.cases
    ):
        _reject(WaiverGovernanceRejectReason.CORPUS_INVALID, "assurance corpus metadata is invalid")

    case_map: dict[str, AssuranceCase] = {}
    for case in corpus.cases:
        if (
            not case.case_id
            or not case.boundary
            or not case.attack_class
            or not case.invariant
            or not isinstance(case.severity, AssuranceSeverity)
            or not isinstance(case.expectation, AssuranceExpectation)
        ):
            _reject(
                WaiverGovernanceRejectReason.CORPUS_INVALID,
                "assurance corpus contains an invalid case definition",
                case_id=case.case_id or None,
            )
        if case.case_id in case_map:
            _reject(
                WaiverGovernanceRejectReason.CORPUS_INVALID,
                "assurance corpus contains duplicate case IDs",
                case_id=case.case_id,
            )
        case_map[case.case_id] = case

    exact_corpus_sha256 = corpus_digest(corpus)
    if (
        not _is_sha256(policy.expected_corpus_sha256)
        or not hmac.compare_digest(
            exact_corpus_sha256,
            policy.expected_corpus_sha256.casefold(),
        )
    ):
        _reject(
            WaiverGovernanceRejectReason.CORPUS_DIGEST_MISMATCH,
            "assurance corpus does not match the waiver-policy pin",
        )
    return case_map


def _validate_registry(
    *,
    registry: InvariantRegistry,
    exact_corpus_sha256: str,
    case_map: dict[str, AssuranceCase],
    policy: WaiverGovernancePolicy,
) -> dict[str, InvariantRecord]:
    if (
        registry.schema_version != P6B_INVARIANT_REGISTRY_SCHEMA_VERSION
        or not registry.registry_id
        or not registry.version
        or not _is_sha256(registry.corpus_sha256)
        or not registry.records
    ):
        _reject(
            WaiverGovernanceRejectReason.REGISTRY_INVALID,
            "security invariant registry metadata is invalid",
        )
    if not hmac.compare_digest(registry.corpus_sha256.casefold(), exact_corpus_sha256):
        _reject(
            WaiverGovernanceRejectReason.INVARIANT_DRIFT,
            "security invariant registry is not bound to the exact assurance corpus",
        )

    records: dict[str, InvariantRecord] = {}
    for record in registry.records:
        if (
            not record.case_id
            or not record.owner_id
            or not _is_sha256(record.case_definition_sha256)
            or not isinstance(record.severity, AssuranceSeverity)
        ):
            _reject(
                WaiverGovernanceRejectReason.REGISTRY_INVALID,
                "security invariant registry contains an invalid record",
                case_id=record.case_id or None,
            )
        if record.case_id in records:
            _reject(
                WaiverGovernanceRejectReason.REGISTRY_INVALID,
                "security invariant registry contains duplicate case IDs",
                case_id=record.case_id,
            )
        records[record.case_id] = record

    if set(records) != set(case_map):
        _reject(
            WaiverGovernanceRejectReason.INVARIANT_DRIFT,
            "security invariant registry must exactly cover the assurance corpus",
        )
    if set(policy.expected_owner_by_case) != set(case_map):
        _reject(
            WaiverGovernanceRejectReason.REGISTRY_INVALID,
            "waiver policy must pin one invariant owner for every corpus case",
        )

    for case_id, case in sorted(case_map.items()):
        record = records[case_id]
        if not hmac.compare_digest(
            record.case_definition_sha256.casefold(),
            case_definition_digest(case),
        ) or record.severity != case.severity:
            _reject(
                WaiverGovernanceRejectReason.INVARIANT_DRIFT,
                "registry definition or severity drifted from the immutable corpus case",
                case_id=case_id,
            )
        expected_owner = policy.expected_owner_by_case[case_id]
        if not expected_owner or record.owner_id != expected_owner:
            _reject(
                WaiverGovernanceRejectReason.INVARIANT_OWNER_MISMATCH,
                "security invariant owner does not match the policy-pinned owner",
                case_id=case_id,
            )

    actual_registry_sha256 = invariant_registry_digest(registry)
    if (
        not _is_sha256(policy.expected_registry_sha256)
        or not hmac.compare_digest(
            actual_registry_sha256,
            policy.expected_registry_sha256.casefold(),
        )
    ):
        _reject(
            WaiverGovernanceRejectReason.REGISTRY_DIGEST_MISMATCH,
            "security invariant registry does not match the policy-pinned digest",
        )
    return records


def _validate_candidate_evidence(
    *,
    evidence: ReleaseAssuranceEvidence,
    exact_corpus_sha256: str,
    case_map: dict[str, AssuranceCase],
    policy: WaiverGovernancePolicy,
) -> dict[str, CaseObservation]:
    if (
        evidence.schema_version != P6A_EVIDENCE_SCHEMA_VERSION
        or not evidence.release_id
        or not evidence.package_version
        or not _is_sha256(evidence.commit_sha)
        or not _is_sha256(evidence.corpus_sha256)
    ):
        _reject(
            WaiverGovernanceRejectReason.CANDIDATE_EVIDENCE_INVALID,
            "candidate assurance evidence metadata is invalid",
        )
    if not hmac.compare_digest(evidence.corpus_sha256.casefold(), exact_corpus_sha256):
        _reject(
            WaiverGovernanceRejectReason.CANDIDATE_IDENTITY_MISMATCH,
            "candidate assurance evidence does not bind to the exact corpus",
        )
    if evidence.runner_id not in policy.trusted_runner_ids:
        _reject(
            WaiverGovernanceRejectReason.RUNNER_UNTRUSTED,
            "candidate assurance evidence came from an untrusted deterministic runner ID",
        )

    observations: dict[str, CaseObservation] = {}
    for result in evidence.results:
        if result.case_id in observations:
            _reject(
                WaiverGovernanceRejectReason.CASE_COVERAGE_MISMATCH,
                "candidate assurance evidence contains a duplicate case result",
                case_id=result.case_id,
            )
        if result.case_id not in case_map:
            _reject(
                WaiverGovernanceRejectReason.CASE_COVERAGE_MISMATCH,
                "candidate assurance evidence contains an unknown case result",
                case_id=result.case_id,
            )
        if not isinstance(result.observed_outcome, AssuranceExpectation):
            _reject(
                WaiverGovernanceRejectReason.CANDIDATE_EVIDENCE_INVALID,
                "candidate case result has an invalid observed outcome",
                case_id=result.case_id,
            )
        expected_definition_sha256 = case_definition_digest(case_map[result.case_id])
        if (
            not _is_sha256(result.case_definition_sha256)
            or not hmac.compare_digest(
                result.case_definition_sha256.casefold(),
                expected_definition_sha256,
            )
        ):
            _reject(
                WaiverGovernanceRejectReason.CASE_DEFINITION_MISMATCH,
                "candidate case result does not bind to the immutable case definition",
                case_id=result.case_id,
            )
        observations[result.case_id] = result

    if set(observations) != set(case_map):
        _reject(
            WaiverGovernanceRejectReason.CASE_COVERAGE_MISMATCH,
            "candidate assurance evidence must exactly cover the assurance corpus",
        )
    return observations


def _validate_policy(policy: WaiverGovernancePolicy) -> None:
    if not policy.trusted_runner_ids or not policy.waivable_severities:
        _reject(WaiverGovernanceRejectReason.REGISTRY_INVALID, "waiver policy trust sets are empty")
    for severity in AssuranceSeverity:
        if severity not in policy.required_roles_by_severity:
            _reject(
                WaiverGovernanceRejectReason.REGISTRY_INVALID,
                "waiver policy must define approval roles for every severity",
            )
        if severity not in policy.max_waiver_seconds_by_severity:
            _reject(
                WaiverGovernanceRejectReason.REGISTRY_INVALID,
                "waiver policy must define maximum duration for every severity",
            )
        if policy.max_waiver_seconds_by_severity[severity] <= 0:
            _reject(
                WaiverGovernanceRejectReason.REGISTRY_INVALID,
                "waiver policy duration limits must be positive",
            )
    for role, approvers in policy.trusted_approvers_by_role.items():
        if not role or not approvers:
            _reject(
                WaiverGovernanceRejectReason.REGISTRY_INVALID,
                "trusted waiver-approver role mappings may not be empty",
            )


def _validate_waiver(
    *,
    waiver: SecurityWaiver,
    case: AssuranceCase,
    record: InvariantRecord,
    request: WaiverGovernanceRequest,
    policy: WaiverGovernancePolicy,
) -> None:
    if (
        waiver.schema_version != P6B_WAIVER_SCHEMA_VERSION
        or not waiver.waiver_id
        or not waiver.case_id
        or not waiver.owner_id
        or not waiver.reason.strip()
        or not waiver.tracking_ref.strip()
        or not _is_sha256(waiver.case_definition_sha256)
        or not _is_sha256(waiver.candidate_commit_sha)
        or not _is_sha256(waiver.corpus_sha256)
        or not _is_sha256(waiver.candidate_evidence_sha256)
        or not isinstance(waiver.severity, AssuranceSeverity)
        or waiver.issued_at_epoch <= 0
        or waiver.expires_at_epoch <= 0
    ):
        _reject(
            WaiverGovernanceRejectReason.WAIVER_INVALID,
            "security waiver metadata is invalid",
            case_id=waiver.case_id or None,
            waiver_id=waiver.waiver_id or None,
        )

    if waiver.case_id != case.case_id:
        _reject(
            WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH,
            "security waiver targets the wrong regression case",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )
    if not hmac.compare_digest(
        waiver.case_definition_sha256.casefold(),
        case_definition_digest(case),
    ):
        _reject(
            WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH,
            "security waiver does not bind to the immutable case definition",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )
    if waiver.owner_id != record.owner_id:
        _reject(
            WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH,
            "security waiver does not bind to the policy-pinned invariant owner",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )
    if waiver.severity != case.severity:
        _reject(
            WaiverGovernanceRejectReason.WAIVER_SEVERITY_DOWNGRADE,
            "security waiver severity must exactly match the corpus severity",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )
    if waiver.severity not in policy.waivable_severities:
        _reject(
            WaiverGovernanceRejectReason.WAIVER_NOT_PERMITTED,
            "policy does not permit waivers for this regression severity",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )

    if (
        waiver.candidate_release_id != request.candidate_release_id
        or waiver.candidate_commit_sha.casefold() != request.candidate_commit_sha.casefold()
        or waiver.candidate_package_version != request.candidate_package_version
        or waiver.corpus_sha256.casefold() != request.corpus_sha256.casefold()
        or waiver.candidate_evidence_sha256.casefold()
        != request.candidate_evidence_sha256.casefold()
    ):
        _reject(
            WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH,
            "security waiver does not bind to the exact candidate release evidence",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )

    if waiver.issued_at_epoch > request.evaluated_at_epoch:
        _reject(
            WaiverGovernanceRejectReason.WAIVER_NOT_YET_VALID,
            "security waiver was issued after the deterministic evaluation time",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )
    if waiver.expires_at_epoch <= request.evaluated_at_epoch:
        _reject(
            WaiverGovernanceRejectReason.WAIVER_EXPIRED,
            "security waiver has expired",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )
    duration = waiver.expires_at_epoch - waiver.issued_at_epoch
    max_duration = policy.max_waiver_seconds_by_severity[waiver.severity]
    if duration <= 0 or duration > max_duration:
        _reject(
            WaiverGovernanceRejectReason.WAIVER_DURATION_EXCEEDED,
            "security waiver exceeds the severity-specific maximum duration",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )

    approvals_by_role: dict[str, set[str]] = {}
    seen_approvals: set[tuple[str, str]] = set()
    for approval in waiver.approvals:
        if (
            not approval.approver_id
            or not approval.role
            or approval.approved_at_epoch <= 0
            or approval.approved_at_epoch > waiver.issued_at_epoch
        ):
            _reject(
                WaiverGovernanceRejectReason.WAIVER_INVALID,
                "security waiver contains invalid or post-issuance approval evidence",
                case_id=case.case_id,
                waiver_id=waiver.waiver_id,
            )
        key = (approval.role, approval.approver_id)
        if key in seen_approvals:
            _reject(
                WaiverGovernanceRejectReason.WAIVER_INVALID,
                "security waiver contains duplicate approval evidence",
                case_id=case.case_id,
                waiver_id=waiver.waiver_id,
            )
        seen_approvals.add(key)
        trusted_for_role = policy.trusted_approvers_by_role.get(approval.role)
        if not trusted_for_role or approval.approver_id not in trusted_for_role:
            _reject(
                WaiverGovernanceRejectReason.APPROVER_UNTRUSTED,
                "security waiver approval came from an untrusted approver for the declared role",
                case_id=case.case_id,
                waiver_id=waiver.waiver_id,
            )
        if approval.role == "invariant_owner" and approval.approver_id != record.owner_id:
            _reject(
                WaiverGovernanceRejectReason.OWNER_APPROVAL_MISMATCH,
                "invariant-owner approval must come from the exact policy-pinned owner",
                case_id=case.case_id,
                waiver_id=waiver.waiver_id,
            )
        approvals_by_role.setdefault(approval.role, set()).add(approval.approver_id)

    required_roles = policy.required_roles_by_severity[waiver.severity]
    missing_roles = sorted(role for role in required_roles if role not in approvals_by_role)
    if missing_roles:
        _reject(
            WaiverGovernanceRejectReason.APPROVAL_INSUFFICIENT,
            "security waiver is missing one or more severity-required approval roles",
            case_id=case.case_id,
            waiver_id=waiver.waiver_id,
        )


class SecurityInvariantWaiverGovernanceGate:
    """Govern explicit, scoped, expiry-bound exceptions to P6-A regression evidence.

    This synthetic lab validates deterministic governance evidence. It does not contact
    ticketing systems, execute production change management, or cryptographically attest
    human approvals.
    """

    def __init__(
        self,
        *,
        corpus: AssuranceCorpus,
        registry: InvariantRegistry,
        policy: WaiverGovernancePolicy,
    ) -> None:
        self._corpus = corpus
        self._registry = registry
        self._policy = policy

    def evaluate(
        self,
        *,
        request: WaiverGovernanceRequest,
        candidate: ReleaseAssuranceEvidence,
        waivers: tuple[SecurityWaiver, ...],
    ) -> VerifiedWaiverGovernance:
        _validate_policy(self._policy)
        case_map = _validate_corpus(self._corpus, self._policy)
        exact_corpus_sha256 = corpus_digest(self._corpus)
        records = _validate_registry(
            registry=self._registry,
            exact_corpus_sha256=exact_corpus_sha256,
            case_map=case_map,
            policy=self._policy,
        )
        observations = _validate_candidate_evidence(
            evidence=candidate,
            exact_corpus_sha256=exact_corpus_sha256,
            case_map=case_map,
            policy=self._policy,
        )
        exact_candidate_evidence_sha256 = release_evidence_digest(candidate)

        if (
            not request.candidate_release_id
            or not request.candidate_package_version
            or not _is_sha256(request.candidate_commit_sha)
            or not _is_sha256(request.corpus_sha256)
            or not _is_sha256(request.candidate_evidence_sha256)
            or request.evaluated_at_epoch <= 0
            or request.candidate_release_id != candidate.release_id
            or request.candidate_commit_sha.casefold() != candidate.commit_sha.casefold()
            or request.candidate_package_version != candidate.package_version
            or not hmac.compare_digest(request.corpus_sha256.casefold(), exact_corpus_sha256)
            or not hmac.compare_digest(
                request.candidate_evidence_sha256.casefold(),
                exact_candidate_evidence_sha256,
            )
        ):
            _reject(
                WaiverGovernanceRejectReason.CANDIDATE_IDENTITY_MISMATCH,
                "waiver-governance request does not bind to the exact candidate evidence",
            )

        mismatches = [
            case
            for case_id, case in sorted(case_map.items())
            if observations[case_id].observed_outcome != case.expectation
        ]
        safe_task_regressions = [
            case for case in mismatches if case.expectation == AssuranceExpectation.ALLOW
        ]
        if safe_task_regressions:
            _reject(
                WaiverGovernanceRejectReason.SAFE_TASK_REGRESSION,
                "benign safe-task regressions are not convertible into security waivers",
                case_id=safe_task_regressions[0].case_id,
            )
        security_regressions = [
            case for case in mismatches if case.expectation == AssuranceExpectation.BLOCK
        ]
        regression_case_ids = tuple(case.case_id for case in security_regressions)
        regression_set = set(regression_case_ids)

        waiver_by_case: dict[str, SecurityWaiver] = {}
        seen_waiver_ids: set[str] = set()
        for waiver in waivers:
            if waiver.waiver_id in seen_waiver_ids or waiver.case_id in waiver_by_case:
                _reject(
                    WaiverGovernanceRejectReason.WAIVER_DUPLICATE,
                    "each security regression may have at most one unique waiver",
                    case_id=waiver.case_id,
                    waiver_id=waiver.waiver_id,
                )
            seen_waiver_ids.add(waiver.waiver_id)
            waiver_by_case[waiver.case_id] = waiver

        if set(waiver_by_case) - regression_set:
            extra_case = sorted(set(waiver_by_case) - regression_set)[0]
            _reject(
                WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH,
                "security waivers may only target actual candidate security regressions",
                case_id=extra_case,
                waiver_id=waiver_by_case[extra_case].waiver_id,
            )

        missing_waivers = sorted(regression_set - set(waiver_by_case))
        if missing_waivers:
            _reject(
                WaiverGovernanceRejectReason.REGRESSION_UNWAIVED,
                "candidate contains an unwaived security regression",
                case_id=missing_waivers[0],
            )

        approved: list[SecurityWaiver] = []
        for case in security_regressions:
            waiver = waiver_by_case[case.case_id]
            _validate_waiver(
                waiver=waiver,
                case=case,
                record=records[case.case_id],
                request=request,
                policy=self._policy,
            )
            approved.append(waiver)

        registry_sha256 = invariant_registry_digest(self._registry)
        governance_document = {
            "candidate_evidence_sha256": exact_candidate_evidence_sha256,
            "corpus_sha256": exact_corpus_sha256,
            "policy_version": P6B_WAIVER_POLICY_VERSION,
            "registry_sha256": registry_sha256,
            "request": asdict(request),
            "waiver_sha256s": [waiver_digest(item) for item in sorted(approved, key=lambda item: item.waiver_id)],
        }
        governance_evidence_sha256 = hashlib.sha256(
            json.dumps(governance_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        expiries = [waiver.expires_at_epoch for waiver in approved]
        return VerifiedWaiverGovernance(
            candidate_release_id=candidate.release_id,
            candidate_commit_sha=candidate.commit_sha.casefold(),
            candidate_package_version=candidate.package_version,
            corpus_sha256=exact_corpus_sha256,
            registry_sha256=registry_sha256,
            candidate_evidence_sha256=exact_candidate_evidence_sha256,
            regression_case_ids=regression_case_ids,
            approved_waiver_ids=tuple(sorted(waiver.waiver_id for waiver in approved)),
            approved_waived_case_ids=tuple(sorted(waiver.case_id for waiver in approved)),
            waiver_count=len(approved),
            high_waiver_count=sum(1 for waiver in approved if waiver.severity == AssuranceSeverity.HIGH),
            medium_waiver_count=sum(1 for waiver in approved if waiver.severity == AssuranceSeverity.MEDIUM),
            low_waiver_count=sum(1 for waiver in approved if waiver.severity == AssuranceSeverity.LOW),
            critical_waiver_count=sum(1 for waiver in approved if waiver.severity == AssuranceSeverity.CRITICAL),
            earliest_expiry_epoch=min(expiries) if expiries else None,
            governance_evidence_sha256=governance_evidence_sha256,
        )
