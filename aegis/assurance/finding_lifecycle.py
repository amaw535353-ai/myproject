from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import StrEnum

from .regression import (
    P6A_CORPUS_SCHEMA_VERSION,
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    CaseObservation,
    case_definition_digest,
    corpus_digest,
)
from .waiver_governance import (
    P6B_INVARIANT_REGISTRY_SCHEMA_VERSION,
    InvariantRecord,
    InvariantRegistry,
    invariant_registry_digest,
)


P6E_FINDING_POLICY_VERSION = "adversarial-finding-lifecycle-closure-v1"
P6E_FINDING_SCHEMA_VERSION = "aegis-adversarial-finding-v1"
P6E_RETEST_SCHEMA_VERSION = "aegis-adversarial-finding-retest-v1"
P6E_LIFECYCLE_MODE = "deterministic-release-bound-finding-closure-v1"


class FindingState(StrEnum):
    OPEN = "open"
    FIX_IN_PROGRESS = "fix_in_progress"
    READY_FOR_RETEST = "ready_for_retest"
    CLOSED = "closed"


class FindingLifecycleRejectReason(StrEnum):
    CORPUS_INVALID = "corpus_invalid"
    CORPUS_DIGEST_MISMATCH = "corpus_digest_mismatch"
    REGISTRY_INVALID = "registry_invalid"
    REGISTRY_DIGEST_MISMATCH = "registry_digest_mismatch"
    INVARIANT_DRIFT = "invariant_drift"
    FINDING_INVALID = "finding_invalid"
    FINDING_IDENTITY_MISMATCH = "finding_identity_mismatch"
    FINDING_OWNER_UNTRUSTED = "finding_owner_untrusted"
    FINDING_SCOPE_MISMATCH = "finding_scope_mismatch"
    INVARIANT_OWNER_BINDING_MISMATCH = "invariant_owner_binding_mismatch"
    FINDING_SEVERITY_DOWNGRADE = "finding_severity_downgrade"
    FINDING_VERSION_INVALID = "finding_version_invalid"
    TRANSITION_INVALID = "transition_invalid"
    TIMESTAMP_INVALID = "timestamp_invalid"
    TARGET_IDENTITY_INVALID = "target_identity_invalid"
    REQUEST_INVALID = "request_invalid"
    RETEST_REQUIRED = "retest_required"
    RETEST_UNEXPECTED = "retest_unexpected"
    RETEST_INVALID = "retest_invalid"
    RETEST_RUNNER_UNTRUSTED = "retest_runner_untrusted"
    RETEST_IDENTITY_MISMATCH = "retest_identity_mismatch"
    RETEST_CASE_COVERAGE_MISMATCH = "retest_case_coverage_mismatch"
    RETEST_CASE_DEFINITION_MISMATCH = "retest_case_definition_mismatch"
    RETEST_FAILED = "retest_failed"
    RETEST_STALE = "retest_stale"
    RETEST_FUTURE = "retest_future"
    RETEST_DIGEST_MISMATCH = "retest_digest_mismatch"


class FindingLifecycleRejected(ValueError):
    def __init__(
        self,
        reason: FindingLifecycleRejectReason,
        message: str,
        *,
        finding_id: str | None = None,
        case_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.finding_id = finding_id
        self.case_id = case_id


@dataclass(frozen=True)
class AdversarialFinding:
    finding_id: str
    version: int
    title: str
    severity: AssuranceSeverity
    owner_id: str
    affected_case_ids: tuple[str, ...]
    affected_boundaries: tuple[str, ...]
    invariant_owner_ids: tuple[str, ...]
    discovered_release_id: str
    discovered_commit_sha: str
    discovered_package_version: str
    state: FindingState
    tracking_ref: str
    opened_at_epoch: int
    updated_at_epoch: int
    target_release_id: str = ""
    target_commit_sha: str = ""
    target_package_version: str = ""
    closure_retest_sha256: str = ""
    schema_version: str = P6E_FINDING_SCHEMA_VERSION


@dataclass(frozen=True)
class FindingRetestEvidence:
    finding_id: str
    ready_record_sha256: str
    release_id: str
    commit_sha: str
    package_version: str
    corpus_sha256: str
    runner_id: str
    executed_at_epoch: int
    results: tuple[CaseObservation, ...]
    schema_version: str = P6E_RETEST_SCHEMA_VERSION


@dataclass(frozen=True)
class FindingLifecycleRequest:
    finding_id: str
    expected_previous_record_sha256: str
    proposed_record_sha256: str
    evaluated_at_epoch: int


@dataclass(frozen=True)
class FindingLifecyclePolicy:
    expected_corpus_sha256: str
    expected_invariant_registry_sha256: str
    trusted_finding_owner_ids: frozenset[str]
    trusted_retest_runner_ids: frozenset[str]
    max_retest_age_seconds: int


@dataclass(frozen=True)
class VerifiedFindingTransition:
    finding_id: str
    previous_version: int
    current_version: int
    previous_state: FindingState
    current_state: FindingState
    severity: AssuranceSeverity
    owner_id: str
    affected_case_ids: tuple[str, ...]
    affected_boundaries: tuple[str, ...]
    invariant_owner_ids: tuple[str, ...]
    previous_record_sha256: str
    current_record_sha256: str
    corpus_sha256: str
    invariant_registry_sha256: str
    retest_evidence_sha256: str | None
    transition_evidence_sha256: str
    closure_verified: bool
    linked_case_definitions_verified: bool = True
    invariant_owner_binding_verified: bool = True
    severity_preserved: bool = True
    exact_release_target_verified: bool = True
    exact_retest_coverage_verified: bool = True
    caller_declared_closed_trusted: bool = False
    production_ticket_integration: bool = False
    production_patch_deployment: bool = False
    cryptographic_human_approval: bool = False
    exhaustive_finding_discovery: bool = False
    rollback_resistant_finding_store: bool = False
    network_operations: int = 0
    policy_version: str = P6E_FINDING_POLICY_VERSION
    lifecycle_mode: str = P6E_LIFECYCLE_MODE


_ALLOWED_TRANSITIONS = {
    FindingState.OPEN: frozenset({FindingState.FIX_IN_PROGRESS}),
    FindingState.FIX_IN_PROGRESS: frozenset({FindingState.READY_FOR_RETEST}),
    FindingState.READY_FOR_RETEST: frozenset({FindingState.CLOSED}),
    FindingState.CLOSED: frozenset(),
}


_SEVERITY_RANK = {
    AssuranceSeverity.LOW: 1,
    AssuranceSeverity.MEDIUM: 2,
    AssuranceSeverity.HIGH: 3,
    AssuranceSeverity.CRITICAL: 4,
}


def _reject(
    reason: FindingLifecycleRejectReason,
    message: str,
    *,
    finding_id: str | None = None,
    case_id: str | None = None,
) -> None:
    raise FindingLifecycleRejected(
        reason,
        message,
        finding_id=finding_id,
        case_id=case_id,
    )


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _finding_document(finding: AdversarialFinding) -> dict[str, object]:
    return {
        "affected_boundaries": sorted(finding.affected_boundaries),
        "affected_case_ids": sorted(finding.affected_case_ids),
        "closure_retest_sha256": finding.closure_retest_sha256.casefold(),
        "discovered_commit_sha": finding.discovered_commit_sha.casefold(),
        "discovered_package_version": finding.discovered_package_version,
        "discovered_release_id": finding.discovered_release_id,
        "finding_id": finding.finding_id,
        "invariant_owner_ids": sorted(finding.invariant_owner_ids),
        "opened_at_epoch": finding.opened_at_epoch,
        "owner_id": finding.owner_id,
        "schema_version": finding.schema_version,
        "severity": finding.severity.value
        if isinstance(finding.severity, AssuranceSeverity)
        else str(finding.severity),
        "state": finding.state.value
        if isinstance(finding.state, FindingState)
        else str(finding.state),
        "target_commit_sha": finding.target_commit_sha.casefold(),
        "target_package_version": finding.target_package_version,
        "target_release_id": finding.target_release_id,
        "title": finding.title,
        "tracking_ref": finding.tracking_ref,
        "updated_at_epoch": finding.updated_at_epoch,
        "version": finding.version,
    }


def canonical_finding_bytes(finding: AdversarialFinding) -> bytes:
    return json.dumps(
        _finding_document(finding),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def finding_digest(finding: AdversarialFinding) -> str:
    return hashlib.sha256(canonical_finding_bytes(finding)).hexdigest()


def canonical_retest_bytes(retest: FindingRetestEvidence) -> bytes:
    document = {
        "commit_sha": retest.commit_sha.casefold(),
        "corpus_sha256": retest.corpus_sha256.casefold(),
        "executed_at_epoch": retest.executed_at_epoch,
        "finding_id": retest.finding_id,
        "package_version": retest.package_version,
        "ready_record_sha256": retest.ready_record_sha256.casefold(),
        "release_id": retest.release_id,
        "results": [
            {
                "case_definition_sha256": item.case_definition_sha256.casefold(),
                "case_id": item.case_id,
                "observed_outcome": item.observed_outcome.value
                if isinstance(item.observed_outcome, AssuranceExpectation)
                else str(item.observed_outcome),
            }
            for item in sorted(retest.results, key=lambda result: result.case_id)
        ],
        "runner_id": retest.runner_id,
        "schema_version": retest.schema_version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def retest_digest(retest: FindingRetestEvidence) -> str:
    return hashlib.sha256(canonical_retest_bytes(retest)).hexdigest()


def _validate_corpus(
    corpus: AssuranceCorpus,
    policy: FindingLifecyclePolicy,
) -> tuple[dict[str, AssuranceCase], str]:
    if (
        corpus.schema_version != P6A_CORPUS_SCHEMA_VERSION
        or not corpus.corpus_id
        or not corpus.version
        or not corpus.cases
    ):
        _reject(FindingLifecycleRejectReason.CORPUS_INVALID, "assurance corpus metadata is invalid")
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
                FindingLifecycleRejectReason.CORPUS_INVALID,
                "assurance corpus contains an invalid case",
                case_id=case.case_id or None,
            )
        if case.case_id in case_map:
            _reject(
                FindingLifecycleRejectReason.CORPUS_INVALID,
                "assurance corpus contains duplicate case IDs",
                case_id=case.case_id,
            )
        case_map[case.case_id] = case
    exact_sha = corpus_digest(corpus)
    if (
        not _is_sha256(policy.expected_corpus_sha256)
        or not hmac.compare_digest(exact_sha, policy.expected_corpus_sha256.casefold())
    ):
        _reject(
            FindingLifecycleRejectReason.CORPUS_DIGEST_MISMATCH,
            "assurance corpus does not match the policy-pinned digest",
        )
    return case_map, exact_sha


def _validate_registry(
    registry: InvariantRegistry,
    *,
    case_map: dict[str, AssuranceCase],
    corpus_sha256: str,
    policy: FindingLifecyclePolicy,
) -> tuple[dict[str, InvariantRecord], str]:
    if (
        registry.schema_version != P6B_INVARIANT_REGISTRY_SCHEMA_VERSION
        or not registry.registry_id
        or not registry.version
        or not _is_sha256(registry.corpus_sha256)
        or not registry.records
    ):
        _reject(
            FindingLifecycleRejectReason.REGISTRY_INVALID,
            "invariant registry metadata is invalid",
        )
    if not hmac.compare_digest(registry.corpus_sha256.casefold(), corpus_sha256):
        _reject(
            FindingLifecycleRejectReason.INVARIANT_DRIFT,
            "invariant registry is bound to a different assurance corpus",
        )
    registry_sha = invariant_registry_digest(registry)
    if (
        not _is_sha256(policy.expected_invariant_registry_sha256)
        or not hmac.compare_digest(
            registry_sha,
            policy.expected_invariant_registry_sha256.casefold(),
        )
    ):
        _reject(
            FindingLifecycleRejectReason.REGISTRY_DIGEST_MISMATCH,
            "invariant registry does not match the policy-pinned digest",
        )

    records: dict[str, InvariantRecord] = {}
    for record in registry.records:
        if (
            not record.case_id
            or not _is_sha256(record.case_definition_sha256)
            or not record.owner_id
            or not isinstance(record.severity, AssuranceSeverity)
        ):
            _reject(
                FindingLifecycleRejectReason.REGISTRY_INVALID,
                "invariant registry contains an invalid record",
                case_id=record.case_id or None,
            )
        if record.case_id in records:
            _reject(
                FindingLifecycleRejectReason.REGISTRY_INVALID,
                "invariant registry contains duplicate case IDs",
                case_id=record.case_id,
            )
        case = case_map.get(record.case_id)
        if case is None:
            _reject(
                FindingLifecycleRejectReason.INVARIANT_DRIFT,
                "invariant registry references a case outside the assurance corpus",
                case_id=record.case_id,
            )
        if (
            not hmac.compare_digest(
                record.case_definition_sha256.casefold(),
                case_definition_digest(case),
            )
            or record.severity != case.severity
        ):
            _reject(
                FindingLifecycleRejectReason.INVARIANT_DRIFT,
                "invariant registry definition or severity drifted from the assurance corpus",
                case_id=record.case_id,
            )
        records[record.case_id] = record
    if set(records) != set(case_map):
        _reject(
            FindingLifecycleRejectReason.INVARIANT_DRIFT,
            "invariant registry must have exact one-to-one assurance-case coverage",
        )
    return records, registry_sha


def _validate_finding(
    finding: AdversarialFinding,
    *,
    case_map: dict[str, AssuranceCase],
    registry_map: dict[str, InvariantRecord],
    trusted_owner_ids: frozenset[str],
) -> None:
    if (
        finding.schema_version != P6E_FINDING_SCHEMA_VERSION
        or not finding.finding_id
        or finding.version <= 0
        or not finding.title
        or not isinstance(finding.severity, AssuranceSeverity)
        or not finding.owner_id
        or not finding.affected_case_ids
        or not finding.affected_boundaries
        or not finding.invariant_owner_ids
        or not finding.discovered_release_id
        or not _is_sha256(finding.discovered_commit_sha)
        or not finding.discovered_package_version
        or not isinstance(finding.state, FindingState)
        or not finding.tracking_ref
        or finding.opened_at_epoch <= 0
        or finding.updated_at_epoch < finding.opened_at_epoch
    ):
        _reject(
            FindingLifecycleRejectReason.FINDING_INVALID,
            "finding metadata is invalid",
            finding_id=finding.finding_id or None,
        )
    if finding.owner_id not in trusted_owner_ids:
        _reject(
            FindingLifecycleRejectReason.FINDING_OWNER_UNTRUSTED,
            "finding owner is not trusted by lifecycle policy",
            finding_id=finding.finding_id,
        )
    if (
        len(set(finding.affected_case_ids)) != len(finding.affected_case_ids)
        or len(set(finding.affected_boundaries)) != len(finding.affected_boundaries)
        or len(set(finding.invariant_owner_ids)) != len(finding.invariant_owner_ids)
    ):
        _reject(
            FindingLifecycleRejectReason.FINDING_SCOPE_MISMATCH,
            "finding scope contains duplicate case, boundary, or invariant-owner identifiers",
            finding_id=finding.finding_id,
        )

    linked_cases: list[AssuranceCase] = []
    for case_id in finding.affected_case_ids:
        case = case_map.get(case_id)
        if case is None:
            _reject(
                FindingLifecycleRejectReason.FINDING_SCOPE_MISMATCH,
                "finding references an unknown assurance case",
                finding_id=finding.finding_id,
                case_id=case_id,
            )
        if case.expectation != AssuranceExpectation.BLOCK:
            _reject(
                FindingLifecycleRejectReason.FINDING_SCOPE_MISMATCH,
                "adversarial findings may only link to attack-blocking assurance cases",
                finding_id=finding.finding_id,
                case_id=case_id,
            )
        linked_cases.append(case)

    expected_boundaries = tuple(sorted({case.boundary for case in linked_cases}))
    if tuple(sorted(finding.affected_boundaries)) != expected_boundaries:
        _reject(
            FindingLifecycleRejectReason.FINDING_SCOPE_MISMATCH,
            "finding boundary scope does not match linked assurance cases",
            finding_id=finding.finding_id,
        )
    expected_invariant_owners = tuple(
        sorted({registry_map[case.case_id].owner_id for case in linked_cases})
    )
    if tuple(sorted(finding.invariant_owner_ids)) != expected_invariant_owners:
        _reject(
            FindingLifecycleRejectReason.INVARIANT_OWNER_BINDING_MISMATCH,
            "finding does not bind the exact invariant owners of linked cases",
            finding_id=finding.finding_id,
        )
    expected_severity = max(linked_cases, key=lambda case: _SEVERITY_RANK[case.severity]).severity
    if finding.severity != expected_severity:
        _reject(
            FindingLifecycleRejectReason.FINDING_SEVERITY_DOWNGRADE,
            "finding severity must equal the highest severity of its linked assurance cases",
            finding_id=finding.finding_id,
        )

    has_target = bool(
        finding.target_release_id
        or finding.target_commit_sha
        or finding.target_package_version
    )
    if finding.state == FindingState.OPEN:
        if has_target or finding.closure_retest_sha256:
            _reject(
                FindingLifecycleRejectReason.TARGET_IDENTITY_INVALID,
                "open findings may not carry fix-target or closure evidence",
                finding_id=finding.finding_id,
            )
    else:
        if (
            not finding.target_release_id
            or not _is_sha256(finding.target_commit_sha)
            or not finding.target_package_version
        ):
            _reject(
                FindingLifecycleRejectReason.TARGET_IDENTITY_INVALID,
                "findings beyond open state require an exact fix-target release identity",
                finding_id=finding.finding_id,
            )
        if finding.state != FindingState.CLOSED and finding.closure_retest_sha256:
            _reject(
                FindingLifecycleRejectReason.RETEST_UNEXPECTED,
                "non-closed findings may not carry closure retest evidence",
                finding_id=finding.finding_id,
            )
        if finding.state == FindingState.CLOSED and not _is_sha256(finding.closure_retest_sha256):
            _reject(
                FindingLifecycleRejectReason.RETEST_REQUIRED,
                "closed findings require an exact closure retest digest",
                finding_id=finding.finding_id,
            )


def _validate_transition(
    previous: AdversarialFinding,
    proposed: AdversarialFinding,
    *,
    evaluated_at_epoch: int,
) -> None:
    if previous.finding_id != proposed.finding_id:
        _reject(
            FindingLifecycleRejectReason.FINDING_IDENTITY_MISMATCH,
            "finding ID changed across lifecycle transition",
            finding_id=proposed.finding_id,
        )
    immutable_pairs = (
        (previous.title, proposed.title),
        (previous.severity, proposed.severity),
        (previous.owner_id, proposed.owner_id),
        (tuple(sorted(previous.affected_case_ids)), tuple(sorted(proposed.affected_case_ids))),
        (tuple(sorted(previous.affected_boundaries)), tuple(sorted(proposed.affected_boundaries))),
        (tuple(sorted(previous.invariant_owner_ids)), tuple(sorted(proposed.invariant_owner_ids))),
        (previous.discovered_release_id, proposed.discovered_release_id),
        (previous.discovered_commit_sha.casefold(), proposed.discovered_commit_sha.casefold()),
        (previous.discovered_package_version, proposed.discovered_package_version),
        (previous.tracking_ref, proposed.tracking_ref),
        (previous.opened_at_epoch, proposed.opened_at_epoch),
    )
    if any(left != right for left, right in immutable_pairs):
        _reject(
            FindingLifecycleRejectReason.FINDING_IDENTITY_MISMATCH,
            "immutable finding identity or scope changed across transition",
            finding_id=proposed.finding_id,
        )
    if proposed.version != previous.version + 1:
        _reject(
            FindingLifecycleRejectReason.FINDING_VERSION_INVALID,
            "finding version must advance by exactly one",
            finding_id=proposed.finding_id,
        )
    if proposed.state not in _ALLOWED_TRANSITIONS[previous.state]:
        _reject(
            FindingLifecycleRejectReason.TRANSITION_INVALID,
            "finding state transition is not permitted",
            finding_id=proposed.finding_id,
        )
    if (
        previous.updated_at_epoch > evaluated_at_epoch
        or proposed.updated_at_epoch > evaluated_at_epoch
        or proposed.updated_at_epoch <= previous.updated_at_epoch
    ):
        _reject(
            FindingLifecycleRejectReason.TIMESTAMP_INVALID,
            "finding timestamps are future-dated or non-monotonic",
            finding_id=proposed.finding_id,
        )

    if previous.state != FindingState.OPEN:
        if (
            previous.target_release_id != proposed.target_release_id
            or previous.target_commit_sha.casefold() != proposed.target_commit_sha.casefold()
            or previous.target_package_version != proposed.target_package_version
        ):
            _reject(
                FindingLifecycleRejectReason.TARGET_IDENTITY_INVALID,
                "fix-target release identity changed after remediation began",
                finding_id=proposed.finding_id,
            )


def _validate_request(
    request: FindingLifecycleRequest,
    *,
    previous: AdversarialFinding,
    proposed: AdversarialFinding,
) -> tuple[str, str]:
    previous_sha = finding_digest(previous)
    proposed_sha = finding_digest(proposed)
    if (
        not request.finding_id
        or not _is_sha256(request.expected_previous_record_sha256)
        or not _is_sha256(request.proposed_record_sha256)
        or request.evaluated_at_epoch <= 0
    ):
        _reject(
            FindingLifecycleRejectReason.REQUEST_INVALID,
            "finding lifecycle request metadata is invalid",
            finding_id=request.finding_id or None,
        )
    if (
        request.finding_id != previous.finding_id
        or request.finding_id != proposed.finding_id
        or not hmac.compare_digest(
            request.expected_previous_record_sha256.casefold(), previous_sha
        )
        or not hmac.compare_digest(request.proposed_record_sha256.casefold(), proposed_sha)
    ):
        _reject(
            FindingLifecycleRejectReason.FINDING_IDENTITY_MISMATCH,
            "lifecycle request does not bind to exact previous/proposed finding records",
            finding_id=request.finding_id,
        )
    return previous_sha, proposed_sha


def _validate_retest(
    retest: FindingRetestEvidence,
    *,
    previous: AdversarialFinding,
    proposed: AdversarialFinding,
    case_map: dict[str, AssuranceCase],
    corpus_sha256: str,
    policy: FindingLifecyclePolicy,
    evaluated_at_epoch: int,
) -> str:
    if (
        retest.schema_version != P6E_RETEST_SCHEMA_VERSION
        or not retest.finding_id
        or not _is_sha256(retest.ready_record_sha256)
        or not retest.release_id
        or not _is_sha256(retest.commit_sha)
        or not retest.package_version
        or not _is_sha256(retest.corpus_sha256)
        or not retest.runner_id
        or retest.executed_at_epoch <= 0
        or not retest.results
    ):
        _reject(
            FindingLifecycleRejectReason.RETEST_INVALID,
            "finding closure retest metadata is invalid",
            finding_id=proposed.finding_id,
        )
    if retest.runner_id not in policy.trusted_retest_runner_ids:
        _reject(
            FindingLifecycleRejectReason.RETEST_RUNNER_UNTRUSTED,
            "finding closure retest was produced by an untrusted runner",
            finding_id=proposed.finding_id,
        )
    if (
        retest.finding_id != proposed.finding_id
        or not hmac.compare_digest(
            retest.ready_record_sha256.casefold(), finding_digest(previous)
        )
        or retest.release_id != proposed.target_release_id
        or retest.commit_sha.casefold() != proposed.target_commit_sha.casefold()
        or retest.package_version != proposed.target_package_version
        or not hmac.compare_digest(retest.corpus_sha256.casefold(), corpus_sha256)
    ):
        _reject(
            FindingLifecycleRejectReason.RETEST_IDENTITY_MISMATCH,
            "closure retest does not bind to exact finding, ready state, target release, or corpus",
            finding_id=proposed.finding_id,
        )
    if retest.executed_at_epoch > evaluated_at_epoch:
        _reject(
            FindingLifecycleRejectReason.RETEST_FUTURE,
            "closure retest is future-dated",
            finding_id=proposed.finding_id,
        )
    if (
        retest.executed_at_epoch < previous.updated_at_epoch
        or evaluated_at_epoch - retest.executed_at_epoch > policy.max_retest_age_seconds
    ):
        _reject(
            FindingLifecycleRejectReason.RETEST_STALE,
            "closure retest predates ready-for-retest state or exceeds freshness policy",
            finding_id=proposed.finding_id,
        )

    observations: dict[str, CaseObservation] = {}
    for result in retest.results:
        if result.case_id in observations:
            _reject(
                FindingLifecycleRejectReason.RETEST_CASE_COVERAGE_MISMATCH,
                "closure retest contains a duplicate assurance-case result",
                finding_id=proposed.finding_id,
                case_id=result.case_id,
            )
        case = case_map.get(result.case_id)
        if case is None:
            _reject(
                FindingLifecycleRejectReason.RETEST_CASE_COVERAGE_MISMATCH,
                "closure retest contains an unknown assurance-case result",
                finding_id=proposed.finding_id,
                case_id=result.case_id,
            )
        if not isinstance(result.observed_outcome, AssuranceExpectation):
            _reject(
                FindingLifecycleRejectReason.RETEST_INVALID,
                "closure retest contains an invalid observed outcome",
                finding_id=proposed.finding_id,
                case_id=result.case_id,
            )
        if (
            not _is_sha256(result.case_definition_sha256)
            or not hmac.compare_digest(
                result.case_definition_sha256.casefold(), case_definition_digest(case)
            )
        ):
            _reject(
                FindingLifecycleRejectReason.RETEST_CASE_DEFINITION_MISMATCH,
                "closure retest result does not bind to the immutable case definition",
                finding_id=proposed.finding_id,
                case_id=result.case_id,
            )
        observations[result.case_id] = result
    if set(observations) != set(case_map):
        _reject(
            FindingLifecycleRejectReason.RETEST_CASE_COVERAGE_MISMATCH,
            "closure retest must contain exact one-to-one corpus case coverage",
            finding_id=proposed.finding_id,
        )
    for case_id in proposed.affected_case_ids:
        case = case_map[case_id]
        if observations[case_id].observed_outcome != case.expectation:
            _reject(
                FindingLifecycleRejectReason.RETEST_FAILED,
                "one or more finding-linked assurance cases still fail on the target release",
                finding_id=proposed.finding_id,
                case_id=case_id,
            )

    exact_retest_sha = retest_digest(retest)
    if not hmac.compare_digest(
        proposed.closure_retest_sha256.casefold(), exact_retest_sha
    ):
        _reject(
            FindingLifecycleRejectReason.RETEST_DIGEST_MISMATCH,
            "closed finding record does not bind to the exact retest evidence digest",
            finding_id=proposed.finding_id,
        )
    return exact_retest_sha


class AdversarialFindingLifecycleGate:
    """Fail closed on finding lifecycle transitions and closure claims.

    The lab validates deterministic records and retest evidence. It does not mutate a
    production ticket system, deploy patches, or claim exhaustive finding discovery.
    """

    def __init__(
        self,
        *,
        corpus: AssuranceCorpus,
        invariant_registry: InvariantRegistry,
        policy: FindingLifecyclePolicy,
    ) -> None:
        self._corpus = corpus
        self._registry = invariant_registry
        self._policy = policy

    def evaluate(
        self,
        *,
        request: FindingLifecycleRequest,
        previous: AdversarialFinding,
        proposed: AdversarialFinding,
        retest: FindingRetestEvidence | None = None,
    ) -> VerifiedFindingTransition:
        if (
            not self._policy.trusted_finding_owner_ids
            or not self._policy.trusted_retest_runner_ids
            or self._policy.max_retest_age_seconds <= 0
        ):
            _reject(
                FindingLifecycleRejectReason.REQUEST_INVALID,
                "finding lifecycle policy is invalid",
            )
        case_map, exact_corpus_sha = _validate_corpus(self._corpus, self._policy)
        registry_map, exact_registry_sha = _validate_registry(
            self._registry,
            case_map=case_map,
            corpus_sha256=exact_corpus_sha,
            policy=self._policy,
        )
        _validate_finding(
            previous,
            case_map=case_map,
            registry_map=registry_map,
            trusted_owner_ids=self._policy.trusted_finding_owner_ids,
        )
        _validate_finding(
            proposed,
            case_map=case_map,
            registry_map=registry_map,
            trusted_owner_ids=self._policy.trusted_finding_owner_ids,
        )
        previous_sha, proposed_sha = _validate_request(
            request,
            previous=previous,
            proposed=proposed,
        )
        _validate_transition(
            previous,
            proposed,
            evaluated_at_epoch=request.evaluated_at_epoch,
        )

        exact_retest_sha: str | None = None
        if proposed.state == FindingState.CLOSED:
            if retest is None:
                _reject(
                    FindingLifecycleRejectReason.RETEST_REQUIRED,
                    "a finding cannot close without exact retest evidence",
                    finding_id=proposed.finding_id,
                )
            exact_retest_sha = _validate_retest(
                retest,
                previous=previous,
                proposed=proposed,
                case_map=case_map,
                corpus_sha256=exact_corpus_sha,
                policy=self._policy,
                evaluated_at_epoch=request.evaluated_at_epoch,
            )
        elif retest is not None:
            _reject(
                FindingLifecycleRejectReason.RETEST_UNEXPECTED,
                "retest evidence is only accepted for a closure transition",
                finding_id=proposed.finding_id,
            )

        transition_document = {
            "corpus_sha256": exact_corpus_sha,
            "finding_id": proposed.finding_id,
            "invariant_registry_sha256": exact_registry_sha,
            "policy_version": P6E_FINDING_POLICY_VERSION,
            "previous_record_sha256": previous_sha,
            "proposed_record_sha256": proposed_sha,
            "retest_evidence_sha256": exact_retest_sha,
            "evaluated_at_epoch": request.evaluated_at_epoch,
        }
        transition_sha = hashlib.sha256(
            json.dumps(
                transition_document,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return VerifiedFindingTransition(
            finding_id=proposed.finding_id,
            previous_version=previous.version,
            current_version=proposed.version,
            previous_state=previous.state,
            current_state=proposed.state,
            severity=proposed.severity,
            owner_id=proposed.owner_id,
            affected_case_ids=tuple(sorted(proposed.affected_case_ids)),
            affected_boundaries=tuple(sorted(proposed.affected_boundaries)),
            invariant_owner_ids=tuple(sorted(proposed.invariant_owner_ids)),
            previous_record_sha256=previous_sha,
            current_record_sha256=proposed_sha,
            corpus_sha256=exact_corpus_sha,
            invariant_registry_sha256=exact_registry_sha,
            retest_evidence_sha256=exact_retest_sha,
            transition_evidence_sha256=transition_sha,
            closure_verified=proposed.state == FindingState.CLOSED,
        )
