from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum

from .regression import (
    P6A_CORPUS_SCHEMA_VERSION,
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    case_definition_digest,
    corpus_digest,
)


P6C_EVOLUTION_POLICY_VERSION = "assurance-corpus-evolution-governance-v1"
P6C_CHANGE_MANIFEST_SCHEMA_VERSION = "aegis-assurance-corpus-change-manifest-v1"
P6C_TOMBSTONE_SCHEMA_VERSION = "aegis-assurance-case-tombstone-v1"
P6C_EVOLUTION_MODE = "deterministic-corpus-evolution-coverage-drift-gate-v1"


class CorpusChangeType(StrEnum):
    ADD = "add"
    MODIFY = "modify"
    DEPRECATE = "deprecate"


class CorpusEvolutionRejectReason(StrEnum):
    BASELINE_INVALID = "baseline_invalid"
    BASELINE_DIGEST_MISMATCH = "baseline_digest_mismatch"
    CANDIDATE_INVALID = "candidate_invalid"
    CANDIDATE_IDENTITY_MISMATCH = "candidate_identity_mismatch"
    VERSION_NOT_ADVANCED = "version_not_advanced"
    REQUEST_INVALID = "request_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    CHANGE_COVERAGE_MISMATCH = "change_coverage_mismatch"
    CHANGE_DUPLICATE = "change_duplicate"
    CHANGE_DEFINITION_MISMATCH = "change_definition_mismatch"
    CHANGE_OWNER_UNTRUSTED = "change_owner_untrusted"
    EXPECTATION_WEAKENED = "expectation_weakened"
    SEVERITY_DOWNGRADED = "severity_downgraded"
    BOUNDARY_RECLASSIFIED = "boundary_reclassified"
    ATTACK_CLASS_RECLASSIFIED = "attack_class_reclassified"
    TOMBSTONE_MISSING = "tombstone_missing"
    TOMBSTONE_INVALID = "tombstone_invalid"
    TOMBSTONE_DUPLICATE = "tombstone_duplicate"
    REPLACEMENT_REQUIRED = "replacement_required"
    REPLACEMENT_INVALID = "replacement_invalid"
    COVERAGE_FLOOR_VIOLATED = "coverage_floor_violated"


class CorpusEvolutionRejected(ValueError):
    def __init__(
        self,
        reason: CorpusEvolutionRejectReason,
        message: str,
        *,
        case_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.case_id = case_id


@dataclass(frozen=True)
class CoverageFloor:
    boundary: str
    min_block_cases: int
    min_high_or_critical_block_cases: int = 0


@dataclass(frozen=True)
class CorpusChangeRecord:
    change_id: str
    change_type: CorpusChangeType
    case_id: str
    owner_id: str
    reason: str
    old_case_definition_sha256: str = ""
    new_case_definition_sha256: str = ""
    replacement_case_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CaseTombstone:
    case_id: str
    case_definition_sha256: str
    boundary: str
    severity: AssuranceSeverity
    expectation: AssuranceExpectation
    removed_in_version: str
    replacement_case_ids: tuple[str, ...] = ()
    schema_version: str = P6C_TOMBSTONE_SCHEMA_VERSION


@dataclass(frozen=True)
class CorpusChangeManifest:
    baseline_corpus_sha256: str
    candidate_corpus_sha256: str
    changes: tuple[CorpusChangeRecord, ...]
    tombstones: tuple[CaseTombstone, ...]
    schema_version: str = P6C_CHANGE_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class CorpusEvolutionRequest:
    candidate_corpus_id: str
    candidate_version: str
    candidate_corpus_sha256: str
    change_manifest_sha256: str


@dataclass(frozen=True)
class CorpusEvolutionPolicy:
    expected_baseline_corpus_id: str
    expected_baseline_corpus_sha256: str
    trusted_change_owner_ids: frozenset[str]
    coverage_floors: tuple[CoverageFloor, ...]
    min_critical_block_cases: int
    min_high_or_critical_block_cases: int
    min_allow_cases: int
    require_replacement_for_high_critical_removal: bool = True
    forbid_block_to_allow: bool = True
    forbid_attack_severity_downgrade: bool = True


@dataclass(frozen=True)
class VerifiedCorpusEvolution:
    corpus_id: str
    baseline_version: str
    candidate_version: str
    baseline_corpus_sha256: str
    candidate_corpus_sha256: str
    change_manifest_sha256: str
    added_case_ids: tuple[str, ...]
    modified_case_ids: tuple[str, ...]
    deprecated_case_ids: tuple[str, ...]
    tombstoned_case_ids: tuple[str, ...]
    candidate_case_count: int
    candidate_block_case_count: int
    candidate_allow_case_count: int
    candidate_critical_block_count: int
    candidate_high_or_critical_block_count: int
    evidence_sha256: str
    exact_change_coverage_verified: bool = True
    removal_tombstones_verified: bool = True
    coverage_floors_verified: bool = True
    weakening_prevented: bool = True
    silent_coverage_shrink_prevented: bool = True
    formal_verification: bool = False
    exhaustive_attack_coverage: bool = False
    production_change_management: bool = False
    network_operations: int = 0
    policy_version: str = P6C_EVOLUTION_POLICY_VERSION
    evolution_mode: str = P6C_EVOLUTION_MODE


def _reject(
    reason: CorpusEvolutionRejectReason,
    message: str,
    *,
    case_id: str | None = None,
) -> None:
    raise CorpusEvolutionRejected(reason, message, case_id=case_id)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _severity_rank(severity: AssuranceSeverity) -> int:
    return {
        AssuranceSeverity.LOW: 1,
        AssuranceSeverity.MEDIUM: 2,
        AssuranceSeverity.HIGH: 3,
        AssuranceSeverity.CRITICAL: 4,
    }[severity]


def _canonical_change(change: CorpusChangeRecord) -> dict[str, object]:
    return {
        "case_id": change.case_id,
        "change_id": change.change_id,
        "change_type": change.change_type.value if isinstance(change.change_type, CorpusChangeType) else str(change.change_type),
        "new_case_definition_sha256": change.new_case_definition_sha256.casefold(),
        "old_case_definition_sha256": change.old_case_definition_sha256.casefold(),
        "owner_id": change.owner_id,
        "reason": change.reason,
        "replacement_case_ids": sorted(change.replacement_case_ids),
    }


def _canonical_tombstone(tombstone: CaseTombstone) -> dict[str, object]:
    return {
        "boundary": tombstone.boundary,
        "case_definition_sha256": tombstone.case_definition_sha256.casefold(),
        "case_id": tombstone.case_id,
        "expectation": tombstone.expectation.value if isinstance(tombstone.expectation, AssuranceExpectation) else str(tombstone.expectation),
        "removed_in_version": tombstone.removed_in_version,
        "replacement_case_ids": sorted(tombstone.replacement_case_ids),
        "schema_version": tombstone.schema_version,
        "severity": tombstone.severity.value if isinstance(tombstone.severity, AssuranceSeverity) else str(tombstone.severity),
    }


def canonical_change_manifest_bytes(manifest: CorpusChangeManifest) -> bytes:
    document = {
        "baseline_corpus_sha256": manifest.baseline_corpus_sha256.casefold(),
        "candidate_corpus_sha256": manifest.candidate_corpus_sha256.casefold(),
        "changes": [_canonical_change(item) for item in sorted(manifest.changes, key=lambda item: item.change_id)],
        "schema_version": manifest.schema_version,
        "tombstones": [_canonical_tombstone(item) for item in sorted(manifest.tombstones, key=lambda item: item.case_id)],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def change_manifest_digest(manifest: CorpusChangeManifest) -> str:
    return hashlib.sha256(canonical_change_manifest_bytes(manifest)).hexdigest()


def _validate_corpus(corpus: AssuranceCorpus, *, label: str) -> dict[str, AssuranceCase]:
    reason = (
        CorpusEvolutionRejectReason.BASELINE_INVALID
        if label == "baseline"
        else CorpusEvolutionRejectReason.CANDIDATE_INVALID
    )
    if (
        corpus.schema_version != P6A_CORPUS_SCHEMA_VERSION
        or not corpus.corpus_id
        or not corpus.version
        or not corpus.cases
    ):
        _reject(reason, f"{label} assurance corpus metadata is invalid")
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
            _reject(reason, f"{label} assurance corpus contains an invalid case", case_id=case.case_id or None)
        if case.case_id in case_map:
            _reject(reason, f"{label} assurance corpus contains duplicate case IDs", case_id=case.case_id)
        case_map[case.case_id] = case
    return case_map


def _validate_policy(policy: CorpusEvolutionPolicy) -> None:
    if (
        not policy.expected_baseline_corpus_id
        or not _is_sha256(policy.expected_baseline_corpus_sha256)
        or not policy.trusted_change_owner_ids
        or policy.min_critical_block_cases < 0
        or policy.min_high_or_critical_block_cases < 0
        or policy.min_allow_cases < 0
    ):
        _reject(CorpusEvolutionRejectReason.BASELINE_INVALID, "corpus evolution policy is invalid")
    floor_boundaries: set[str] = set()
    for floor in policy.coverage_floors:
        if (
            not floor.boundary
            or floor.min_block_cases < 0
            or floor.min_high_or_critical_block_cases < 0
            or floor.boundary in floor_boundaries
        ):
            _reject(CorpusEvolutionRejectReason.BASELINE_INVALID, "coverage-floor policy is invalid")
        floor_boundaries.add(floor.boundary)


def _validate_request(
    request: CorpusEvolutionRequest,
    *,
    candidate: AssuranceCorpus,
    candidate_sha256: str,
    manifest_sha256: str,
) -> None:
    if (
        not request.candidate_corpus_id
        or not request.candidate_version
        or not _is_sha256(request.candidate_corpus_sha256)
        or not _is_sha256(request.change_manifest_sha256)
    ):
        _reject(CorpusEvolutionRejectReason.REQUEST_INVALID, "corpus evolution request metadata is invalid")
    if (
        request.candidate_corpus_id != candidate.corpus_id
        or request.candidate_version != candidate.version
        or not hmac.compare_digest(request.candidate_corpus_sha256.casefold(), candidate_sha256)
    ):
        _reject(CorpusEvolutionRejectReason.CANDIDATE_IDENTITY_MISMATCH, "request does not bind to the exact candidate corpus identity")
    if not hmac.compare_digest(request.change_manifest_sha256.casefold(), manifest_sha256):
        _reject(CorpusEvolutionRejectReason.MANIFEST_DIGEST_MISMATCH, "request does not bind to the exact change manifest digest")


def _index_manifest(
    manifest: CorpusChangeManifest,
    *,
    baseline_sha256: str,
    candidate_sha256: str,
    trusted_change_owner_ids: frozenset[str],
) -> tuple[dict[str, CorpusChangeRecord], dict[str, CaseTombstone]]:
    if (
        manifest.schema_version != P6C_CHANGE_MANIFEST_SCHEMA_VERSION
        or not _is_sha256(manifest.baseline_corpus_sha256)
        or not _is_sha256(manifest.candidate_corpus_sha256)
    ):
        _reject(CorpusEvolutionRejectReason.MANIFEST_INVALID, "change manifest metadata is invalid")
    if (
        not hmac.compare_digest(manifest.baseline_corpus_sha256.casefold(), baseline_sha256)
        or not hmac.compare_digest(manifest.candidate_corpus_sha256.casefold(), candidate_sha256)
    ):
        _reject(CorpusEvolutionRejectReason.MANIFEST_DIGEST_MISMATCH, "change manifest does not bind to exact baseline/candidate corpus digests")

    changes_by_case: dict[str, CorpusChangeRecord] = {}
    change_ids: set[str] = set()
    for change in manifest.changes:
        if (
            not change.change_id
            or not change.case_id
            or not change.owner_id
            or not change.reason
            or not isinstance(change.change_type, CorpusChangeType)
        ):
            _reject(CorpusEvolutionRejectReason.MANIFEST_INVALID, "change manifest contains an invalid change record", case_id=change.case_id or None)
        if change.change_id in change_ids or change.case_id in changes_by_case:
            _reject(CorpusEvolutionRejectReason.CHANGE_DUPLICATE, "change manifest contains a duplicate change ID or case target", case_id=change.case_id)
        change_ids.add(change.change_id)
        changes_by_case[change.case_id] = change
        if change.owner_id not in trusted_change_owner_ids:
            _reject(CorpusEvolutionRejectReason.CHANGE_OWNER_UNTRUSTED, "change record owner is not trusted by policy", case_id=change.case_id)

    tombstones_by_case: dict[str, CaseTombstone] = {}
    for tombstone in manifest.tombstones:
        if tombstone.case_id in tombstones_by_case:
            _reject(CorpusEvolutionRejectReason.TOMBSTONE_DUPLICATE, "duplicate tombstone for removed case", case_id=tombstone.case_id)
        if (
            tombstone.schema_version != P6C_TOMBSTONE_SCHEMA_VERSION
            or not tombstone.case_id
            or not _is_sha256(tombstone.case_definition_sha256)
            or not tombstone.boundary
            or not isinstance(tombstone.severity, AssuranceSeverity)
            or not isinstance(tombstone.expectation, AssuranceExpectation)
            or not tombstone.removed_in_version
        ):
            _reject(CorpusEvolutionRejectReason.TOMBSTONE_INVALID, "tombstone metadata is invalid", case_id=tombstone.case_id or None)
        tombstones_by_case[tombstone.case_id] = tombstone
    return changes_by_case, tombstones_by_case


def _validate_coverage_floors(
    candidate_map: dict[str, AssuranceCase],
    policy: CorpusEvolutionPolicy,
) -> tuple[int, int, int]:
    block_cases = [case for case in candidate_map.values() if case.expectation == AssuranceExpectation.BLOCK]
    allow_cases = [case for case in candidate_map.values() if case.expectation == AssuranceExpectation.ALLOW]
    critical_count = sum(case.severity == AssuranceSeverity.CRITICAL for case in block_cases)
    high_or_critical_count = sum(case.severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL} for case in block_cases)
    if critical_count < policy.min_critical_block_cases:
        _reject(CorpusEvolutionRejectReason.COVERAGE_FLOOR_VIOLATED, "candidate corpus falls below the global critical attack-case floor")
    if high_or_critical_count < policy.min_high_or_critical_block_cases:
        _reject(CorpusEvolutionRejectReason.COVERAGE_FLOOR_VIOLATED, "candidate corpus falls below the global high/critical attack-case floor")
    if len(allow_cases) < policy.min_allow_cases:
        _reject(CorpusEvolutionRejectReason.COVERAGE_FLOOR_VIOLATED, "candidate corpus falls below the benign safe-task floor")
    for floor in policy.coverage_floors:
        boundary_cases = [
            case for case in block_cases
            if case.boundary == floor.boundary
        ]
        boundary_high = [
            case for case in boundary_cases
            if case.severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL}
        ]
        if len(boundary_cases) < floor.min_block_cases or len(boundary_high) < floor.min_high_or_critical_block_cases:
            _reject(
                CorpusEvolutionRejectReason.COVERAGE_FLOOR_VIOLATED,
                f"candidate corpus violates the coverage floor for boundary {floor.boundary}",
            )
    return len(block_cases), critical_count, high_or_critical_count


class AssuranceCorpusEvolutionGate:
    """Govern exact version-to-version corpus evolution without claiming exhaustive coverage.

    This lab checks deterministic corpus/change metadata. It does not execute attacks,
    verify production change tickets, or prove that the corpus is complete.
    """

    def __init__(self, *, policy: CorpusEvolutionPolicy) -> None:
        self._policy = policy

    def evaluate(
        self,
        *,
        request: CorpusEvolutionRequest,
        baseline: AssuranceCorpus,
        candidate: AssuranceCorpus,
        manifest: CorpusChangeManifest,
    ) -> VerifiedCorpusEvolution:
        _validate_policy(self._policy)
        baseline_map = _validate_corpus(baseline, label="baseline")
        candidate_map = _validate_corpus(candidate, label="candidate")
        baseline_sha256 = corpus_digest(baseline)
        candidate_sha256 = corpus_digest(candidate)

        if (
            baseline.corpus_id != self._policy.expected_baseline_corpus_id
            or not hmac.compare_digest(baseline_sha256, self._policy.expected_baseline_corpus_sha256.casefold())
        ):
            _reject(CorpusEvolutionRejectReason.BASELINE_DIGEST_MISMATCH, "baseline corpus does not match the policy-pinned identity and digest")
        if candidate.corpus_id != baseline.corpus_id:
            _reject(CorpusEvolutionRejectReason.CANDIDATE_IDENTITY_MISMATCH, "candidate corpus ID must remain in the same versioned corpus lineage")
        if candidate.version == baseline.version:
            _reject(CorpusEvolutionRejectReason.VERSION_NOT_ADVANCED, "candidate corpus version must advance")

        manifest_sha256 = change_manifest_digest(manifest)
        _validate_request(
            request,
            candidate=candidate,
            candidate_sha256=candidate_sha256,
            manifest_sha256=manifest_sha256,
        )
        changes_by_case, tombstones_by_case = _index_manifest(
            manifest,
            baseline_sha256=baseline_sha256,
            candidate_sha256=candidate_sha256,
            trusted_change_owner_ids=self._policy.trusted_change_owner_ids,
        )

        baseline_ids = set(baseline_map)
        candidate_ids = set(candidate_map)
        added_ids = candidate_ids - baseline_ids
        removed_ids = baseline_ids - candidate_ids
        common_ids = baseline_ids & candidate_ids
        modified_ids = {
            case_id
            for case_id in common_ids
            if case_definition_digest(baseline_map[case_id]) != case_definition_digest(candidate_map[case_id])
        }

        expected_changed_ids = added_ids | removed_ids | modified_ids
        if set(changes_by_case) != expected_changed_ids:
            missing = sorted(expected_changed_ids - set(changes_by_case))
            orphan = sorted(set(changes_by_case) - expected_changed_ids)
            case_id = (missing or orphan or [None])[0]
            _reject(
                CorpusEvolutionRejectReason.CHANGE_COVERAGE_MISMATCH,
                "change manifest must provide exact one-to-one coverage for every add/modify/deprecate operation and no unchanged cases",
                case_id=case_id,
            )

        for case_id in sorted(added_ids):
            change = changes_by_case[case_id]
            new_digest = case_definition_digest(candidate_map[case_id])
            if (
                change.change_type != CorpusChangeType.ADD
                or change.old_case_definition_sha256
                or not _is_sha256(change.new_case_definition_sha256)
                or not hmac.compare_digest(change.new_case_definition_sha256.casefold(), new_digest)
                or change.replacement_case_ids
            ):
                _reject(CorpusEvolutionRejectReason.CHANGE_DEFINITION_MISMATCH, "add record does not bind to the exact new case definition", case_id=case_id)

        for case_id in sorted(modified_ids):
            change = changes_by_case[case_id]
            old_case = baseline_map[case_id]
            new_case = candidate_map[case_id]
            old_digest = case_definition_digest(old_case)
            new_digest = case_definition_digest(new_case)
            if (
                change.change_type != CorpusChangeType.MODIFY
                or not _is_sha256(change.old_case_definition_sha256)
                or not _is_sha256(change.new_case_definition_sha256)
                or not hmac.compare_digest(change.old_case_definition_sha256.casefold(), old_digest)
                or not hmac.compare_digest(change.new_case_definition_sha256.casefold(), new_digest)
                or change.replacement_case_ids
            ):
                _reject(CorpusEvolutionRejectReason.CHANGE_DEFINITION_MISMATCH, "modify record does not bind to exact old/new case definitions", case_id=case_id)
            if old_case.boundary != new_case.boundary:
                _reject(CorpusEvolutionRejectReason.BOUNDARY_RECLASSIFIED, "existing case boundary may not be silently reclassified; deprecate and add a new case instead", case_id=case_id)
            if old_case.attack_class != new_case.attack_class:
                _reject(CorpusEvolutionRejectReason.ATTACK_CLASS_RECLASSIFIED, "existing case attack class may not be silently reclassified; deprecate and add a new case instead", case_id=case_id)
            if (
                self._policy.forbid_block_to_allow
                and old_case.expectation == AssuranceExpectation.BLOCK
                and new_case.expectation != AssuranceExpectation.BLOCK
            ):
                _reject(CorpusEvolutionRejectReason.EXPECTATION_WEAKENED, "attack-blocking case may not be weakened into an allow expectation", case_id=case_id)
            if (
                self._policy.forbid_attack_severity_downgrade
                and old_case.expectation == AssuranceExpectation.BLOCK
                and _severity_rank(new_case.severity) < _severity_rank(old_case.severity)
            ):
                _reject(CorpusEvolutionRejectReason.SEVERITY_DOWNGRADED, "attack case severity may not be downgraded during in-place modification", case_id=case_id)

        if set(tombstones_by_case) != removed_ids:
            missing = sorted(removed_ids - set(tombstones_by_case))
            extra = sorted(set(tombstones_by_case) - removed_ids)
            case_id = (missing or extra or [None])[0]
            reason = CorpusEvolutionRejectReason.TOMBSTONE_MISSING if missing else CorpusEvolutionRejectReason.TOMBSTONE_INVALID
            _reject(reason, "removed cases require exact tombstone coverage and unchanged cases may not be tombstoned", case_id=case_id)

        for case_id in sorted(removed_ids):
            old_case = baseline_map[case_id]
            change = changes_by_case[case_id]
            tombstone = tombstones_by_case[case_id]
            old_digest = case_definition_digest(old_case)
            if (
                change.change_type != CorpusChangeType.DEPRECATE
                or not _is_sha256(change.old_case_definition_sha256)
                or not hmac.compare_digest(change.old_case_definition_sha256.casefold(), old_digest)
                or change.new_case_definition_sha256
            ):
                _reject(CorpusEvolutionRejectReason.CHANGE_DEFINITION_MISMATCH, "deprecation record does not bind to the exact removed case definition", case_id=case_id)
            if (
                not hmac.compare_digest(tombstone.case_definition_sha256.casefold(), old_digest)
                or tombstone.boundary != old_case.boundary
                or tombstone.severity != old_case.severity
                or tombstone.expectation != old_case.expectation
                or tombstone.removed_in_version != candidate.version
                or tuple(sorted(tombstone.replacement_case_ids)) != tuple(sorted(change.replacement_case_ids))
            ):
                _reject(CorpusEvolutionRejectReason.TOMBSTONE_INVALID, "tombstone does not preserve exact removed-case identity and replacement metadata", case_id=case_id)

            high_or_critical_attack = (
                old_case.expectation == AssuranceExpectation.BLOCK
                and old_case.severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL}
            )
            if self._policy.require_replacement_for_high_critical_removal and high_or_critical_attack:
                if not change.replacement_case_ids:
                    _reject(CorpusEvolutionRejectReason.REPLACEMENT_REQUIRED, "high/critical removed attack cases require explicit replacement coverage", case_id=case_id)
                for replacement_id in change.replacement_case_ids:
                    replacement = candidate_map.get(replacement_id)
                    if (
                        replacement is None
                        or replacement_id not in added_ids
                        or replacement.expectation != AssuranceExpectation.BLOCK
                        or replacement.boundary != old_case.boundary
                        or _severity_rank(replacement.severity) < _severity_rank(old_case.severity)
                    ):
                        _reject(CorpusEvolutionRejectReason.REPLACEMENT_INVALID, "replacement must be a newly added same-boundary block case of equal-or-higher severity", case_id=case_id)

        block_count, critical_count, high_or_critical_count = _validate_coverage_floors(candidate_map, self._policy)
        allow_count = sum(case.expectation == AssuranceExpectation.ALLOW for case in candidate_map.values())

        evidence_document = {
            "baseline_corpus_sha256": baseline_sha256,
            "candidate_corpus_sha256": candidate_sha256,
            "change_manifest_sha256": manifest_sha256,
            "policy_version": P6C_EVOLUTION_POLICY_VERSION,
            "request": asdict(request),
        }
        evidence_sha256 = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return VerifiedCorpusEvolution(
            corpus_id=candidate.corpus_id,
            baseline_version=baseline.version,
            candidate_version=candidate.version,
            baseline_corpus_sha256=baseline_sha256,
            candidate_corpus_sha256=candidate_sha256,
            change_manifest_sha256=manifest_sha256,
            added_case_ids=tuple(sorted(added_ids)),
            modified_case_ids=tuple(sorted(modified_ids)),
            deprecated_case_ids=tuple(sorted(removed_ids)),
            tombstoned_case_ids=tuple(sorted(tombstones_by_case)),
            candidate_case_count=len(candidate_map),
            candidate_block_case_count=block_count,
            candidate_allow_case_count=allow_count,
            candidate_critical_block_count=critical_count,
            candidate_high_or_critical_block_count=high_or_critical_count,
            evidence_sha256=evidence_sha256,
        )
