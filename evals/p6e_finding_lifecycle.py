from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any

from aegis.assurance.finding_lifecycle import (
    AdversarialFinding,
    AdversarialFindingLifecycleGate,
    FindingLifecyclePolicy,
    FindingLifecycleRejectReason,
    FindingLifecycleRejected,
    FindingLifecycleRequest,
    FindingRetestEvidence,
    FindingState,
    finding_digest,
    retest_digest,
)
from aegis.assurance.regression import (
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    CaseObservation,
    case_definition_digest,
    corpus_digest,
)
from aegis.assurance.waiver_governance import (
    InvariantRecord,
    InvariantRegistry,
    invariant_registry_digest,
)
from aegis.vulnerable.finding_lifecycle import VulnerableCallerDeclaredFindingLifecycle


DISCOVERY_RELEASE = "aegisdesk-v0.58.0"
DISCOVERY_COMMIT = "c" * 64
DISCOVERY_VERSION = "0.58.0"
TARGET_RELEASE = "aegisdesk-v0.59.0"
TARGET_COMMIT = "d" * 64
TARGET_VERSION = "0.59.0"
FINDING_OWNER = "redteam-finding-owner"
RUNNER_ID = "aegis-finding-retest-runner-v1"
OPENED_AT = 1_900_000_000
EVALUATED_AT = 1_900_000_400


BOUNDARY_OWNER = {
    "p5a-artifact-provenance": "supply-chain-owner",
    "p5b-package-provenance": "supply-chain-owner",
    "p5c-registry-acquisition": "registry-owner",
    "p5d-key-lifecycle": "key-lifecycle-owner",
    "p5e-runtime-isolation": "runtime-owner",
    "p5f-model-scanning": "model-integrity-owner",
    "p5g-model-privacy": "privacy-owner",
    "p5h-deployment-attestation": "deployment-owner",
    "p5i-serving-response": "serving-owner",
}


def build_corpus() -> AssuranceCorpus:
    cases = (
        AssuranceCase("P6A-C01", "p5a-artifact-provenance", "artifact-digest-substitution", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "signed artifact payload remains digest-bound"),
        AssuranceCase("P6A-C02", "p5b-package-provenance", "transitive-adapter-substitution", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "package closure remains exact and publisher-authorized"),
        AssuranceCase("P6A-C03", "p5c-registry-acquisition", "mutable-tag-drift", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "mutable aliases cannot escape immutable release pins"),
        AssuranceCase("P6A-C04", "p5d-key-lifecycle", "revoked-signing-key", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "revoked provenance signing keys remain rejected"),
        AssuranceCase("P6A-C05", "p5e-runtime-isolation", "remote-code-request", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "runtime admission continues to deny remote or dynamic code"),
        AssuranceCase("P6A-C06", "p5e-runtime-isolation", "host-capability-escalation", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "runtime admission continues to deny host privilege expansion"),
        AssuranceCase("P6A-C07", "p5f-model-scanning", "poisoning-indicator", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "release-scoped model-content indicators remain policy-gated"),
        AssuranceCase("P6A-C08", "p5f-model-scanning", "backdoor-probe-trigger", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "required backdoor-probe indicators remain below policy thresholds"),
        AssuranceCase("P6A-C09", "p5g-model-privacy", "raw-logit-extraction", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "high-fidelity inference internals remain unavailable"),
        AssuranceCase("P6A-C10", "p5g-model-privacy", "training-canary-leak", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "modeled training canary leakage remains denied"),
        AssuranceCase("P6A-C11", "p5h-deployment-attestation", "environment-measurement-substitution", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "deployment evidence remains bound to policy-pinned measurements"),
        AssuranceCase("P6A-C12", "p5h-deployment-attestation", "stale-attestation-replay", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "stale signed deployment evidence remains unusable"),
        AssuranceCase("P6A-C13", "p5i-serving-response", "telemetry-chain-fork", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "serving telemetry remains sequence and hash-chain bound"),
        AssuranceCase("P6A-C14", "p5i-serving-response", "privacy-budget-abuse", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "serving abuse evidence continues to trigger policy-owned response"),
        AssuranceCase("P6A-C15", "p5i-serving-response", "canary-incident-suppression", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "canary-leak incidents cannot be silently downgraded"),
        AssuranceCase("P6A-C16", "p5e-runtime-isolation", "benign-static-runtime-plan", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "approved inert runtime plans remain admissible"),
        AssuranceCase("P6A-C17", "p5g-model-privacy", "benign-bounded-answer", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "bounded privacy-safe inference remains usable"),
        AssuranceCase("P6A-C18", "p5i-serving-response", "benign-observe-telemetry", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "benign telemetry remains non-disruptive"),
    )
    return AssuranceCorpus(
        corpus_id="aegisdesk-cross-boundary-security-corpus",
        version="2026.08-p6e.1",
        cases=cases,
    )


def build_registry(corpus: AssuranceCorpus) -> InvariantRegistry:
    return InvariantRegistry(
        registry_id="aegisdesk-security-invariants",
        version="2026.08-p6e.1",
        corpus_sha256=corpus_digest(corpus),
        records=tuple(
            InvariantRecord(
                case_id=case.case_id,
                case_definition_sha256=case_definition_digest(case),
                owner_id=BOUNDARY_OWNER[case.boundary],
                severity=case.severity,
            )
            for case in corpus.cases
        ),
    )


def finding_stage(state: FindingState, *, version: int, updated_at_epoch: int) -> AdversarialFinding:
    target = state != FindingState.OPEN
    return AdversarialFinding(
        finding_id="FIND-P6E-001",
        version=version,
        title="Serving telemetry chain and incident suppression regression",
        severity=AssuranceSeverity.CRITICAL,
        owner_id=FINDING_OWNER,
        affected_case_ids=("P6A-C13", "P6A-C15"),
        affected_boundaries=("p5i-serving-response",),
        invariant_owner_ids=("serving-owner",),
        discovered_release_id=DISCOVERY_RELEASE,
        discovered_commit_sha=DISCOVERY_COMMIT,
        discovered_package_version=DISCOVERY_VERSION,
        state=state,
        tracking_ref="AegisDesk-RT-001",
        opened_at_epoch=OPENED_AT,
        updated_at_epoch=updated_at_epoch,
        target_release_id=TARGET_RELEASE if target else "",
        target_commit_sha=TARGET_COMMIT if target else "",
        target_package_version=TARGET_VERSION if target else "",
    )


def retest_for(
    corpus: AssuranceCorpus,
    ready: AdversarialFinding,
    *,
    executed_at_epoch: int = OPENED_AT + 250,
) -> FindingRetestEvidence:
    return FindingRetestEvidence(
        finding_id=ready.finding_id,
        ready_record_sha256=finding_digest(ready),
        release_id=ready.target_release_id,
        commit_sha=ready.target_commit_sha,
        package_version=ready.target_package_version,
        corpus_sha256=corpus_digest(corpus),
        runner_id=RUNNER_ID,
        executed_at_epoch=executed_at_epoch,
        results=tuple(
            CaseObservation(
                case_id=case.case_id,
                case_definition_sha256=case_definition_digest(case),
                observed_outcome=case.expectation,
            )
            for case in corpus.cases
        ),
    )


def request_for(
    previous: AdversarialFinding,
    proposed: AdversarialFinding,
    *,
    evaluated_at_epoch: int = EVALUATED_AT,
) -> FindingLifecycleRequest:
    return FindingLifecycleRequest(
        finding_id=previous.finding_id,
        expected_previous_record_sha256=finding_digest(previous),
        proposed_record_sha256=finding_digest(proposed),
        evaluated_at_epoch=evaluated_at_epoch,
    )


def default_fixture() -> dict[str, Any]:
    corpus = build_corpus()
    registry = build_registry(corpus)
    ready = finding_stage(FindingState.READY_FOR_RETEST, version=3, updated_at_epoch=OPENED_AT + 200)
    retest = retest_for(corpus, ready)
    closed = replace(
        ready,
        version=4,
        state=FindingState.CLOSED,
        updated_at_epoch=OPENED_AT + 300,
        closure_retest_sha256=retest_digest(retest),
    )
    policy = FindingLifecyclePolicy(
        expected_corpus_sha256=corpus_digest(corpus),
        expected_invariant_registry_sha256=invariant_registry_digest(registry),
        trusted_finding_owner_ids=frozenset({FINDING_OWNER, "secondary-finding-owner"}),
        trusted_retest_runner_ids=frozenset({RUNNER_ID, "secondary-retest-runner-v1"}),
        max_retest_age_seconds=1_000,
    )
    return {
        "corpus": corpus,
        "registry": registry,
        "policy": policy,
        "previous": ready,
        "proposed": closed,
        "retest": retest,
        "request": request_for(ready, closed),
    }


def _serializable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, frozenset):
        return sorted(value)
    if isinstance(value, tuple):
        return [_serializable(item) for item in value]
    if isinstance(value, dict):
        return {key: _serializable(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {key: _serializable(item) for key, item in asdict(value).items()}
    return value


def fixture_digest() -> str:
    fixture = default_fixture()
    document = {
        "corpus": _serializable(fixture["corpus"]),
        "registry": _serializable(fixture["registry"]),
        "policy": _serializable(fixture["policy"]),
        "previous": _serializable(fixture["previous"]),
        "proposed": _serializable(fixture["proposed"]),
        "request": _serializable(fixture["request"]),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _scope_finding(
    base: AdversarialFinding,
    *,
    case_ids: tuple[str, ...],
    boundaries: tuple[str, ...],
    invariant_owner_ids: tuple[str, ...],
    severity: AssuranceSeverity,
) -> AdversarialFinding:
    return replace(
        base,
        affected_case_ids=case_ids,
        affected_boundaries=boundaries,
        invariant_owner_ids=invariant_owner_ids,
        severity=severity,
    )


def adversarial_cases() -> list[tuple[str, FindingLifecycleRejectReason, dict[str, Any]]]:
    base = default_fixture()
    corpus: AssuranceCorpus = base["corpus"]
    registry: InvariantRegistry = base["registry"]
    policy: FindingLifecyclePolicy = base["policy"]
    ready: AdversarialFinding = base["previous"]
    closed: AdversarialFinding = base["proposed"]
    retest: FindingRetestEvidence = base["retest"]

    missing_registry = replace(registry, records=registry.records[:-1])
    missing_registry_policy = replace(
        policy,
        expected_invariant_registry_sha256=invariant_registry_digest(missing_registry),
    )
    drift_record = replace(registry.records[0], case_definition_sha256="0" * 64)
    drift_registry = replace(registry, records=(drift_record,) + registry.records[1:])
    drift_registry_policy = replace(
        policy,
        expected_invariant_registry_sha256=invariant_registry_digest(drift_registry),
    )
    severity_record = replace(registry.records[0], severity=AssuranceSeverity.LOW)
    severity_registry = replace(registry, records=(severity_record,) + registry.records[1:])
    severity_registry_policy = replace(
        policy,
        expected_invariant_registry_sha256=invariant_registry_digest(severity_registry),
    )

    safe_ready = _scope_finding(
        ready,
        case_ids=("P6A-C16",),
        boundaries=("p5e-runtime-isolation",),
        invariant_owner_ids=("runtime-owner",),
        severity=AssuranceSeverity.LOW,
    )
    safe_closed = _scope_finding(
        closed,
        case_ids=("P6A-C16",),
        boundaries=("p5e-runtime-isolation",),
        invariant_owner_ids=("runtime-owner",),
        severity=AssuranceSeverity.LOW,
    )
    safe_retest = replace(retest, finding_id=safe_ready.finding_id, ready_record_sha256=finding_digest(safe_ready))
    safe_closed = replace(safe_closed, closure_retest_sha256=retest_digest(safe_retest))

    unknown_ready = replace(ready, affected_case_ids=("P6A-UNKNOWN",))
    unknown_closed = replace(closed, affected_case_ids=("P6A-UNKNOWN",))

    boundary_ready = replace(ready, affected_boundaries=("p5h-deployment-attestation",))
    boundary_closed = replace(closed, affected_boundaries=("p5h-deployment-attestation",))

    owner_binding_ready = replace(ready, invariant_owner_ids=("privacy-owner",))
    owner_binding_closed = replace(closed, invariant_owner_ids=("privacy-owner",))

    severity_ready = replace(ready, severity=AssuranceSeverity.HIGH)
    severity_closed = replace(closed, severity=AssuranceSeverity.HIGH)

    proposed_id = replace(closed, finding_id="FIND-P6E-OTHER")
    immutable_scope = replace(
        closed,
        affected_case_ids=("P6A-C15",),
        affected_boundaries=("p5i-serving-response",),
        invariant_owner_ids=("serving-owner",),
        severity=AssuranceSeverity.CRITICAL,
    )
    version_skip = replace(closed, version=5)
    timestamp_rollback = replace(closed, updated_at_epoch=ready.updated_at_epoch)

    open_record = finding_stage(FindingState.OPEN, version=1, updated_at_epoch=OPENED_AT)
    illegal_closed = replace(
        open_record,
        version=2,
        state=FindingState.CLOSED,
        updated_at_epoch=OPENED_AT + 100,
        target_release_id=TARGET_RELEASE,
        target_commit_sha=TARGET_COMMIT,
        target_package_version=TARGET_VERSION,
        closure_retest_sha256=retest_digest(retest),
    )

    target_substitution = replace(closed, target_commit_sha="9" * 64)

    fix = finding_stage(FindingState.FIX_IN_PROGRESS, version=2, updated_at_epoch=OPENED_AT + 100)
    ready_from_fix = finding_stage(FindingState.READY_FOR_RETEST, version=3, updated_at_epoch=OPENED_AT + 200)

    missing_results = replace(retest, results=retest.results[:-1])
    duplicate_results = replace(retest, results=retest.results + (retest.results[0],))
    unknown_result = replace(
        retest.results[-1],
        case_id="P6A-UNKNOWN",
    )
    unknown_results = replace(retest, results=retest.results[:-1] + (unknown_result,))
    bad_definition_results = tuple(
        replace(item, case_definition_sha256="1" * 64)
        if item.case_id == "P6A-C13"
        else item
        for item in retest.results
    )
    failed_results = tuple(
        replace(item, observed_outcome=AssuranceExpectation.ALLOW)
        if item.case_id == "P6A-C15"
        else item
        for item in retest.results
    )
    invalid_outcome_results = tuple(
        replace(item, observed_outcome="not-an-outcome")
        if item.case_id == "P6A-C13"
        else item
        for item in retest.results
    )
    stale_retest = replace(retest, executed_at_epoch=ready.updated_at_epoch - 1)
    future_retest = replace(retest, executed_at_epoch=EVALUATED_AT + 1)
    alternate_valid_retest = replace(retest, executed_at_epoch=retest.executed_at_epoch + 1)

    nonclosed_with_digest = replace(ready_from_fix, closure_retest_sha256="a" * 64)

    cases: list[tuple[str, FindingLifecycleRejectReason, dict[str, Any]]] = [
        ("P6E-A01 corpus digest substitution", FindingLifecycleRejectReason.CORPUS_DIGEST_MISMATCH, {"policy": replace(policy, expected_corpus_sha256="0" * 64)}),
        ("P6E-A02 registry digest substitution", FindingLifecycleRejectReason.REGISTRY_DIGEST_MISMATCH, {"policy": replace(policy, expected_invariant_registry_sha256="0" * 64)}),
        ("P6E-A03 registry case omission under repin", FindingLifecycleRejectReason.INVARIANT_DRIFT, {"registry": missing_registry, "policy": missing_registry_policy}),
        ("P6E-A04 invariant definition drift under repin", FindingLifecycleRejectReason.INVARIANT_DRIFT, {"registry": drift_registry, "policy": drift_registry_policy}),
        ("P6E-A05 invariant severity drift under repin", FindingLifecycleRejectReason.INVARIANT_DRIFT, {"registry": severity_registry, "policy": severity_registry_policy}),
        ("P6E-A06 untrusted finding owner", FindingLifecycleRejectReason.FINDING_OWNER_UNTRUSTED, {"previous": replace(ready, owner_id="untrusted-owner"), "proposed": replace(closed, owner_id="untrusted-owner")}),
        ("P6E-A07 safe-task case linked as finding", FindingLifecycleRejectReason.FINDING_SCOPE_MISMATCH, {"previous": safe_ready, "proposed": safe_closed, "retest": safe_retest}),
        ("P6E-A08 unknown assurance case link", FindingLifecycleRejectReason.FINDING_SCOPE_MISMATCH, {"previous": unknown_ready, "proposed": unknown_closed}),
        ("P6E-A09 affected boundary substitution", FindingLifecycleRejectReason.FINDING_SCOPE_MISMATCH, {"previous": boundary_ready, "proposed": boundary_closed}),
        ("P6E-A10 invariant owner binding substitution", FindingLifecycleRejectReason.INVARIANT_OWNER_BINDING_MISMATCH, {"previous": owner_binding_ready, "proposed": owner_binding_closed}),
        ("P6E-A11 finding severity downgrade", FindingLifecycleRejectReason.FINDING_SEVERITY_DOWNGRADE, {"previous": severity_ready, "proposed": severity_closed}),
        ("P6E-A12 proposed finding ID substitution", FindingLifecycleRejectReason.FINDING_IDENTITY_MISMATCH, {"proposed": proposed_id}),
        ("P6E-A13 immutable affected-case scope mutation", FindingLifecycleRejectReason.FINDING_IDENTITY_MISMATCH, {"proposed": immutable_scope}),
        ("P6E-A14 finding version skip", FindingLifecycleRejectReason.FINDING_VERSION_INVALID, {"proposed": version_skip}),
        ("P6E-A15 non-monotonic finding timestamp", FindingLifecycleRejectReason.TIMESTAMP_INVALID, {"proposed": timestamp_rollback}),
        ("P6E-A16 illegal open-to-closed transition", FindingLifecycleRejectReason.TRANSITION_INVALID, {"previous": open_record, "proposed": illegal_closed}),
        ("P6E-A17 fix-target identity substitution after ready", FindingLifecycleRejectReason.TARGET_IDENTITY_INVALID, {"proposed": target_substitution}),
        ("P6E-A18 closure without retest evidence", FindingLifecycleRejectReason.RETEST_REQUIRED, {"retest": None}),
        ("P6E-A19 retest supplied before closure", FindingLifecycleRejectReason.RETEST_UNEXPECTED, {"previous": fix, "proposed": ready_from_fix, "retest": retest}),
        ("P6E-A20 untrusted retest runner", FindingLifecycleRejectReason.RETEST_RUNNER_UNTRUSTED, {"retest": replace(retest, runner_id="untrusted-runner")}),
        ("P6E-A21 retest finding substitution", FindingLifecycleRejectReason.RETEST_IDENTITY_MISMATCH, {"retest": replace(retest, finding_id="FIND-P6E-OTHER")}),
        ("P6E-A22 retest ready-record substitution", FindingLifecycleRejectReason.RETEST_IDENTITY_MISMATCH, {"retest": replace(retest, ready_record_sha256="2" * 64)}),
        ("P6E-A23 retest target-release substitution", FindingLifecycleRejectReason.RETEST_IDENTITY_MISMATCH, {"retest": replace(retest, release_id="wrong-release")}),
        ("P6E-A24 retest corpus substitution", FindingLifecycleRejectReason.RETEST_IDENTITY_MISMATCH, {"retest": replace(retest, corpus_sha256="3" * 64)}),
        ("P6E-A25 retest case omission", FindingLifecycleRejectReason.RETEST_CASE_COVERAGE_MISMATCH, {"retest": missing_results}),
        ("P6E-A26 retest duplicate case", FindingLifecycleRejectReason.RETEST_CASE_COVERAGE_MISMATCH, {"retest": duplicate_results}),
        ("P6E-A27 retest unknown case", FindingLifecycleRejectReason.RETEST_CASE_COVERAGE_MISMATCH, {"retest": unknown_results}),
        ("P6E-A28 retest case-definition substitution", FindingLifecycleRejectReason.RETEST_CASE_DEFINITION_MISMATCH, {"retest": replace(retest, results=bad_definition_results)}),
        ("P6E-A29 finding-linked retest still fails", FindingLifecycleRejectReason.RETEST_FAILED, {"retest": replace(retest, results=failed_results)}),
        ("P6E-A30 stale retest", FindingLifecycleRejectReason.RETEST_STALE, {"retest": stale_retest}),
        ("P6E-A31 future-dated retest", FindingLifecycleRejectReason.RETEST_FUTURE, {"retest": future_retest}),
        ("P6E-A32 closure retest digest substitution", FindingLifecycleRejectReason.RETEST_DIGEST_MISMATCH, {"retest": alternate_valid_retest}),
        ("P6E-A33 previous-record request digest substitution", FindingLifecycleRejectReason.FINDING_IDENTITY_MISMATCH, {"request": replace(base["request"], expected_previous_record_sha256="4" * 64)}),
        ("P6E-A34 proposed-record request digest substitution", FindingLifecycleRejectReason.FINDING_IDENTITY_MISMATCH, {"request": replace(base["request"], proposed_record_sha256="5" * 64)}),
        ("P6E-A35 invalid retest outcome type", FindingLifecycleRejectReason.RETEST_INVALID, {"retest": replace(retest, results=invalid_outcome_results)}),
        ("P6E-A36 closure digest attached before closed state", FindingLifecycleRejectReason.RETEST_UNEXPECTED, {"previous": fix, "proposed": nonclosed_with_digest, "retest": None}),
    ]

    rebuilt: list[tuple[str, FindingLifecycleRejectReason, dict[str, Any]]] = []
    for name, reason, overrides in cases:
        previous = overrides.get("previous", ready)
        proposed = overrides.get("proposed", closed)
        if "request" not in overrides:
            overrides = dict(overrides)
            overrides["request"] = request_for(previous, proposed)
        rebuilt.append((name, reason, overrides))
    return rebuilt


def benign_cases() -> list[tuple[str, dict[str, Any]]]:
    base = default_fixture()
    corpus: AssuranceCorpus = base["corpus"]
    open_record = finding_stage(FindingState.OPEN, version=1, updated_at_epoch=OPENED_AT)
    fix = finding_stage(FindingState.FIX_IN_PROGRESS, version=2, updated_at_epoch=OPENED_AT + 100)
    ready = finding_stage(FindingState.READY_FOR_RETEST, version=3, updated_at_epoch=OPENED_AT + 200)
    retest = retest_for(corpus, ready)
    closed = replace(
        ready,
        version=4,
        state=FindingState.CLOSED,
        updated_at_epoch=OPENED_AT + 300,
        closure_retest_sha256=retest_digest(retest),
    )
    return [
        ("P6E-B1 open to fix-in-progress", {"previous": open_record, "proposed": fix, "retest": None, "request": request_for(open_record, fix)}),
        ("P6E-B2 fix-in-progress to ready-for-retest", {"previous": fix, "proposed": ready, "retest": None, "request": request_for(fix, ready)}),
        ("P6E-B3 ready-for-retest to closed with exact passing evidence", {"previous": ready, "proposed": closed, "retest": retest, "request": request_for(ready, closed)}),
    ]


def dataset_digest() -> str:
    document = {
        "adversarial": [
            {"name": name, "reason": reason.value}
            for name, reason, _ in adversarial_cases()
        ],
        "benign": [name for name, _ in benign_cases()],
        "finding_cases": ["P6A-C13", "P6A-C15"],
        "states": [state.value for state in FindingState],
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def run_evaluation() -> dict[str, Any]:
    base = default_fixture()
    vulnerable = VulnerableCallerDeclaredFindingLifecycle()
    adversarial_results: list[dict[str, Any]] = []
    vulnerable_success = 0
    hardened_success = 0

    for name, expected_reason, overrides in adversarial_cases():
        corpus = overrides.get("corpus", base["corpus"])
        registry = overrides.get("registry", base["registry"])
        policy = overrides.get("policy", base["policy"])
        previous = overrides.get("previous", base["previous"])
        proposed = overrides.get("proposed", base["proposed"])
        retest = overrides.get("retest", base["retest"])
        request = overrides.get("request", base["request"])

        vulnerable_result = vulnerable.transition(
            finding_id=proposed.finding_id,
            declared_status="closed",
            declared_retest_passed=True,
        )
        if vulnerable_result.accepted:
            vulnerable_success += 1

        actual_reason = None
        try:
            AdversarialFindingLifecycleGate(
                corpus=corpus,
                invariant_registry=registry,
                policy=policy,
            ).evaluate(
                request=request,
                previous=previous,
                proposed=proposed,
                retest=retest,
            )
            hardened_accepted = True
            hardened_success += 1
        except FindingLifecycleRejected as exc:
            hardened_accepted = False
            actual_reason = exc.reason.value

        adversarial_results.append(
            {
                "case": name,
                "vulnerable_accepted": vulnerable_result.accepted,
                "hardened_accepted": hardened_accepted,
                "expected_reject_reason": expected_reason.value,
                "actual_reject_reason": actual_reason,
            }
        )

    benign_results: list[dict[str, Any]] = []
    false_positives = 0
    safe_success = 0
    for name, overrides in benign_cases():
        try:
            verified = AdversarialFindingLifecycleGate(
                corpus=base["corpus"],
                invariant_registry=base["registry"],
                policy=base["policy"],
            ).evaluate(
                request=overrides["request"],
                previous=overrides["previous"],
                proposed=overrides["proposed"],
                retest=overrides["retest"],
            )
            accepted = True
            safe_success += 1
            transition_sha = verified.transition_evidence_sha256
        except FindingLifecycleRejected:
            accepted = False
            false_positives += 1
            transition_sha = None
        benign_results.append(
            {
                "case": name,
                "hardened_accepted": accepted,
                "transition_evidence_sha256": transition_sha,
            }
        )

    wrong_reasons = [
        item
        for item in adversarial_results
        if item["actual_reject_reason"] != item["expected_reject_reason"]
    ]
    if wrong_reasons:
        raise AssertionError(f"P6-E reject reason mismatch: {wrong_reasons}")
    if hardened_success != 0 or false_positives != 0:
        raise AssertionError("P6-E hardened evaluation did not meet zero-ASR/zero-FPR target")

    return {
        "adversarial_cases": len(adversarial_results),
        "vulnerable_asr": f"{vulnerable_success}/{len(adversarial_results)}",
        "hardened_asr": f"{hardened_success}/{len(adversarial_results)}",
        "hardened_fpr": f"{false_positives}/{len(benign_results)}",
        "safe_task_rate": f"{safe_success}/{len(benign_results)}",
        "corpus_sha256": corpus_digest(build_corpus()),
        "invariant_registry_sha256": invariant_registry_digest(build_registry(build_corpus())),
        "dataset_sha256": dataset_digest(),
        "fixture_sha256": fixture_digest(),
        "adversarial_results": adversarial_results,
        "benign_results": benign_results,
        "claim_boundary": {
            "exact_finding_scope_binding": True,
            "exact_invariant_owner_binding": True,
            "severity_non_downgrade": True,
            "release_bound_retest_closure": True,
            "caller_declared_closed_trusted": False,
            "production_ticket_integration": False,
            "production_patch_deployment": False,
            "exhaustive_finding_discovery": False,
            "network_operations": 0,
        },
    }


def main() -> None:
    print(json.dumps(run_evaluation(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
