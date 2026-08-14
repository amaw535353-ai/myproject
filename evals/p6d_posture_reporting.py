from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any

from aegis.assurance.corpus_evolution import VerifiedCorpusEvolution
from aegis.assurance.posture_reporting import (
    AISecurityPostureReporter,
    PostureRating,
    PostureRejectReason,
    SecurityControlCatalog,
    SecurityControlObjective,
    SecurityPosturePolicy,
    SecurityPostureRejected,
    SecurityPostureRequest,
    control_catalog_digest,
)
from aegis.assurance.regression import (
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    corpus_digest,
)
from aegis.assurance.waiver_governance import VerifiedWaiverGovernance
from aegis.vulnerable.posture_reporting import VulnerableDeclaredPostureReporter


RELEASE_ID = "aegisdesk-v0.58.0"
COMMIT_SHA = "d" * 64
PACKAGE_VERSION = "0.58.0"
WAIVER_EVIDENCE_SHA256 = "a" * 64
EVOLUTION_EVIDENCE_SHA256 = "b" * 64
REGISTRY_SHA256 = "c" * 64
CANDIDATE_EVIDENCE_SHA256 = "e" * 64
CHANGE_MANIFEST_SHA256 = "f" * 64


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
        version="2026.08-p6d.1",
        cases=cases,
    )


def build_catalog() -> SecurityControlCatalog:
    controls = (
        SecurityControlObjective(
            "AISC-SUPPLY-CHAIN",
            "model-supply-chain",
            "Model artifacts, packages, registries, and signing keys remain release-bound",
            AssuranceSeverity.CRITICAL,
            ("P6A-C01", "P6A-C02", "P6A-C03", "P6A-C04"),
            ("p5a-artifact-provenance", "p5b-package-provenance", "p5c-registry-acquisition", "p5d-key-lifecycle"),
            False,
        ),
        SecurityControlObjective(
            "AISC-RUNTIME",
            "runtime-isolation",
            "Model runtime admission denies remote code and host capability escalation",
            AssuranceSeverity.CRITICAL,
            ("P6A-C05", "P6A-C06"),
            ("p5e-runtime-isolation",),
            False,
        ),
        SecurityControlObjective(
            "AISC-MODEL-INTEGRITY",
            "model-integrity",
            "Poisoning and backdoor indicators remain release-scoped and gated",
            AssuranceSeverity.HIGH,
            ("P6A-C07", "P6A-C08"),
            ("p5f-model-scanning",),
            True,
        ),
        SecurityControlObjective(
            "AISC-PRIVACY",
            "model-privacy",
            "High-information extraction and modeled training leakage remain bounded",
            AssuranceSeverity.CRITICAL,
            ("P6A-C09", "P6A-C10"),
            ("p5g-model-privacy",),
            False,
        ),
        SecurityControlObjective(
            "AISC-DEPLOYMENT",
            "deployment-attestation",
            "Deployment admission remains bound to fresh measured environment evidence",
            AssuranceSeverity.CRITICAL,
            ("P6A-C11", "P6A-C12"),
            ("p5h-deployment-attestation",),
            False,
        ),
        SecurityControlObjective(
            "AISC-SERVING-RESPONSE",
            "serving-security-operations",
            "Serving telemetry remains chained and abuse response remains policy-owned",
            AssuranceSeverity.HIGH,
            ("P6A-C13", "P6A-C14", "P6A-C15"),
            ("p5i-serving-response",),
            True,
        ),
        SecurityControlObjective(
            "AISC-SAFE-RUNTIME",
            "safe-task-utility",
            "Benign static runtime plans remain usable",
            AssuranceSeverity.LOW,
            ("P6A-C16",),
            ("p5e-runtime-isolation",),
            True,
        ),
        SecurityControlObjective(
            "AISC-SAFE-PRIVACY",
            "safe-task-utility",
            "Bounded privacy-safe inference remains usable",
            AssuranceSeverity.LOW,
            ("P6A-C17",),
            ("p5g-model-privacy",),
            True,
        ),
        SecurityControlObjective(
            "AISC-SAFE-TELEMETRY",
            "safe-task-utility",
            "Benign serving telemetry remains non-disruptive",
            AssuranceSeverity.LOW,
            ("P6A-C18",),
            ("p5i-serving-response",),
            True,
        ),
    )
    return SecurityControlCatalog(
        catalog_id="aegisdesk-ai-security-control-catalog",
        version="2026.08-p6d.1",
        controls=controls,
    )


def upstream_for(
    corpus: AssuranceCorpus,
    *,
    regression_case_ids: tuple[str, ...] = (),
    waived_case_ids: tuple[str, ...] = (),
    waiver_ids: tuple[str, ...] = (),
    high_waiver_count: int = 0,
    medium_waiver_count: int = 0,
    low_waiver_count: int = 0,
    critical_waiver_count: int = 0,
    critical_waivers_permitted: bool = False,
) -> tuple[VerifiedWaiverGovernance, VerifiedCorpusEvolution]:
    sha = corpus_digest(corpus)
    block_cases = [case for case in corpus.cases if case.expectation == AssuranceExpectation.BLOCK]
    allow_cases = [case for case in corpus.cases if case.expectation == AssuranceExpectation.ALLOW]
    critical = sum(case.severity == AssuranceSeverity.CRITICAL for case in block_cases)
    high_or_critical = sum(
        case.severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL}
        for case in block_cases
    )
    waiver = VerifiedWaiverGovernance(
        candidate_release_id=RELEASE_ID,
        candidate_commit_sha=COMMIT_SHA,
        candidate_package_version=PACKAGE_VERSION,
        corpus_sha256=sha,
        registry_sha256=REGISTRY_SHA256,
        candidate_evidence_sha256=CANDIDATE_EVIDENCE_SHA256,
        regression_case_ids=regression_case_ids,
        approved_waiver_ids=waiver_ids,
        approved_waived_case_ids=waived_case_ids,
        waiver_count=len(waived_case_ids),
        high_waiver_count=high_waiver_count,
        medium_waiver_count=medium_waiver_count,
        low_waiver_count=low_waiver_count,
        critical_waiver_count=critical_waiver_count,
        earliest_expiry_epoch=1_900_000_000 if waived_case_ids else None,
        governance_evidence_sha256=WAIVER_EVIDENCE_SHA256,
        critical_waivers_permitted=critical_waivers_permitted,
    )
    evolution = VerifiedCorpusEvolution(
        corpus_id=corpus.corpus_id,
        baseline_version="2026.08-p6c.0",
        candidate_version=corpus.version,
        baseline_corpus_sha256="1" * 64,
        candidate_corpus_sha256=sha,
        change_manifest_sha256=CHANGE_MANIFEST_SHA256,
        added_case_ids=(),
        modified_case_ids=(),
        deprecated_case_ids=(),
        tombstoned_case_ids=(),
        candidate_case_count=len(corpus.cases),
        candidate_block_case_count=len(block_cases),
        candidate_allow_case_count=len(allow_cases),
        candidate_critical_block_count=critical,
        candidate_high_or_critical_block_count=high_or_critical,
        evidence_sha256=EVOLUTION_EVIDENCE_SHA256,
    )
    return waiver, evolution


def default_fixture() -> dict[str, Any]:
    corpus = build_corpus()
    catalog = build_catalog()
    waiver, evolution = upstream_for(corpus)
    policy = SecurityPosturePolicy(
        expected_control_catalog_sha256=control_catalog_digest(catalog),
        required_control_ids=frozenset(control.control_id for control in catalog.controls),
        required_risk_domains=frozenset(control.risk_domain for control in catalog.controls),
    )
    request = SecurityPostureRequest(
        candidate_release_id=RELEASE_ID,
        candidate_commit_sha=COMMIT_SHA,
        candidate_package_version=PACKAGE_VERSION,
        corpus_sha256=corpus_digest(corpus),
        control_catalog_sha256=control_catalog_digest(catalog),
        waiver_governance_evidence_sha256=waiver.governance_evidence_sha256,
        corpus_evolution_evidence_sha256=evolution.evidence_sha256,
        declared_rating=PostureRating.GREEN,
    )
    return {
        "corpus": corpus,
        "catalog": catalog,
        "policy": policy,
        "request": request,
        "waiver": waiver,
        "evolution": evolution,
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
        "catalog": _serializable(fixture["catalog"]),
        "policy": _serializable(fixture["policy"]),
        "request": _serializable(fixture["request"]),
        "corpus_sha256": corpus_digest(fixture["corpus"]),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _request_for(
    *,
    corpus: AssuranceCorpus,
    catalog: SecurityControlCatalog,
    waiver: VerifiedWaiverGovernance,
    evolution: VerifiedCorpusEvolution,
    declared_rating: PostureRating = PostureRating.GREEN,
) -> SecurityPostureRequest:
    return SecurityPostureRequest(
        candidate_release_id=waiver.candidate_release_id,
        candidate_commit_sha=waiver.candidate_commit_sha,
        candidate_package_version=waiver.candidate_package_version,
        corpus_sha256=corpus_digest(corpus),
        control_catalog_sha256=control_catalog_digest(catalog),
        waiver_governance_evidence_sha256=waiver.governance_evidence_sha256,
        corpus_evolution_evidence_sha256=evolution.evidence_sha256,
        declared_rating=declared_rating,
    )


def adversarial_cases() -> list[tuple[str, PostureRejectReason, dict[str, Any]]]:
    base = default_fixture()
    corpus: AssuranceCorpus = base["corpus"]
    catalog: SecurityControlCatalog = base["catalog"]
    policy: SecurityPosturePolicy = base["policy"]
    request: SecurityPostureRequest = base["request"]
    waiver: VerifiedWaiverGovernance = base["waiver"]
    evolution: VerifiedCorpusEvolution = base["evolution"]

    mutated_control = replace(catalog.controls[0], title="caller-mutated control title")
    mutated_catalog = replace(catalog, controls=(mutated_control,) + catalog.controls[1:])
    duplicate_catalog = replace(catalog, controls=catalog.controls + (catalog.controls[0],))
    bad_mapping_control = replace(catalog.controls[0], mapped_case_ids=("P6A-C01", "P6A-C01"))
    bad_mapping_catalog = replace(catalog, controls=(bad_mapping_control,) + catalog.controls[1:])
    removed_control_catalog = replace(catalog, controls=catalog.controls[1:])
    removed_control_policy = replace(
        policy,
        expected_control_catalog_sha256=control_catalog_digest(removed_control_catalog),
    )
    no_supply_controls = tuple(
        control for control in catalog.controls if control.risk_domain != "model-supply-chain"
    )
    no_supply_catalog = replace(catalog, controls=no_supply_controls)
    no_supply_policy = replace(
        policy,
        expected_control_catalog_sha256=control_catalog_digest(no_supply_catalog),
        required_control_ids=frozenset(control.control_id for control in no_supply_catalog.controls),
    )

    high_waiver, high_evolution = upstream_for(
        corpus,
        regression_case_ids=("P6A-C13",),
        waived_case_ids=("P6A-C13",),
        waiver_ids=("W-HIGH-1",),
        high_waiver_count=1,
    )
    high_request = _request_for(
        corpus=corpus,
        catalog=catalog,
        waiver=high_waiver,
        evolution=high_evolution,
        declared_rating=PostureRating.GREEN,
    )

    critical_waiver, critical_evolution = upstream_for(
        corpus,
        regression_case_ids=("P6A-C01",),
        waived_case_ids=("P6A-C01",),
        waiver_ids=("W-CRIT-1",),
        critical_waiver_count=1,
        critical_waivers_permitted=True,
    )
    critical_request = _request_for(
        corpus=corpus,
        catalog=catalog,
        waiver=critical_waiver,
        evolution=critical_evolution,
        declared_rating=PostureRating.GREEN,
    )

    reduced_corpus = replace(
        corpus,
        cases=tuple(case for case in corpus.cases if case.case_id != "P6A-C05"),
    )
    reduced_waiver, reduced_evolution = upstream_for(reduced_corpus)
    reduced_request = _request_for(
        corpus=reduced_corpus,
        catalog=catalog,
        waiver=reduced_waiver,
        evolution=reduced_evolution,
        declared_rating=PostureRating.GREEN,
    )

    removed_scan_corpus = replace(
        corpus,
        cases=tuple(
            case for case in corpus.cases
            if case.boundary != "p5f-model-scanning"
        ),
    )
    scan_waiver, scan_evolution = upstream_for(removed_scan_corpus)
    scan_request = _request_for(
        corpus=removed_scan_corpus,
        catalog=catalog,
        waiver=scan_waiver,
        evolution=scan_evolution,
        declared_rating=PostureRating.GREEN,
    )

    return [
        ("P6D-A01 policy catalog digest substitution", PostureRejectReason.CATALOG_DIGEST_MISMATCH, {"policy": replace(policy, expected_control_catalog_sha256="0" * 64)}),
        ("P6D-A02 control catalog content substitution", PostureRejectReason.CATALOG_DIGEST_MISMATCH, {"catalog": mutated_catalog}),
        ("P6D-A03 duplicate control ID", PostureRejectReason.CONTROL_DUPLICATE, {"catalog": duplicate_catalog}),
        ("P6D-A04 duplicate mapped case", PostureRejectReason.CONTROL_MAPPING_INVALID, {"catalog": bad_mapping_catalog}),
        ("P6D-A05 required control omission", PostureRejectReason.REQUIRED_CONTROL_MISSING, {"catalog": removed_control_catalog, "policy": removed_control_policy}),
        ("P6D-A06 required risk-domain omission", PostureRejectReason.REQUIRED_RISK_DOMAIN_MISSING, {"catalog": no_supply_catalog, "policy": no_supply_policy}),
        ("P6D-A07 request release substitution", PostureRejectReason.RELEASE_IDENTITY_MISMATCH, {"request": replace(request, candidate_release_id="wrong-release")}),
        ("P6D-A08 request commit substitution", PostureRejectReason.RELEASE_IDENTITY_MISMATCH, {"request": replace(request, candidate_commit_sha="2" * 64)}),
        ("P6D-A09 request package-version substitution", PostureRejectReason.RELEASE_IDENTITY_MISMATCH, {"request": replace(request, candidate_package_version="9.9.9")}),
        ("P6D-A10 request corpus digest substitution", PostureRejectReason.CORPUS_DIGEST_MISMATCH, {"request": replace(request, corpus_sha256="3" * 64)}),
        ("P6D-A11 request catalog digest substitution", PostureRejectReason.CATALOG_DIGEST_MISMATCH, {"request": replace(request, control_catalog_sha256="4" * 64)}),
        ("P6D-A12 request waiver-evidence substitution", PostureRejectReason.EVIDENCE_BINDING_MISMATCH, {"request": replace(request, waiver_governance_evidence_sha256="5" * 64)}),
        ("P6D-A13 request evolution-evidence substitution", PostureRejectReason.EVIDENCE_BINDING_MISMATCH, {"request": replace(request, corpus_evolution_evidence_sha256="6" * 64)}),
        ("P6D-A14 degraded waiver verification flag", PostureRejectReason.WAIVER_GOVERNANCE_UNVERIFIED, {"waiver": replace(waiver, expiry_verified=False)}),
        ("P6D-A15 waiver corpus substitution", PostureRejectReason.EVIDENCE_BINDING_MISMATCH, {"waiver": replace(waiver, corpus_sha256="7" * 64)}),
        ("P6D-A16 waived case not in regression scope", PostureRejectReason.WAIVER_SCOPE_MISMATCH, {"waiver": replace(waiver, approved_waiver_ids=("W1",), approved_waived_case_ids=("P6A-C13",), waiver_count=1, high_waiver_count=1)}),
        ("P6D-A17 waived unknown case", PostureRejectReason.WAIVER_SCOPE_MISMATCH, {"waiver": replace(waiver, regression_case_ids=("UNKNOWN",), approved_waiver_ids=("W1",), approved_waived_case_ids=("UNKNOWN",), waiver_count=1, high_waiver_count=1)}),
        ("P6D-A18 waiver summary count mismatch", PostureRejectReason.WAIVER_SCOPE_MISMATCH, {"waiver": replace(waiver, waiver_count=1)}),
        ("P6D-A19 degraded corpus-evolution flag", PostureRejectReason.CORPUS_EVOLUTION_UNVERIFIED, {"evolution": replace(evolution, coverage_floors_verified=False)}),
        ("P6D-A20 evolution candidate corpus substitution", PostureRejectReason.EVIDENCE_BINDING_MISMATCH, {"evolution": replace(evolution, candidate_corpus_sha256="8" * 64)}),
        ("P6D-A21 evolution summary count substitution", PostureRejectReason.UPSTREAM_COUNT_MISMATCH, {"evolution": replace(evolution, candidate_case_count=evolution.candidate_case_count + 1)}),
        ("P6D-A22 caller green masks high exception", PostureRejectReason.DECLARED_POSTURE_MISMATCH, {"waiver": high_waiver, "evolution": high_evolution, "request": high_request}),
        ("P6D-A23 caller green masks critical exception", PostureRejectReason.DECLARED_POSTURE_MISMATCH, {"waiver": critical_waiver, "evolution": critical_evolution, "request": critical_request}),
        ("P6D-A24 caller green masks missing critical case", PostureRejectReason.DECLARED_POSTURE_MISMATCH, {"corpus": reduced_corpus, "waiver": reduced_waiver, "evolution": reduced_evolution, "request": reduced_request}),
        ("P6D-A25 caller green masks missing high boundary", PostureRejectReason.DECLARED_POSTURE_MISMATCH, {"corpus": removed_scan_corpus, "waiver": scan_waiver, "evolution": scan_evolution, "request": scan_request}),
        ("P6D-A26 caller amber masks all-green evidence", PostureRejectReason.DECLARED_POSTURE_MISMATCH, {"request": replace(request, declared_rating=PostureRating.AMBER)}),
    ]


def benign_cases() -> list[tuple[str, dict[str, Any]]]:
    base = default_fixture()
    catalog: SecurityControlCatalog = base["catalog"]
    reordered_catalog = replace(catalog, controls=tuple(reversed(catalog.controls)))
    reordered_policy = replace(
        base["policy"],
        expected_control_catalog_sha256=control_catalog_digest(reordered_catalog),
    )
    reordered_request = replace(
        base["request"],
        control_catalog_sha256=control_catalog_digest(reordered_catalog),
    )
    no_declaration_request = replace(base["request"], declared_rating=None)
    return [
        ("P6D-B1 exact evidence-derived green posture", {}),
        ("P6D-B2 canonical control ordering independence", {"catalog": reordered_catalog, "policy": reordered_policy, "request": reordered_request}),
        ("P6D-B3 no caller-declared rating required", {"request": no_declaration_request}),
    ]


def dataset_digest() -> str:
    document = {
        "adversarial": [
            {"name": name, "reason": reason.value}
            for name, reason, _ in adversarial_cases()
        ],
        "benign": [name for name, _ in benign_cases()],
        "controls": [
            {
                "control_id": control.control_id,
                "risk_domain": control.risk_domain,
                "severity": control.severity.value,
                "mapped_case_ids": list(control.mapped_case_ids),
                "required_boundaries": list(control.required_boundaries),
            }
            for control in build_catalog().controls
        ],
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def run_evaluation() -> dict[str, Any]:
    base = default_fixture()
    vulnerable = VulnerableDeclaredPostureReporter()
    adversarial_results: list[dict[str, Any]] = []
    vulnerable_success = 0
    hardened_success = 0

    for name, expected_reason, overrides in adversarial_cases():
        corpus = overrides.get("corpus", base["corpus"])
        catalog = overrides.get("catalog", base["catalog"])
        policy = overrides.get("policy", base["policy"])
        request = overrides.get("request", base["request"])
        waiver = overrides.get("waiver", base["waiver"])
        evolution = overrides.get("evolution", base["evolution"])

        vulnerable_result = vulnerable.report(
            declared_rating=(
                request.declared_rating.value
                if isinstance(request.declared_rating, PostureRating)
                else "green"
            ),
            declared_satisfied_controls=len(catalog.controls),
            declared_exceptioned_controls=0,
            declared_not_evaluated_controls=0,
        )
        if vulnerable_result.accepted:
            vulnerable_success += 1

        actual_reason = None
        try:
            AISecurityPostureReporter(catalog=catalog, policy=policy).evaluate(
                request=request,
                corpus=corpus,
                waiver_governance=waiver,
                corpus_evolution=evolution,
            )
            hardened_accepted = True
            hardened_success += 1
        except SecurityPostureRejected as exc:
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
        corpus = overrides.get("corpus", base["corpus"])
        catalog = overrides.get("catalog", base["catalog"])
        policy = overrides.get("policy", base["policy"])
        request = overrides.get("request", base["request"])
        waiver = overrides.get("waiver", base["waiver"])
        evolution = overrides.get("evolution", base["evolution"])
        try:
            verified = AISecurityPostureReporter(catalog=catalog, policy=policy).evaluate(
                request=request,
                corpus=corpus,
                waiver_governance=waiver,
                corpus_evolution=evolution,
            )
            accepted = verified.overall_rating == PostureRating.GREEN
            if accepted:
                safe_success += 1
            else:
                false_positives += 1
        except SecurityPostureRejected:
            accepted = False
            false_positives += 1
        benign_results.append({"case": name, "hardened_accepted": accepted})

    if any(
        item["actual_reject_reason"] != item["expected_reject_reason"]
        for item in adversarial_results
    ):
        raise AssertionError("one or more P6-D adversarial cases produced the wrong reject reason")
    if hardened_success != 0 or false_positives != 0:
        raise AssertionError("P6-D hardened evaluation did not meet the deterministic zero-ASR/zero-FPR target")

    return {
        "adversarial_cases": len(adversarial_results),
        "vulnerable_asr": f"{vulnerable_success}/{len(adversarial_results)}",
        "hardened_asr": f"{hardened_success}/{len(adversarial_results)}",
        "hardened_fpr": f"{false_positives}/{len(benign_results)}",
        "safe_task_rate": f"{safe_success}/{len(benign_results)}",
        "control_catalog_sha256": control_catalog_digest(build_catalog()),
        "corpus_sha256": corpus_digest(build_corpus()),
        "dataset_sha256": dataset_digest(),
        "fixture_sha256": fixture_digest(),
        "adversarial_results": adversarial_results,
        "benign_results": benign_results,
        "claim_boundary": {
            "evidence_derived_posture": True,
            "exact_upstream_digest_binding": True,
            "missing_evidence_visibility": True,
            "exception_visibility": True,
            "regulatory_certification": False,
            "production_grc_integration": False,
            "external_audit_evidence": False,
            "network_operations": 0,
        },
    }


def main() -> None:
    print(json.dumps(run_evaluation(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
