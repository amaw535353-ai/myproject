from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any

from aegis.assurance.corpus_evolution import (
    AssuranceCorpusEvolutionGate,
    CaseTombstone,
    CorpusChangeManifest,
    CorpusChangeRecord,
    CorpusChangeType,
    CorpusEvolutionPolicy,
    CorpusEvolutionRejectReason,
    CorpusEvolutionRejected,
    CorpusEvolutionRequest,
    CoverageFloor,
    change_manifest_digest,
)
from aegis.assurance.regression import (
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    case_definition_digest,
    corpus_digest,
)
from aegis.vulnerable.corpus_evolution import VulnerableSelfReportedCorpusEvolutionGate

PRIMARY_OWNER = "assurance-corpus-owner"
SECONDARY_OWNER = "security-research-owner"


def build_baseline_corpus() -> AssuranceCorpus:
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
    return AssuranceCorpus(corpus_id="aegisdesk-cross-boundary-security-corpus", version="2026.08-p6a.1", cases=cases)


def default_policy(baseline: AssuranceCorpus) -> CorpusEvolutionPolicy:
    by_boundary: dict[str, list[AssuranceCase]] = {}
    for case in baseline.cases:
        if case.expectation == AssuranceExpectation.BLOCK:
            by_boundary.setdefault(case.boundary, []).append(case)
    floors = tuple(CoverageFloor(boundary, len(cases), len(cases)) for boundary, cases in sorted(by_boundary.items()))
    return CorpusEvolutionPolicy(
        expected_baseline_corpus_id=baseline.corpus_id,
        expected_baseline_corpus_sha256=corpus_digest(baseline),
        trusted_change_owner_ids=frozenset({PRIMARY_OWNER, SECONDARY_OWNER}),
        coverage_floors=floors,
        min_critical_block_cases=7,
        min_high_or_critical_block_cases=15,
        min_allow_cases=3,
    )


def manifest_for(baseline: AssuranceCorpus, candidate: AssuranceCorpus, *, owner_id: str = PRIMARY_OWNER, replacements: dict[str, tuple[str, ...]] | None = None) -> CorpusChangeManifest:
    replacements = replacements or {}
    old = {case.case_id: case for case in baseline.cases}
    new = {case.case_id: case for case in candidate.cases}
    changes: list[CorpusChangeRecord] = []
    tombstones: list[CaseTombstone] = []
    for case_id in sorted(set(new) - set(old)):
        changes.append(CorpusChangeRecord(f"add-{case_id}", CorpusChangeType.ADD, case_id, owner_id, "explicit addition", new_case_definition_sha256=case_definition_digest(new[case_id])))
    for case_id in sorted(set(old) & set(new)):
        if case_definition_digest(old[case_id]) != case_definition_digest(new[case_id]):
            changes.append(CorpusChangeRecord(f"modify-{case_id}", CorpusChangeType.MODIFY, case_id, owner_id, "explicit modification", old_case_definition_sha256=case_definition_digest(old[case_id]), new_case_definition_sha256=case_definition_digest(new[case_id])))
    for case_id in sorted(set(old) - set(new)):
        replacement_ids = replacements.get(case_id, ())
        changes.append(CorpusChangeRecord(f"deprecate-{case_id}", CorpusChangeType.DEPRECATE, case_id, owner_id, "explicit deprecation", old_case_definition_sha256=case_definition_digest(old[case_id]), replacement_case_ids=replacement_ids))
        tombstones.append(CaseTombstone(case_id, case_definition_digest(old[case_id]), old[case_id].boundary, old[case_id].severity, old[case_id].expectation, candidate.version, replacement_ids))
    return CorpusChangeManifest(corpus_digest(baseline), corpus_digest(candidate), tuple(changes), tuple(tombstones))


def request_for(candidate: AssuranceCorpus, manifest: CorpusChangeManifest) -> CorpusEvolutionRequest:
    return CorpusEvolutionRequest(candidate.corpus_id, candidate.version, corpus_digest(candidate), change_manifest_digest(manifest))


def scenario(baseline: AssuranceCorpus, candidate: AssuranceCorpus, manifest: CorpusChangeManifest, policy: CorpusEvolutionPolicy, request: CorpusEvolutionRequest | None = None) -> dict[str, Any]:
    return {"baseline": baseline, "candidate": candidate, "manifest": manifest, "policy": policy, "request": request or request_for(candidate, manifest)}


def default_fixture() -> dict[str, Any]:
    baseline = build_baseline_corpus()
    extra = AssuranceCase("P6C-C19", "p5f-model-scanning", "scan-evidence-replay", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "new-explicit-case")
    candidate = replace(baseline, version="2026.08-p6c.1", cases=baseline.cases + (extra,))
    manifest = manifest_for(baseline, candidate)
    return scenario(baseline, candidate, manifest, default_policy(baseline))


def adversarial_cases() -> list[tuple[str, CorpusEvolutionRejectReason, dict[str, Any]]]:
    base = default_fixture()
    b, c, m, p, r = (base[k] for k in ("baseline", "candidate", "manifest", "policy", "request"))
    old = {case.case_id: case for case in b.cases}

    modified_case = replace(old["P6A-C07"], invariant="updated-invariant")
    modified = replace(b, version="2026.08-p6c-mod", cases=tuple(modified_case if x.case_id == "P6A-C07" else x for x in b.cases))
    modified_manifest = manifest_for(b, modified)
    weakened_case = replace(old["P6A-C07"], expectation=AssuranceExpectation.ALLOW)
    weakened = replace(b, version="2026.08-p6c-weaken", cases=tuple(weakened_case if x.case_id == "P6A-C07" else x for x in b.cases))
    weakened_manifest = manifest_for(b, weakened)
    downgraded_case = replace(old["P6A-C07"], severity=AssuranceSeverity.MEDIUM)
    downgraded = replace(b, version="2026.08-p6c-down", cases=tuple(downgraded_case if x.case_id == "P6A-C07" else x for x in b.cases))
    downgraded_manifest = manifest_for(b, downgraded)
    moved_case = replace(old["P6A-C07"], boundary="p5g-model-privacy")
    moved = replace(b, version="2026.08-p6c-move", cases=tuple(moved_case if x.case_id == "P6A-C07" else x for x in b.cases))
    moved_manifest = manifest_for(b, moved)
    reclass_case = replace(old["P6A-C07"], attack_class="different-class")
    reclassed = replace(b, version="2026.08-p6c-class", cases=tuple(reclass_case if x.case_id == "P6A-C07" else x for x in b.cases))
    reclass_manifest = manifest_for(b, reclassed)
    removed = replace(b, version="2026.08-p6c-remove", cases=tuple(x for x in b.cases if x.case_id != "P6A-C03"))
    removed_manifest = manifest_for(b, removed)

    bad_new = AssuranceCase("P6C-BAD", "p5c-registry-acquisition", "benign-replacement", AssuranceSeverity.HIGH, AssuranceExpectation.ALLOW, "not-blocking")
    bad_replacement = replace(b, version="2026.08-p6c-bad", cases=tuple(x for x in b.cases if x.case_id != "P6A-C03") + (bad_new,))
    bad_replacement_manifest = manifest_for(b, bad_replacement, replacements={"P6A-C03": ("P6C-BAD",)})

    shared_new = AssuranceCase("P6C-P5E", "p5e-runtime-isolation", "combined-case", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "one-replacement")
    floor_candidate = replace(b, version="2026.08-p6c-floor", cases=tuple(x for x in b.cases if x.case_id not in {"P6A-C05", "P6A-C06"}) + (shared_new,))
    floor_manifest = manifest_for(b, floor_candidate, replacements={"P6A-C05": ("P6C-P5E",), "P6A-C06": ("P6C-P5E",)})
    safe_floor = replace(b, version="2026.08-p6c-safe", cases=tuple(x for x in b.cases if x.case_id != "P6A-C16"))
    safe_floor_manifest = manifest_for(b, safe_floor)
    duplicate = replace(c, version="2026.08-p6c-dup", cases=c.cases + (c.cases[-1],))
    duplicate_manifest = replace(m, candidate_corpus_sha256=corpus_digest(duplicate))
    add = m.changes[0]
    mod = modified_manifest.changes[0]

    return [
        ("A01 baseline digest", CorpusEvolutionRejectReason.BASELINE_DIGEST_MISMATCH, scenario(b, c, m, replace(p, expected_baseline_corpus_sha256="0"*64), r)),
        ("A02 candidate digest", CorpusEvolutionRejectReason.CANDIDATE_IDENTITY_MISMATCH, scenario(b, c, m, p, replace(r, candidate_corpus_sha256="1"*64))),
        ("A03 version reuse", CorpusEvolutionRejectReason.VERSION_NOT_ADVANCED, scenario(b, replace(c, version=b.version), manifest_for(b, replace(c, version=b.version)), p)),
        ("A04 manifest digest", CorpusEvolutionRejectReason.MANIFEST_DIGEST_MISMATCH, scenario(b, c, m, p, replace(r, change_manifest_sha256="2"*64))),
        ("A05 silent add", CorpusEvolutionRejectReason.CHANGE_COVERAGE_MISMATCH, scenario(b, c, replace(m, changes=()), p)),
        ("A06 silent modify", CorpusEvolutionRejectReason.CHANGE_COVERAGE_MISMATCH, scenario(b, modified, replace(modified_manifest, changes=()), p)),
        ("A07 silent remove", CorpusEvolutionRejectReason.CHANGE_COVERAGE_MISMATCH, scenario(b, removed, replace(removed_manifest, changes=()), p)),
        ("A08 duplicate change", CorpusEvolutionRejectReason.CHANGE_DUPLICATE, scenario(b, c, replace(m, changes=m.changes + (replace(add, change_id="duplicate"),)), p)),
        ("A09 untrusted owner", CorpusEvolutionRejectReason.CHANGE_OWNER_UNTRUSTED, scenario(b, c, replace(m, changes=(replace(add, owner_id="untrusted"),)), p)),
        ("A10 add digest", CorpusEvolutionRejectReason.CHANGE_DEFINITION_MISMATCH, scenario(b, c, replace(m, changes=(replace(add, new_case_definition_sha256="3"*64),)), p)),
        ("A11 modify digest", CorpusEvolutionRejectReason.CHANGE_DEFINITION_MISMATCH, scenario(b, modified, replace(modified_manifest, changes=(replace(mod, old_case_definition_sha256="4"*64),)), p)),
        ("A12 expectation weakening", CorpusEvolutionRejectReason.EXPECTATION_WEAKENED, scenario(b, weakened, weakened_manifest, p)),
        ("A13 severity downgrade", CorpusEvolutionRejectReason.SEVERITY_DOWNGRADED, scenario(b, downgraded, downgraded_manifest, p)),
        ("A14 boundary reclass", CorpusEvolutionRejectReason.BOUNDARY_RECLASSIFIED, scenario(b, moved, moved_manifest, p)),
        ("A15 class reclass", CorpusEvolutionRejectReason.ATTACK_CLASS_RECLASSIFIED, scenario(b, reclassed, reclass_manifest, p)),
        ("A16 tombstone omission", CorpusEvolutionRejectReason.TOMBSTONE_MISSING, scenario(b, removed, replace(removed_manifest, tombstones=()), p)),
        ("A17 tombstone substitution", CorpusEvolutionRejectReason.TOMBSTONE_INVALID, scenario(b, removed, replace(removed_manifest, tombstones=(replace(removed_manifest.tombstones[0], case_definition_sha256="5"*64),)), p)),
        ("A18 missing replacement", CorpusEvolutionRejectReason.REPLACEMENT_REQUIRED, scenario(b, removed, removed_manifest, p)),
        ("A19 invalid replacement", CorpusEvolutionRejectReason.REPLACEMENT_INVALID, scenario(b, bad_replacement, bad_replacement_manifest, p)),
        ("A20 boundary floor", CorpusEvolutionRejectReason.COVERAGE_FLOOR_VIOLATED, scenario(b, floor_candidate, floor_manifest, p)),
        ("A21 safe-task floor", CorpusEvolutionRejectReason.COVERAGE_FLOOR_VIOLATED, scenario(b, safe_floor, safe_floor_manifest, p)),
        ("A22 duplicate candidate case", CorpusEvolutionRejectReason.CANDIDATE_INVALID, scenario(b, duplicate, duplicate_manifest, p)),
    ]


def benign_cases() -> list[tuple[str, dict[str, Any]]]:
    b = build_baseline_corpus()
    p = default_policy(b)
    old = {case.case_id: case for case in b.cases}
    extra = AssuranceCase("P6C-C19", "p5f-model-scanning", "scan-evidence-replay", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "new-explicit-case")
    c1 = replace(b, version="2026.08-p6c.1", cases=b.cases + (extra,))
    m1 = manifest_for(b, c1)
    mod = replace(old["P6A-C07"], invariant="clarified-invariant")
    c2 = replace(b, version="2026.08-p6c.2", cases=tuple(mod if x.case_id == "P6A-C07" else x for x in b.cases))
    m2 = manifest_for(b, c2, owner_id=SECONDARY_OWNER)
    replacement = AssuranceCase("P6C-C19-R", "p5c-registry-acquisition", "immutable-alias", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "replacement-case")
    c3 = replace(b, version="2026.08-p6c.3", cases=tuple(x for x in b.cases if x.case_id != "P6A-C03") + (replacement,))
    m3 = manifest_for(b, c3, replacements={"P6A-C03": ("P6C-C19-R",)})
    return [("B1 explicit add", scenario(b, c1, m1, p)), ("B2 non-weakening modify", scenario(b, c2, m2, p)), ("B3 deprecate with replacement", scenario(b, c3, m3, p))]


def _serializable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, frozenset):
        return sorted(value)
    if isinstance(value, tuple):
        return [_serializable(item) for item in value]
    if isinstance(value, dict):
        return {key: _serializable(item) for key, item in sorted(value.items())}
    if hasattr(value, "__dataclass_fields__"):
        return {key: _serializable(item) for key, item in asdict(value).items()}
    return value


def fixture_digest() -> str:
    f = default_fixture()
    doc = {key: _serializable(value) for key, value in sorted(f.items())}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def dataset_digest() -> str:
    doc = {"adversarial": [{"name": n, "reason": r.value} for n, r, _ in adversarial_cases()], "benign": [n for n, _ in benign_cases()]}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_evaluation() -> dict[str, Any]:
    vulnerable = VulnerableSelfReportedCorpusEvolutionGate()
    adversarial_results = []
    vulnerable_success = hardened_success = 0
    for name, expected_reason, s in adversarial_cases():
        vuln_ok = vulnerable.evaluate(declared_coverage_ok=True, declared_untracked_changes=0).accepted
        vulnerable_success += int(vuln_ok)
        actual = None
        try:
            AssuranceCorpusEvolutionGate(policy=s["policy"]).evaluate(request=s["request"], baseline=s["baseline"], candidate=s["candidate"], manifest=s["manifest"])
            hard_ok = True
            hardened_success += 1
        except CorpusEvolutionRejected as exc:
            hard_ok = False
            actual = exc.reason.value
        adversarial_results.append({"case": name, "vulnerable_accepted": vuln_ok, "hardened_accepted": hard_ok, "expected_reject_reason": expected_reason.value, "actual_reject_reason": actual})

    benign_results = []
    false_positive = safe_success = 0
    for name, s in benign_cases():
        try:
            verified = AssuranceCorpusEvolutionGate(policy=s["policy"]).evaluate(request=s["request"], baseline=s["baseline"], candidate=s["candidate"], manifest=s["manifest"])
            accepted, evidence = True, verified.evidence_sha256
            safe_success += 1
        except CorpusEvolutionRejected:
            accepted, evidence = False, None
            false_positive += 1
        benign_results.append({"case": name, "hardened_accepted": accepted, "evidence_sha256": evidence})

    n = len(adversarial_results)
    return {
        "metrics": {"adversarial_cases": n, "vulnerable_asr": f"{vulnerable_success}/{n}", "hardened_asr": f"{hardened_success}/{n}", "hardened_fpr": f"{false_positive}/3", "safe_task_rate": f"{safe_success}/3"},
        "baseline_corpus_sha256": corpus_digest(build_baseline_corpus()),
        "dataset_sha256": dataset_digest(),
        "fixture_sha256": fixture_digest(),
        "adversarial_results": adversarial_results,
        "benign_results": benign_results,
        "claim_boundary": {"exact_change_record_coverage": True, "nonweakening_modification": True, "removal_tombstones": True, "replacement_requirement": True, "coverage_floors": True, "formal_verification": False, "exhaustive_attack_coverage": False, "production_change_management": False, "network_operations": 0},
    }


def main() -> int:
    result = run_evaluation()
    print(json.dumps(result, sort_keys=True, indent=2))
    n = len(adversarial_cases())
    expected = {"vulnerable_asr": f"{n}/{n}", "hardened_asr": f"0/{n}", "hardened_fpr": "0/3", "safe_task_rate": "3/3"}
    return 0 if all(result["metrics"][key] == value for key, value in expected.items()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
