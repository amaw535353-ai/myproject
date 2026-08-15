from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json

from aegis.training.evaluation_governance_security import EvaluationBenchmarkGovernanceAnalyzer
from aegis.training.evaluation_governance_types import *
from aegis.vulnerable.evaluation_governance import VulnerableCallerDeclaredEvaluationSafety
from evals.p9f_fixture import *


def _refresh_benchmark(benchmark: BenchmarkSourceEvidence) -> BenchmarkSourceEvidence:
    temp = replace(benchmark, snapshot_sha256="0" * 64)
    return replace(temp, snapshot_sha256=benchmark_snapshot_digest(temp))


def _manifest_with(fixture, **changes):
    manifest = fixture["manifest"]
    return replace(manifest, **changes)


def _benchmark_with(fixture, **changes):
    benchmark = replace(fixture["manifest"].benchmark, **changes)
    return _refresh_benchmark(benchmark)


def _record_variant(fixture, index: int, **changes):
    records = list(fixture["manifest"].benchmark.records)
    records[index] = replace(records[index], **changes)
    benchmark = _refresh_benchmark(replace(fixture["manifest"].benchmark, records=tuple(records)))
    return replace(fixture["manifest"], benchmark=benchmark)


def adversarial_cases() -> list[tuple[str, dict[str, object]]]:
    base = build_fixture()
    out: list[tuple[str, dict[str, object]]] = []
    m = base["manifest"]
    p9e = base["p9e"]

    # Upstream / checkpoint binding
    upstream_changes = [
        ("p9e_decision", replace(p9e, decision=CheckpointDecision.DENY)),
        ("p9e_risk", replace(p9e, risks=("synthetic-risk",))),
        ("p9e_upstream_flag", replace(p9e, upstream_p9d_bound=False)),
        ("p9e_lineage_flag", replace(p9e, checkpoint_lineage_verified=False)),
        ("p9e_state_flag", replace(p9e, checkpoint_state_integrity_verified=False)),
        ("p9e_auth_flag", replace(p9e, operation_authorization_verified=False)),
        ("p9e_rollback_flag", replace(p9e, rollback_safe=False)),
        ("p9e_caller_trust", replace(p9e, caller_declared_safety_trusted=True)),
        ("p9e_prod_store", replace(p9e, production_checkpoint_store_integrated=True)),
        ("p9e_signature_claim", replace(p9e, cryptographic_checkpoint_signature_verified=True)),
        ("p9e_resume_claim", replace(p9e, proof_of_resume_execution=True)),
        ("p9e_schema", replace(p9e, assessment_schema_version="wrong")),
        ("p9e_mode", replace(p9e, assessment_mode="wrong")),
        ("p9e_digest", replace(p9e, assessment_evidence_sha256=h("wrong-p9e"))),
        ("p9e_lineage_id", replace(p9e, lineage_id="other-lineage")),
        ("p9e_active_checkpoint", replace(p9e, active_checkpoint_id="ckpt-0400")),
    ]
    for name, assessment in upstream_changes:
        out.append((name, rebind(base, p9e=assessment)))

    # Training exposure substitution
    out.append(("manifest_upstream_digest", rebind(base, manifest=replace(m, p9e_assessment_sha256=h("other-p9e")))))
    out.append(("lineage_substitution", rebind(base, manifest=replace(m, checkpoint_lineage_id="other-lineage"))))
    out.append(("checkpoint_substitution", rebind(base, manifest=replace(m, checkpoint_id="ckpt-0400"))))
    out.append(("training_exposure_digest", rebind(base, manifest=replace(m, training_exposure_sha256=h("fake-exposure")))))
    out.append(("training_record_add", rebind(base, manifest=replace(m, training_record_ids=m.training_record_ids + ("record-99",)))))
    out.append(("training_record_remove", rebind(base, manifest=replace(m, training_record_ids=m.training_record_ids[:-1]))))
    out.append(("training_canonical_change", rebind(base, manifest=replace(m, training_canonical_fingerprint_sha256s=(h("changed"),)+m.training_canonical_fingerprint_sha256s[1:]))))
    out.append(("training_transform_change", rebind(base, manifest=replace(m, training_transform_fingerprint_sha256s=(h("changed-transform"),)+m.training_transform_fingerprint_sha256s[1:]))))

    # Benchmark source identity
    benchmark_mutations = [
        ("benchmark_id", dict(benchmark_id="other-benchmark")),
        ("benchmark_version", dict(benchmark_version="2026.08-old")),
        ("benchmark_split", dict(split="validation")),
        ("benchmark_owner", dict(owner="untrusted-owner")),
        ("benchmark_uri", dict(uri="https://example.invalid/dynamic")),
        ("benchmark_revision", dict(immutable_revision="floating-latest")),
    ]
    for name, changes in benchmark_mutations:
        b = _benchmark_with(base, **changes)
        out.append((name, rebind(base, manifest=replace(m, benchmark=b))))
    # snapshot mismatch without recomputing snapshot
    out.append(("benchmark_snapshot", rebind(base, manifest=replace(m, benchmark=replace(m.benchmark, snapshot_sha256=h("wrong-snapshot"))))))

    # Coverage/order
    b_missing = _refresh_benchmark(replace(m.benchmark, records=m.benchmark.records[:-1]))
    out.append(("record_missing", rebind(base, manifest=replace(m, benchmark=b_missing))))
    b_reordered = _refresh_benchmark(replace(m.benchmark, records=tuple(reversed(m.benchmark.records))))
    out.append(("record_reordered", rebind(base, manifest=replace(m, benchmark=b_reordered))))

    # Per-record tampering and contamination
    for i, rid in enumerate(EVAL_RECORD_IDS):
        out.append((f"payload_{rid}", rebind(base, manifest=_record_variant(base, i, payload_sha256=h(f"tampered-payload:{rid}")))))
        out.append((f"label_{rid}", rebind(base, manifest=_record_variant(base, i, label_sha256=h(f"tampered-label:{rid}")))))
        out.append((f"id_overlap_{rid}", rebind(base, manifest=_record_variant(base, i, record_id=TRAINING_RECORD_IDS[i % len(TRAINING_RECORD_IDS)]))))
        out.append((f"canonical_overlap_{rid}", rebind(base, manifest=_record_variant(base, i, canonical_fingerprint_sha256=TRAIN_CANON[i % len(TRAIN_CANON)]))))
        out.append((f"transform_overlap_{rid}", rebind(base, manifest=_record_variant(base, i, transform_fingerprint_sha256=TRAIN_TRANSFORM[i % len(TRAIN_TRANSFORM)]))))
        out.append((f"derived_{rid}", rebind(base, manifest=_record_variant(base, i, derived_from_training_record_id=TRAINING_RECORD_IDS[i % len(TRAINING_RECORD_IDS)]))))

    for name, changes in [
        ("labels_exposed", dict(labels_exposed_to_training=True)),
        ("dynamic_generation", dict(dynamic_generation=True)),
        ("external_fetch", dict(external_fetch=True)),
    ]:
        b = _benchmark_with(base, **changes)
        out.append((name, rebind(base, manifest=replace(m, benchmark=b))))

    # Protocol attacks
    proto = m.protocol
    protocol_cases = [
        ("scoring_code", replace(proto, scoring_code_sha256=h("evil-scoring"))),
        ("prompt_template", replace(proto, prompt_template_sha256=h("leaky-prompt"))),
        ("metric_remove", replace(proto, metric_ids=("accuracy",))),
        ("metric_add", replace(proto, metric_ids=proto.metric_ids + ("custom_metric",))),
        ("metric_reorder", replace(proto, metric_ids=tuple(reversed(proto.metric_ids)))),
        ("fewshot_ids", replace(proto, fewshot_example_ids=("other-fewshot",))),
        ("fewshot_digest", replace(proto, fewshot_examples_sha256=h("other-fewshot-bytes"))),
        ("fewshot_test_leak", replace(proto, fewshot_example_ids=(EVAL_RECORD_IDS[0],))),
        ("shuffle_seed", replace(proto, shuffle_seed=30)),
        ("sample_limit_small", replace(proto, sample_limit=len(EVAL_RECORD_IDS)-1)),
        ("sample_limit_large", replace(proto, sample_limit=len(EVAL_RECORD_IDS)+1)),
        ("temperature", replace(proto, temperature_milli=700)),
        ("max_output_tokens", replace(proto, max_output_tokens=1024)),
        ("network_ops", replace(proto, network_operations=1)),
    ]
    for name, p in protocol_cases:
        out.append((name, rebind(base, manifest=replace(m, protocol=p))))

    # Result / claim inflation
    result = m.result
    result_cases = [
        ("result_id", replace(result, result_id="other-result")),
        ("result_checkpoint", replace(result, checkpoint_id="ckpt-0400")),
        ("result_records_missing", replace(result, evaluated_record_ids=result.evaluated_record_ids[:-1])),
        ("result_records_reordered", replace(result, evaluated_record_ids=tuple(reversed(result.evaluated_record_ids)))),
        ("output_digest", replace(result, output_records_sha256=h("substituted-outputs"))),
        ("score_inflation", replace(result, score_basis_points=9999)),
        ("score_deflation", replace(result, score_basis_points=1000)),
    ]
    for name, r in result_cases:
        out.append((name, rebind(base, manifest=replace(m, result=r))))

    # Request replay / declaration substitution
    request_cases = [
        ("request_checkpoint", dict(declared_checkpoint_id="ckpt-0400")),
        ("request_benchmark_id", dict(declared_benchmark_id="other-benchmark")),
        ("request_version", dict(declared_benchmark_version="old")),
        ("request_split", dict(declared_benchmark_split="validation")),
        ("request_records", dict(declared_evaluated_record_ids=EVAL_RECORD_IDS[:-1])),
        ("request_score", dict(declared_score_basis_points=9999)),
        ("request_stale", dict(evaluated_at_epoch=NOW+301)),
        ("request_too_early", dict(evaluated_at_epoch=NOW-6)),
    ]
    for name, updates in request_cases:
        out.append((name, rebind(base, **updates)))

    return out


def clean_cases() -> list[dict[str, object]]:
    base = build_fixture()
    return [rebind(base, evaluated_at_epoch=NOW + offset) for offset in range(4)]


def _is_hardened_allowed(case: dict[str, object]) -> bool:
    analyzer = EvaluationBenchmarkGovernanceAnalyzer(case["policy"])
    try:
        assessment = analyzer.evaluate(case["request"], case["manifest"], case["p9e"])
    except EvaluationSecurityRejected:
        return False
    return assessment.decision == EvaluationDecision.ALLOW and assessment.performance_claim_admissible


def run() -> dict[str, object]:
    attacks = adversarial_cases()
    vulnerable = VulnerableCallerDeclaredEvaluationSafety()
    vulnerable_success = sum(1 for _, case in attacks if vulnerable.evaluate(case["request"]))
    hardened_success = sum(1 for _, case in attacks if _is_hardened_allowed(case))
    safe_cases = clean_cases()
    safe_failures = sum(1 for case in safe_cases if not _is_hardened_allowed(case))
    clean = build_fixture()
    clean_assessment = EvaluationBenchmarkGovernanceAnalyzer(clean["policy"]).evaluate(
        clean["request"], clean["manifest"], clean["p9e"]
    )
    attack_names = [name for name, _ in attacks]
    adversarial_dataset_sha = hashlib.sha256(
        json.dumps(attack_names, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    fixture_evidence_sha = hashlib.sha256(
        json.dumps(
            {
                "evaluation_id": EVALUATION_ID,
                "training_records": TRAINING_RECORD_IDS,
                "eval_records": EVAL_RECORD_IDS,
                "attacks": attack_names,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "tests_expected_separate": True,
        "adversarial_cases": len(attacks),
        "vulnerable_success": vulnerable_success,
        "hardened_success": hardened_success,
        "safe_cases": len(safe_cases),
        "safe_failures": safe_failures,
        "manifest_sha256": evaluation_benchmark_manifest_digest(clean["manifest"]),
        "adversarial_dataset_sha256": adversarial_dataset_sha,
        "fixture_evaluator_evidence_sha256": fixture_evidence_sha,
        "clean_assessment_sha256": clean_assessment.assessment_evidence_sha256,
    }


def main() -> int:
    result = run()
    print(f"adversarial_cases: {result['adversarial_cases']}")
    print(f"vulnerable ASR: {result['vulnerable_success']}/{result['adversarial_cases']}")
    print(f"hardened ASR: {result['hardened_success']}/{result['adversarial_cases']}")
    print(f"hardened FPR: {result['safe_failures']}/{result['safe_cases']}")
    print(f"SafeTaskRate: {result['safe_cases']-result['safe_failures']}/{result['safe_cases']}")
    print(f"evaluation benchmark manifest SHA-256: {result['manifest_sha256']}")
    print(f"adversarial dataset SHA-256: {result['adversarial_dataset_sha256']}")
    print(f"fixture/evaluator evidence SHA-256: {result['fixture_evaluator_evidence_sha256']}")
    print(f"clean assessment SHA-256: {result['clean_assessment_sha256']}")
    return 0 if result["hardened_success"] == 0 and result["safe_failures"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
