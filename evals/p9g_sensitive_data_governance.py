from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from aegis.training.evaluation_governance_types import EvaluationDecision
from aegis.training.sensitive_data_security import SensitiveDataGovernanceAnalyzer
from aegis.training.sensitive_data_types import *
from aegis.vulnerable.sensitive_data_governance import VulnerableCallerDeclaredSensitiveDataSafety
from evals.p9g_fixture import NOW, build_fixture, finding, h, rebind


def _replace_record(manifest, record_id: str, **updates):
    records = tuple(
        replace(record, **updates) if record.record_id == record_id else record
        for record in manifest.records
    )
    return replace(manifest, records=records)


def adversarial_cases() -> list[tuple[str, dict[str, object]]]:
    base = build_fixture()
    manifest = base["manifest"]
    p9f = base["p9f"]
    cases: list[tuple[str, dict[str, object]]] = []

    def add(name: str, *, m=None, upstream=None, preserve=True, **request_updates):
        cases.append((name, rebind(
            base,
            manifest=m,
            p9f=upstream,
            preserve_declarations=preserve,
            **request_updates,
        )))

    add("upstream-decision-deny", upstream=replace(p9f, decision=EvaluationDecision.DENY))
    add("upstream-risks-present", upstream=replace(p9f, risks=("synthetic-risk",)))
    for field in (
        "upstream_p9e_bound",
        "benchmark_provenance_verified",
        "contamination_checks_clear",
        "protocol_verified",
        "result_evidence_bound",
        "performance_claim_admissible",
    ):
        add(f"upstream-flag-false:{field}", upstream=replace(p9f, **{field: False}))
    for field in (
        "production_benchmark_registry_integrated",
        "semantic_near_duplicate_detection_validated",
        "score_recomputed_from_model_outputs",
        "hidden_benchmark_secrecy_proven",
    ):
        add(f"upstream-overclaim:{field}", upstream=replace(p9f, **{field: True}))
    add("upstream-schema-mismatch", upstream=replace(p9f, assessment_schema_version="other"))
    add("upstream-mode-mismatch", upstream=replace(p9f, assessment_mode="other"))
    add("upstream-assessment-digest-swap", upstream=replace(p9f, assessment_evidence_sha256=h("other-p9f")))

    add("manifest-upstream-digest-swap", m=replace(manifest, p9f_assessment_sha256=h("swapped-p9f")))
    add("evaluation-id-swap", m=replace(manifest, evaluation_id="p9f-evaluation-evil"), preserve=False)
    add("checkpoint-id-swap", m=replace(manifest, checkpoint_id="ckpt-evil"), preserve=False)
    add("scanner-profile-swap", m=replace(manifest, scanner_profile_sha256=h("scanner:evil")))
    add("canary-registry-swap", m=replace(manifest, canary_registry_sha256=h("registry:evil")))

    add("record-order-reversed", m=replace(manifest, records=tuple(reversed(manifest.records))), preserve=False)
    add("record-dropped", m=replace(manifest, records=manifest.records[:-1]), preserve=False)
    add("record-duplicated", m=replace(manifest, records=manifest.records + (manifest.records[-1],)), preserve=False)

    surfaces = (DataSurface.TRAINING_INPUT, DataSurface.EVALUATION_INPUT, DataSurface.MODEL_OUTPUT)
    sensitivities = (SensitivityClass.PUBLIC, SensitivityClass.PERSONAL, SensitivityClass.SECRET, SensitivityClass.CANARY)
    dispositions = (DataDisposition.ALLOW, DataDisposition.REDACT, DataDisposition.QUARANTINE, DataDisposition.DENY)
    for record in manifest.records:
        alt_surface = next(v for v in surfaces if v != record.surface)
        add(f"surface-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, surface=alt_surface))
        add(f"content-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, content_sha256=h(f"evil-content:{record.record_id}")))
        add(f"sanitized-digest-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, sanitized_content_sha256=h(f"evil-sanitized:{record.record_id}")))
        alt_sensitivity = next(v for v in sensitivities if v != record.sensitivity)
        add(f"classification-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, sensitivity=alt_sensitivity))
        alt_disposition = next(v for v in dispositions if v != record.disposition)
        add(f"disposition-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, disposition=alt_disposition))
        add(f"inclusion-toggle:{record.record_id}", m=_replace_record(manifest, record.record_id, included=not record.included))

    for record in manifest.records:
        if not record.findings:
            continue
        f = record.findings[0]
        add(f"finding-removed:{record.record_id}", m=_replace_record(manifest, record.record_id, findings=()))
        alt_kind = SensitiveKind.CANARY_TOKEN if f.kind != SensitiveKind.CANARY_TOKEN else SensitiveKind.API_SECRET
        add(f"finding-kind-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, findings=(replace(f, kind=alt_kind),)))
        add(f"finding-rule-id-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, findings=(replace(f, detector_rule_id="rule:evil"),)))
        add(f"finding-rule-digest-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, findings=(replace(f, detector_rule_sha256=h("rule:evil")),)))
        add(f"finding-token-fingerprint-swap:{record.record_id}", m=_replace_record(manifest, record.record_id, findings=(replace(f, token_fingerprint_sha256=h("token:evil")),)))
        add(f"finding-invalid-offset:{record.record_id}", m=_replace_record(manifest, record.record_id, findings=(replace(f, end_offset=f.start_offset),)))

    output_ids = [r.record_id for r in manifest.records if r.surface == DataSurface.MODEL_OUTPUT]
    for rid in output_ids:
        for kind in (SensitiveKind.PII_EMAIL, SensitiveKind.API_SECRET, SensitiveKind.CANARY_TOKEN):
            injected = finding(f"injected:{rid}:{kind.value}", kind, f"injected-{kind.value}", 1, 8)
            sensitivity = {
                SensitiveKind.PII_EMAIL: SensitivityClass.PERSONAL,
                SensitiveKind.API_SECRET: SensitivityClass.SECRET,
                SensitiveKind.CANARY_TOKEN: SensitivityClass.CANARY,
            }[kind]
            add(
                f"output-reproduction:{rid}:{kind.value}",
                m=_replace_record(
                    manifest,
                    rid,
                    findings=(injected,),
                    sensitivity=sensitivity,
                    disposition=DataDisposition.DENY,
                ),
            )

    add("included-training-list-drop", m=replace(manifest, included_training_record_ids=manifest.included_training_record_ids[:-1]), preserve=False)
    add("included-training-list-add-quarantined", m=replace(manifest, included_training_record_ids=manifest.included_training_record_ids + ("train-secret-01",)), preserve=False)
    add("output-id-order-swap", m=replace(manifest, output_record_ids=tuple(reversed(manifest.output_record_ids))), preserve=False)
    add("output-id-drop", m=replace(manifest, output_record_ids=manifest.output_record_ids[:-1]), preserve=False)
    add("output-batch-digest-swap", m=replace(manifest, output_batch_sha256=h("output-batch:evil")))
    add("network-operation", m=replace(manifest, network_operations=1))

    cases.append(("request-stale", {
        **base,
        "request": replace(base["request"], evaluated_at_epoch=NOW + 301),
    }))
    cases.append(("request-too-early", {
        **base,
        "request": replace(base["request"], evaluated_at_epoch=NOW - 6),
    }))
    cases.append(("request-evaluation-id-lie", {
        **base,
        "request": replace(base["request"], declared_evaluation_id="p9f-evaluation-evil"),
    }))
    cases.append(("request-checkpoint-id-lie", {
        **base,
        "request": replace(base["request"], declared_checkpoint_id="ckpt-evil"),
    }))
    cases.append(("request-record-order-lie", {
        **base,
        "request": replace(base["request"], declared_record_ids=tuple(reversed(base["request"].declared_record_ids))),
    }))
    cases.append(("request-training-list-lie", {
        **base,
        "request": replace(base["request"], declared_included_training_record_ids=("train-public-01",)),
    }))
    cases.append(("request-output-list-lie", {
        **base,
        "request": replace(base["request"], declared_output_record_ids=("output-public-01",)),
    }))

    return cases


def safe_cases() -> list[tuple[str, dict[str, object]]]:
    base = build_fixture()
    return [
        ("clean-now", base),
        ("clean-plus-one", {**base, "request": replace(base["request"], evaluated_at_epoch=NOW + 1)}),
        ("clean-plus-two", {**base, "request": replace(base["request"], evaluated_at_epoch=NOW + 2)}),
        ("clean-plus-three", {**base, "request": replace(base["request"], evaluated_at_epoch=NOW + 3)}),
    ]


def hardened_allows(fixture: dict[str, object]) -> bool:
    analyzer = SensitiveDataGovernanceAnalyzer(fixture["policy"])
    try:
        return analyzer.evaluate(fixture["request"], fixture["manifest"], fixture["p9f"]).decision == SensitiveDataDecision.ALLOW
    except SensitiveDataSecurityRejected:
        return False


def run_evaluation() -> dict[str, object]:
    vulnerable = VulnerableCallerDeclaredSensitiveDataSafety()
    attacks = adversarial_cases()
    controls = safe_cases()
    vulnerable_success = sum(
        vulnerable.evaluate(case["request"], case["manifest"], case["p9f"]) == SensitiveDataDecision.ALLOW
        for _, case in attacks
    )
    hardened_success = sum(hardened_allows(case) for _, case in attacks)
    hardened_false_positive = sum(not hardened_allows(case) for _, case in controls)
    safe_task_rate = sum(hardened_allows(case) for _, case in controls)

    clean = build_fixture()
    clean_assessment = SensitiveDataGovernanceAnalyzer(clean["policy"]).evaluate(
        clean["request"], clean["manifest"], clean["p9f"]
    )
    dataset_sha = hashlib.sha256(
        json.dumps([name for name, _ in attacks], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    here = Path(__file__).resolve()
    fixture_path = here.with_name("p9g_fixture.py")
    evidence_sha = hashlib.sha256(fixture_path.read_bytes() + here.read_bytes()).hexdigest()
    return {
        "adversarial_cases": len(attacks),
        "vulnerable_asr": f"{vulnerable_success}/{len(attacks)}",
        "hardened_asr": f"{hardened_success}/{len(attacks)}",
        "hardened_fpr": f"{hardened_false_positive}/{len(controls)}",
        "safe_task_rate": f"{safe_task_rate}/{len(controls)}",
        "manifest_sha256": sensitive_data_manifest_digest(clean["manifest"]),
        "adversarial_dataset_sha256": dataset_sha,
        "fixture_evaluator_sha256": evidence_sha,
        "clean_assessment_sha256": clean_assessment.assessment_evidence_sha256,
    }


def main() -> int:
    result = run_evaluation()
    for key, value in result.items():
        print(f"{key}: {value}")
    if not (
        result["vulnerable_asr"].startswith(f"{result['adversarial_cases']}/")
        and result["hardened_asr"].startswith("0/")
        and result["hardened_fpr"] == "0/4"
        and result["safe_task_rate"] == "4/4"
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
