from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json

from aegis.training.data_poisoning_types import PoisoningDecision
from aegis.training.fine_tuning_security import FineTuningAdmissionAnalyzer
from aegis.training.fine_tuning_types import FineTuneDecision, FineTuneMode, FineTuningSecurityRejected, digest_json, fine_tuning_manifest_digest
from aegis.vulnerable.training_fine_tuning import VulnerableCallerDeclaredFineTuningSafety
from evals.p9c_fixture import NOW, build_fixture, h, rebind


@dataclass(frozen=True)
class AttackCase:
    name: str
    fixture: dict[str, object]


def _manifest_attack(name, mutator):
    f = build_fixture()
    return AttackCase(name, rebind(f, manifest=mutator(f["manifest"])))


def _p9b_attack(name, **updates):
    f = build_fixture()
    return AttackCase(name, rebind(f, p9b=replace(f["p9b"], **updates)))


def _request_attack(name, **updates):
    f = build_fixture()
    return AttackCase(name, dict(f, request=replace(f["request"], **updates)))


def build_attacks() -> tuple[AttackCase, ...]:
    cases: list[AttackCase] = []

    # Upstream P9-B integrity / transitive P9-A binding.
    for field in ("upstream_p9a_bound", "record_integrity_verified", "label_integrity_verified", "contributor_trust_verified", "poisoning_indicators_clear"):
        cases.append(_p9b_attack(f"p9b-flag-{field}-false", **{field: False}))
    for i in range(5):
        cases.append(_p9b_attack(f"p9b-assessment-sha-swap-{i}", assessment_evidence_sha256=h(f"p9b-sha-swap-{i}")))
    cases.extend([
        _p9b_attack("p9b-decision-deny", decision=PoisoningDecision.DENY),
        _p9b_attack("p9b-risk-injected", risks=("synthetic-risk",)),
        _p9b_attack("p9b-dataset-id-swap", dataset_id="other-dataset"),
        _p9b_attack("p9b-dataset-version-swap", dataset_version="old-version"),
        _p9b_attack("p9b-caller-trust-true", caller_declared_training_data_safety_trusted=True),
        _p9b_attack("p9b-production-platform-true", production_data_quality_platform_integrated=True),
        _p9b_attack("p9b-semantic-detection-true", semantic_poisoning_detection_validated=True),
        _p9b_attack("p9b-review-auth-true", human_review_identity_cryptographically_authenticated=True),
        _p9b_attack("p9b-schema-swap", assessment_schema_version="wrong-schema"),
        _p9b_attack("p9b-mode-swap", assessment_mode="wrong-mode"),
        _p9b_attack("p9b-included-record-drop", included_record_ids=build_fixture()["p9b"].included_record_ids[:-1]),
    ])

    # Selected-data lineage and manifest binding.
    for i in range(8):
        cases.append(_manifest_attack(f"selected-record-drop-{i}", lambda m, i=i: replace(m, selected_record_ids=tuple(r for j, r in enumerate(m.selected_record_ids) if j != i))))
    for i in range(5):
        cases.append(_manifest_attack(f"selected-data-digest-swap-{i}", lambda m, i=i: replace(m, selected_data_sha256=h(f"selected-data-swap-{i}"))))
    cases.append(_manifest_attack("manifest-p9b-sha-swap", lambda m: replace(m, p9b_assessment_sha256=h("manifest-p9b-swap"))))

    # Authorization and confused-deputy attempts.
    for i in range(4):
        cases.append(_manifest_attack(f"grant-id-swap-{i}", lambda m, i=i: replace(m, authorization=replace(m.authorization, grant_id=f"grant-attacker-{i}"))))
    for i in range(4):
        cases.append(_manifest_attack(f"principal-swap-{i}", lambda m, i=i: replace(m, principal_id=f"trainer-attacker-{i}")))
    for i in range(4):
        cases.append(_manifest_attack(f"task-swap-{i}", lambda m, i=i: replace(m, task_id=f"task-attacker-{i}")))
    cases.extend([
        _manifest_attack("auth-principal-swap", lambda m: replace(m, authorization=replace(m.authorization, principal_id="other-principal"))),
        _manifest_attack("auth-task-swap", lambda m: replace(m, authorization=replace(m.authorization, task_id="other-task"))),
        _manifest_attack("auth-p9b-sha-swap", lambda m: replace(m, authorization=replace(m.authorization, p9b_assessment_sha256=h("auth-p9b-swap")))),
        _manifest_attack("auth-base-sha-swap", lambda m: replace(m, authorization=replace(m.authorization, base_model_artifact_sha256=h("auth-base-swap")))),
        _manifest_attack("auth-data-sha-swap", lambda m: replace(m, authorization=replace(m.authorization, selected_data_sha256=h("auth-data-swap")))),
        _manifest_attack("auth-expired", lambda m: replace(m, authorization=replace(m.authorization, expires_at_epoch=NOW - 1))),
        _manifest_attack("auth-issued-future", lambda m: replace(m, authorization=replace(m.authorization, issued_at_epoch=NOW + 30, expires_at_epoch=NOW + 600))),
        _manifest_attack("auth-mode-full", lambda m: replace(m, authorization=replace(m.authorization, allowed_modes=(FineTuneMode.FULL,)))),
        _manifest_attack("auth-mode-empty", lambda m: replace(m, authorization=replace(m.authorization, allowed_modes=()))),
    ])

    # Base-model substitution.
    base_fields = {
        "model_id": ["evil-base", "aegisdesk-base-13b", "shadow-model"],
        "revision": ["r41", "latest", "attacker-revision"],
        "artifact_sha256": [h(f"bad-artifact-{i}") for i in range(4)],
        "package_sha256": [h(f"bad-package-{i}") for i in range(4)],
        "tokenizer_sha256": [h(f"bad-tokenizer-{i}") for i in range(4)],
        "runtime_profile": ["remote-code-runtime", "unsafe-transformers", "custom-kernel"],
    }
    for field, values in base_fields.items():
        for i, value in enumerate(values):
            cases.append(_manifest_attack(f"base-{field}-{i}", lambda m, field=field, value=value: replace(m, base_model=replace(m.base_model, **{field: value}))))

    # Adapter policy attacks across both adapters.
    for index in (0, 1):
        for fmt in ("pickle", "pt", "python", "custom-loader"):
            cases.append(_manifest_attack(f"adapter-{index}-format-{fmt}", lambda m, index=index, fmt=fmt: replace(m, adapters=tuple(replace(a, serialization_format=fmt) if j == index else a for j, a in enumerate(m.adapters)))))
        for rank in (0, 33, 64, 1024):
            cases.append(_manifest_attack(f"adapter-{index}-rank-{rank}", lambda m, index=index, rank=rank: replace(m, adapters=tuple(replace(a, rank=rank) if j == index else a for j, a in enumerate(m.adapters)))))
        for alpha in (0, 6401, 9000):
            cases.append(_manifest_attack(f"adapter-{index}-alpha-{alpha}", lambda m, index=index, alpha=alpha: replace(m, adapters=tuple(replace(a, alpha_bps=alpha) if j == index else a for j, a in enumerate(m.adapters)))))
        for target in ("lm_head", "embed_tokens", "attacker_module"):
            cases.append(_manifest_attack(f"adapter-{index}-target-{target}", lambda m, index=index, target=target: replace(m, adapters=tuple(replace(a, target_modules=(target,)) if j == index else a for j, a in enumerate(m.adapters)))))
        for flag in ("remote_code", "custom_code", "native_extensions"):
            cases.append(_manifest_attack(f"adapter-{index}-{flag}", lambda m, index=index, flag=flag: replace(m, adapters=tuple(replace(a, **{flag: True}) if j == index else a for j, a in enumerate(m.adapters)))))
        cases.append(_manifest_attack(f"adapter-{index}-init-swap", lambda m, index=index: replace(m, adapters=tuple(replace(a, init_sha256=h(f"bad-init-{index}")) if j == index else a for j, a in enumerate(m.adapters)))))
    cases.extend([
        _manifest_attack("adapter-order-reversed", lambda m: replace(m, adapters=tuple(reversed(m.adapters)))),
        _manifest_attack("adapter-stack-missing-parent", lambda m: replace(m, adapters=(m.adapters[0], replace(m.adapters[1], parent_adapter_ids=("missing",))))),
        _manifest_attack("adapter-stack-forward-parent", lambda m: replace(m, adapters=(replace(m.adapters[0], parent_adapter_ids=(m.adapters[1].adapter_id,)), m.adapters[1]))),
        _manifest_attack("adapter-mode-full", lambda m: replace(m, adapters=(replace(m.adapters[0], mode=FineTuneMode.FULL), m.adapters[1]))),
        _manifest_attack("adapter-extra-third", lambda m: replace(m, adapters=m.adapters + (replace(m.adapters[0], adapter_id="adapter-extra", parent_adapter_ids=(m.adapters[1].adapter_id,), init_sha256=h("adapter-extra-init")),))),
    ])

    # Hyperparameter policy escape.
    hp_attacks = [
        ("lr-low", {"learning_rate_micros": 1}),
        ("lr-high", {"learning_rate_micros": 501}),
        ("epochs-low", {"epochs_milli": 1}),
        ("epochs-high", {"epochs_milli": 4001}),
        ("batch-high", {"batch_size": 17}),
        ("steps-high", {"max_steps": 2001}),
        ("seed-unauthorized", {"seed": 999}),
        ("grad-accum-high", {"gradient_accumulation_steps": 9}),
    ]
    for name, updates in hp_attacks:
        cases.append(_manifest_attack(name, lambda m, updates=updates: replace(m, hyperparameters=replace(m.hyperparameters, **updates))))

    # Output and freshness/request-summary substitution.
    for i in range(4):
        cases.append(_manifest_attack(f"output-id-swap-{i}", lambda m, i=i: replace(m, planned_output_artifact_id=f"adapter://attacker/output-{i}")))
    cases.extend([
        _request_attack("request-manifest-digest-swap", manifest_sha256=h("request-manifest-swap")),
        _request_attack("request-dataset-id-swap", dataset_id="request-other-dataset"),
        _request_attack("request-version-swap", dataset_version="request-old-version"),
        _request_attack("request-selected-data-sha-swap", declared_selected_data_sha256=h("request-selected-data-swap")),
        _request_attack("request-base-sha-swap", declared_base_model_artifact_sha256=h("request-base-swap")),
        _request_attack("request-adapter-order-swap", declared_adapter_ids=tuple(reversed(build_fixture()["request"].declared_adapter_ids))),
        _request_attack("request-selected-record-drop", declared_selected_record_ids=build_fixture()["request"].declared_selected_record_ids[:-1]),
        _request_attack("request-stale", evaluated_at_epoch=NOW + 301),
        _request_attack("request-too-early", evaluated_at_epoch=NOW - 6),
    ])

    return tuple(cases)


def _blocked_by_hardened(case: AttackCase) -> bool:
    f = case.fixture
    try:
        result = FineTuningAdmissionAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9b"])
        return result.decision is FineTuneDecision.DENY
    except FineTuningSecurityRejected:
        return True


def _accepted_by_vulnerable(case: AttackCase) -> bool:
    f = case.fixture
    return VulnerableCallerDeclaredFineTuningSafety().evaluate(f["request"], f["manifest"], f["p9b"])


def build_benign_variants() -> tuple[dict[str, object], ...]:
    base = build_fixture()
    variants = [base]
    for updates in (
        {"seed": 23},
        {"learning_rate_micros": 100},
        {"epochs_milli": 3000, "gradient_accumulation_steps": 8},
    ):
        f = build_fixture()
        hp = replace(f["manifest"].hyperparameters, **updates)
        variants.append(rebind(f, manifest=replace(f["manifest"], hyperparameters=hp)))
    return tuple(variants)


def run() -> dict[str, object]:
    attacks = build_attacks()
    vulnerable_success = sum(_accepted_by_vulnerable(case) for case in attacks)
    hardened_success = sum(not _blocked_by_hardened(case) for case in attacks)

    benign = build_benign_variants()
    benign_false_positives = 0
    benign_safe = 0
    for f in benign:
        try:
            result = FineTuningAdmissionAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9b"])
            if result.decision is FineTuneDecision.ALLOW:
                benign_safe += 1
            else:
                benign_false_positives += 1
        except FineTuningSecurityRejected:
            benign_false_positives += 1

    clean = FineTuningAdmissionAnalyzer(build_fixture()["policy"]).evaluate(
        build_fixture()["request"], build_fixture()["manifest"], build_fixture()["p9b"]
    )
    adversarial_dataset_sha = digest_json(tuple(case.name for case in attacks))
    fixture_evaluator_evidence_sha = digest_json({
        "manifest_sha256": fine_tuning_manifest_digest(build_fixture()["manifest"]),
        "adversarial_dataset_sha256": adversarial_dataset_sha,
        "clean_assessment_sha256": clean.assessment_evidence_sha256,
        "adversarial_cases": len(attacks),
    })
    return {
        "phase": "P9-C",
        "adversarial_cases": len(attacks),
        "vulnerable_asr": f"{vulnerable_success}/{len(attacks)}",
        "hardened_asr": f"{hardened_success}/{len(attacks)}",
        "hardened_fpr": f"{benign_false_positives}/{len(benign)}",
        "safe_task_rate": f"{benign_safe}/{len(benign)}",
        "fine_tuning_manifest_sha256": fine_tuning_manifest_digest(build_fixture()["manifest"]),
        "adversarial_dataset_sha256": adversarial_dataset_sha,
        "fixture_evaluator_evidence_sha256": fixture_evaluator_evidence_sha,
        "clean_assessment_sha256": clean.assessment_evidence_sha256,
        "claim_boundary": "deterministic synthetic admission evidence only; no proof of training execution or production training-runtime/identity integration",
    }


def main() -> int:
    report = run()
    print(json.dumps(report, sort_keys=True, indent=2))
    expected = report["adversarial_cases"]
    if report["vulnerable_asr"] != f"{expected}/{expected}":
        return 1
    if report["hardened_asr"] != f"0/{expected}":
        return 1
    if report["hardened_fpr"] != "0/4" or report["safe_task_rate"] != "4/4":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
