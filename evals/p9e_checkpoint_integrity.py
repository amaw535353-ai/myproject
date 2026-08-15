from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json

from aegis.training.checkpoint_integrity_security import TrainingCheckpointIntegrityAnalyzer
from aegis.training.checkpoint_integrity_types import *
from aegis.training.training_execution_types import TrainingExecutionDecision
from aegis.vulnerable.training_checkpoint import VulnerableCallerDeclaredCheckpointSafety
from evals.p9e_fixture import build_fixture, h, rebind


def _mutate_checkpoint(manifest, index: int, **updates):
    items = list(manifest.checkpoints)
    items[index] = replace(items[index], **updates)
    return replace(manifest, checkpoints=tuple(items))


def adversarial_cases() -> list[tuple[str, dict[str, object]]]:
    base = build_fixture()
    manifest = base["manifest"]
    p9d = base["p9d"]
    cases: list[tuple[str, dict[str, object]]] = []

    upstream_mutations = [
        ("upstream-deny", replace(p9d, decision=TrainingExecutionDecision.DENY)),
        ("upstream-risk", replace(p9d, risks=("tampered",))),
        ("upstream-job", replace(p9d, job_id="other-job")),
        ("upstream-execution", replace(p9d, execution_id="other-execution")),
        ("upstream-caller-trust", replace(p9d, caller_declared_safety_trusted=True)),
        ("upstream-prod-scheduler", replace(p9d, production_scheduler_integrated=True)),
        ("upstream-prod-secret-manager", replace(p9d, production_secret_manager_integrated=True)),
        ("upstream-prod-container", replace(p9d, production_container_runtime_integrated=True)),
        ("upstream-proof-execution", replace(p9d, proof_of_training_execution=True)),
        ("upstream-hardware-attestation", replace(p9d, hardware_attestation_verified=True)),
        ("upstream-schema", replace(p9d, assessment_schema_version="wrong-schema")),
        ("upstream-mode", replace(p9d, assessment_mode="wrong-mode")),
        ("upstream-digest", replace(p9d, assessment_evidence_sha256=h("other-p9d"))),
    ]
    for name, value in upstream_mutations:
        cases.append((name, rebind(base, p9d=value)))

    top_level = [
        ("lineage-id", replace(manifest, lineage_id="other-lineage")),
        ("execution-id", replace(manifest, execution_id="other-execution")),
        ("job-id", replace(manifest, job_id="other-job")),
        ("upstream-binding", replace(manifest, p9d_assessment_sha256=h("other-upstream"))),
        ("active-checkpoint", replace(manifest, active_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("source-checkpoint", replace(manifest, source_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("target-checkpoint", replace(manifest, target_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("next-step", replace(manifest, next_step=900)),
        ("checkpoint-order", replace(manifest, checkpoints=(manifest.checkpoints[0], manifest.checkpoints[2], manifest.checkpoints[1]))),
        ("checkpoint-missing", replace(manifest, checkpoints=manifest.checkpoints[:-1])),
    ]
    for name, value in top_level:
        cases.append((name, rebind(base, manifest=value)))

    for i, checkpoint in enumerate(manifest.checkpoints):
        prefix = checkpoint.checkpoint_id
        mutations = [
            ("scope-execution", dict(execution_id="other-execution")),
            ("scope-job", dict(job_id="other-job")),
            ("attempt", dict(attempt=2)),
            ("step", dict(step=checkpoint.step + 1)),
            ("parent", dict(parent_checkpoint_id="wrong-parent")),
            ("model-state", dict(model_state_sha256=h(prefix + ":bad-model"))),
            ("optimizer-state", dict(optimizer_state_sha256=h(prefix + ":bad-optimizer"))),
            ("rng-state", dict(rng_state_sha256=h(prefix + ":bad-rng"))),
            ("cursor-state", dict(data_cursor_sha256=h(prefix + ":bad-cursor"))),
            ("trainer-state", dict(trainer_state_sha256=h(prefix + ":bad-trainer"))),
            ("artifact", dict(artifact_sha256=h(prefix + ":bad-artifact"))),
            ("format", dict(serialization_format="pickle")),
            ("mutable", dict(immutable=False)),
            ("external-reference", dict(external_reference=True)),
            ("custom-deserializer", dict(custom_deserializer=True)),
        ]
        for suffix, updates in mutations:
            cases.append((f"{prefix}-{suffix}", rebind(base, manifest=_mutate_checkpoint(manifest, i, **updates))))

    auth = manifest.authorization
    auth_mutations = [
        ("auth-principal", replace(auth, principal_id="other-principal")),
        ("auth-upstream", replace(auth, p9d_assessment_sha256=h("other-upstream"))),
        ("auth-action", replace(auth, action=CheckpointAction.ROLLBACK)),
        ("auth-source", replace(auth, source_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("auth-target", replace(auth, target_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("auth-expired", replace(auth, expires_at_epoch=manifest.created_at_epoch - 1)),
        ("auth-future", replace(auth, issued_at_epoch=manifest.created_at_epoch + 100)),
    ]
    for name, value in auth_mutations:
        cases.append((name, rebind(base, manifest=replace(manifest, authorization=value))))

    rollback_auth = replace(
        auth,
        action=CheckpointAction.ROLLBACK,
        source_checkpoint_id=manifest.checkpoints[2].checkpoint_id,
        target_checkpoint_id=manifest.checkpoints[1].checkpoint_id,
        reason_code="approved-rollback:incident-001",
    )
    rollback = replace(
        manifest,
        action=CheckpointAction.ROLLBACK,
        source_checkpoint_id=manifest.checkpoints[2].checkpoint_id,
        target_checkpoint_id=manifest.checkpoints[1].checkpoint_id,
        next_step=401,
        authorization=rollback_auth,
    )
    bad_rollback_target = replace(
        rollback,
        target_checkpoint_id=manifest.checkpoints[0].checkpoint_id,
        next_step=1,
        authorization=replace(rollback_auth, target_checkpoint_id=manifest.checkpoints[0].checkpoint_id),
    )
    cases.append(("rollback-target-not-allowed", rebind(base, manifest=bad_rollback_target)))
    cases.append(("rollback-non-earlier-target", rebind(base, manifest=replace(
        rollback,
        target_checkpoint_id=manifest.checkpoints[2].checkpoint_id,
        next_step=801,
        authorization=replace(rollback_auth, target_checkpoint_id=manifest.checkpoints[2].checkpoint_id),
    ))))
    cases.append(("rollback-bad-next-step", rebind(base, manifest=replace(rollback, next_step=402))))
    cases.append(("rollback-bad-reason", rebind(base, manifest=replace(rollback, authorization=replace(rollback_auth, reason_code="routine")))))

    request = base["request"]
    request_mutations = [
        ("request-lineage", replace(request, lineage_id="other-lineage")),
        ("request-digest", replace(request, manifest_sha256=h("other-manifest"))),
        ("request-stale", replace(request, evaluated_at_epoch=manifest.created_at_epoch + 301)),
        ("request-predates", replace(request, evaluated_at_epoch=manifest.created_at_epoch - 6)),
        ("request-checkpoint-ids", replace(request, declared_checkpoint_ids=tuple(reversed(request.declared_checkpoint_ids)))),
        ("request-active", replace(request, declared_active_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("request-action", replace(request, declared_action=CheckpointAction.ROLLBACK)),
        ("request-source", replace(request, declared_source_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("request-target", replace(request, declared_target_checkpoint_id=manifest.checkpoints[1].checkpoint_id)),
        ("request-next-step", replace(request, declared_next_step=999)),
    ]
    for name, req in request_mutations:
        item = dict(base)
        item["request"] = req
        cases.append((name, item))

    return cases


def safe_cases() -> list[dict[str, object]]:
    base = build_fixture()
    out = []
    for delta in (0, 1, 2, 3):
        item = dict(base)
        item["request"] = replace(base["request"], evaluated_at_epoch=base["manifest"].created_at_epoch + delta)
        out.append(item)
    return out


def _hash_json(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def main() -> int:
    adversarial = adversarial_cases()
    vulnerable = VulnerableCallerDeclaredCheckpointSafety()
    vulnerable_success = 0
    hardened_success = 0

    for _, fixture in adversarial:
        if vulnerable.evaluate(fixture["request"], fixture["manifest"], fixture["p9d"]):
            vulnerable_success += 1
        try:
            assessment = TrainingCheckpointIntegrityAnalyzer(fixture["policy"]).evaluate(
                fixture["request"], fixture["manifest"], fixture["p9d"]
            )
            if assessment.decision == CheckpointDecision.ALLOW:
                hardened_success += 1
        except CheckpointSecurityRejected:
            pass

    fpr = 0
    safe_pass = 0
    for fixture in safe_cases():
        assessment = TrainingCheckpointIntegrityAnalyzer(fixture["policy"]).evaluate(
            fixture["request"], fixture["manifest"], fixture["p9d"]
        )
        if assessment.decision != CheckpointDecision.ALLOW:
            fpr += 1
        else:
            safe_pass += 1

    clean = build_fixture()
    clean_assessment = TrainingCheckpointIntegrityAnalyzer(clean["policy"]).evaluate(
        clean["request"], clean["manifest"], clean["p9d"]
    )
    report = {
        "milestone": "P9-E",
        "adversarial_cases": len(adversarial),
        "vulnerable_asr": f"{vulnerable_success}/{len(adversarial)}",
        "hardened_asr": f"{hardened_success}/{len(adversarial)}",
        "hardened_fpr": f"{fpr}/{len(safe_cases())}",
        "safe_task_rate": f"{safe_pass}/{len(safe_cases())}",
        "manifest_sha256": training_checkpoint_manifest_digest(clean["manifest"]),
        "adversarial_dataset_sha256": _hash_json([name for name, _ in adversarial]),
        "fixture_evaluator_evidence_sha256": _hash_json({
            "fixture": open(__file__.replace("p9e_checkpoint_integrity.py", "p9e_fixture.py"), "rb").read().hex(),
            "evaluator": open(__file__, "rb").read().hex(),
        }),
        "clean_assessment_sha256": clean_assessment.assessment_evidence_sha256,
        "production_validation_claimed": False,
    }
    print(json.dumps(report, sort_keys=True))
    if vulnerable_success != len(adversarial) or hardened_success != 0 or fpr != 0 or safe_pass != len(safe_cases()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
