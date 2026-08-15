from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Callable

from aegis.agentic.phase8_exit_security import Phase8IntegratedExitGate, machine_readable_phase8_exit
from aegis.agentic.phase8_exit_types import (
    MILESTONE_ORDER,
    Phase8ExitDecision,
    Phase8ExitRejected,
    VerificationStatus,
)
from aegis.vulnerable.phase8_exit_security import VulnerableCallerDeclaredPhase8Exit
from evals.p8l_fixture import build_fixture, h, rebind

Fixture = dict[str, object]
Attack = Callable[[Fixture], Fixture]


def _replace_milestone(f: Fixture, index: int, **changes: object) -> Fixture:
    manifest = f["manifest"]
    milestones = list(manifest.milestone_evidence)  # type: ignore[attr-defined]
    milestones[index] = replace(milestones[index], **changes)
    changed = replace(manifest, milestone_evidence=tuple(milestones))
    return rebind(f, changed, keep_policy_pins=False)


def _replace_verification(f: Fixture, verification_id: str, **changes: object) -> Fixture:
    manifest = f["manifest"]
    records = list(manifest.verification_records)  # type: ignore[attr-defined]
    for i, record in enumerate(records):
        if record.verification_id == verification_id:
            records[i] = replace(record, **changes)
            break
    changed = replace(manifest, verification_records=tuple(records))
    return rebind(f, changed, keep_policy_pins=False)


def _global_cases() -> list[tuple[str, Attack]]:
    cases: list[tuple[str, Attack]] = []

    def schema_bad(f: Fixture) -> Fixture:
        return rebind(
            f,
            replace(f["manifest"], schema_version="wrong-schema"),  # type: ignore[arg-type]
            keep_policy_pins=False,
        )

    cases.append(("manifest-schema", schema_bad))

    def manifest_id_bad(f: Fixture) -> Fixture:
        return rebind(
            f,
            replace(f["manifest"], manifest_id="other-manifest"),  # type: ignore[arg-type]
            keep_policy_pins=False,
        )

    cases.append(("manifest-id", manifest_id_bad))

    def lineage_id_bad(f: Fixture) -> Fixture:
        return rebind(
            f,
            replace(f["manifest"], execution_lineage_id="other-lineage"),  # type: ignore[arg-type]
            keep_policy_pins=False,
        )

    cases.append(("manifest-lineage", lineage_id_bad))

    def assumption_drop(f: Fixture) -> Fixture:
        m = f["manifest"]
        return rebind(
            f,
            replace(m, synthetic_assumptions=m.synthetic_assumptions[:-1]),  # type: ignore[attr-defined]
            keep_policy_pins=False,
        )

    cases.append(("assumption-drop", assumption_drop))

    def assumption_extra(f: Fixture) -> Fixture:
        m = f["manifest"]
        return rebind(
            f,
            replace(
                m,
                synthetic_assumptions=m.synthetic_assumptions + ("unsupported-production-proof",),  # type: ignore[attr-defined]
            ),
            keep_policy_pins=False,
        )

    cases.append(("assumption-extra", assumption_extra))

    claim_fields = [
        "production_runtime_validated",
        "production_distributed_system_validated",
        "production_siem_edr_integrated",
        "production_secret_rotation_executed",
        "cryptographic_attestation_verified",
    ]
    for field in claim_fields:
        def claim_attack(f: Fixture, field: str = field) -> Fixture:
            m = f["manifest"]
            claims = replace(m.claim_profile, **{field: True})  # type: ignore[attr-defined]
            return rebind(f, replace(m, claim_profile=claims), keep_policy_pins=False)  # type: ignore[arg-type]

        cases.append((f"unsupported-claim-{field}", claim_attack))

    cases.append(
        (
            "remote-blocked-runner-started",
            lambda f: _replace_verification(f, "remote-phase8-ci", runner_started=True),
        )
    )
    cases.append(
        (
            "remote-blocked-steps-executed",
            lambda f: _replace_verification(f, "remote-phase8-ci", steps_executed=1),
        )
    )
    cases.append(
        (
            "remote-blocked-unknown-reason",
            lambda f: _replace_verification(f, "remote-phase8-ci", reason_code="unknown-provider-error"),
        )
    )

    def remote_fail(f: Fixture) -> Fixture:
        return build_fixture(VerificationStatus.REMOTE_CI_FAIL)

    cases.append(("remote-ci-executed-failure", remote_fail))

    def remote_pass_no_start(f: Fixture) -> Fixture:
        ff = build_fixture(VerificationStatus.REMOTE_CI_PASS)
        return _replace_verification(ff, "remote-phase8-ci", runner_started=False)

    cases.append(("remote-pass-no-runner", remote_pass_no_start))

    def remote_pass_zero_steps(f: Fixture) -> Fixture:
        ff = build_fixture(VerificationStatus.REMOTE_CI_PASS)
        return _replace_verification(ff, "remote-phase8-ci", steps_executed=0)

    cases.append(("remote-pass-zero-steps", remote_pass_zero_steps))

    def remote_pass_reason(f: Fixture) -> Fixture:
        ff = build_fixture(VerificationStatus.REMOTE_CI_PASS)
        return _replace_verification(ff, "remote-phase8-ci", reason_code="billing-warning")

    cases.append(("remote-pass-with-block-reason", remote_pass_reason))

    def duplicate_remote(f: Fixture) -> Fixture:
        m = f["manifest"]
        remote = [
            v for v in m.verification_records if v.verification_id == "remote-phase8-ci"  # type: ignore[attr-defined]
        ][0]
        duplicate = replace(remote, verification_id="remote-phase8-ci-duplicate")
        return rebind(
            f,
            replace(m, verification_records=m.verification_records + (duplicate,)),  # type: ignore[attr-defined]
            keep_policy_pins=False,
        )

    cases.append(("duplicate-remote-record", duplicate_remote))

    def request_manifest_id(f: Fixture) -> Fixture:
        return {**f, "request": replace(f["request"], manifest_id="caller-other-manifest")}  # type: ignore[arg-type]

    cases.append(("request-manifest-id-lie", request_manifest_id))

    def request_decision(f: Fixture) -> Fixture:
        return {
            **f,
            "request": replace(f["request"], declared_exit_decision=Phase8ExitDecision.PASS),  # type: ignore[arg-type]
        }

    cases.append(("request-decision-lie", request_decision))

    def request_evidence(f: Fixture) -> Fixture:
        r = f["request"]
        d = dict(r.declared_assessment_sha256_by_milestone)  # type: ignore[attr-defined]
        d["P8-K"] = h("caller-forged-assessment")
        return {**f, "request": replace(r, declared_assessment_sha256_by_milestone=d)}

    cases.append(("request-evidence-lie", request_evidence))

    def request_verification(f: Fixture) -> Fixture:
        r = f["request"]
        d = dict(r.declared_verification_status_by_id)  # type: ignore[attr-defined]
        d["remote-phase8-ci"] = VerificationStatus.REMOTE_CI_PASS.value
        return {**f, "request": replace(r, declared_verification_status_by_id=d)}

    cases.append(("request-verification-lie", request_verification))

    return cases


CASES: list[tuple[str, Attack]] = _global_cases()

for index, milestone_id in enumerate(MILESTONE_ORDER):
    current = build_fixture()["manifest"].milestone_evidence[index]  # type: ignore[attr-defined]
    mutations: list[tuple[str, dict[str, object]]] = [
        ("domain", {"control_domain": f"wrong-{current.control_domain}"}),
        ("step-index", {"step_index": 99}),
        ("lineage", {"execution_lineage_id": "forged-lineage"}),
        ("manifest-digest", {"manifest_sha256": h(f"forged:{milestone_id}:manifest")}),
        ("assessment-digest", {"assessment_sha256": h(f"forged:{milestone_id}:assessment")}),
        ("predecessor", {"predecessor_assessment_sha256": h(f"forged:{milestone_id}:predecessor")}),
        ("input-state", {"input_state_sha256": h(f"forged:{milestone_id}:input")}),
        ("output-state", {"output_state_sha256": h(f"forged:{milestone_id}:output")}),
        ("unsafe", {"safe": False}),
        ("caller-trust", {"caller_declared_safety_trusted": True}),
        ("network-ops", {"network_operations": 1}),
        ("assessment-schema", {"assessment_schema_version": "forged-assessment-schema"}),
        ("assessment-mode", {"assessment_mode": "caller-declared-safe-mode"}),
        ("milestone-id", {"milestone_id": f"P8-X{index:02d}"}),
    ]
    for label, changes in mutations:
        CASES.append(
            (
                f"{milestone_id.lower()}-{label}",
                lambda f, index=index, changes=changes: _replace_milestone(f, index, **changes),
            )
        )

for milestone_id in MILESTONE_ORDER:
    verification_id = f"local-{milestone_id.lower()}"
    CASES.append(
        (
            f"{milestone_id.lower()}-local-not-run",
            lambda f, verification_id=verification_id: _replace_verification(
                f, verification_id, status=VerificationStatus.NOT_RUN
            ),
        )
    )
    CASES.append(
        (
            f"{milestone_id.lower()}-local-runner-not-started",
            lambda f, verification_id=verification_id: _replace_verification(
                f, verification_id, runner_started=False
            ),
        )
    )

EXPECTED_ADVERSARIAL_CASES = 198
assert len(CASES) == EXPECTED_ADVERSARIAL_CASES, len(CASES)


def _hardened_accepts(f: Fixture) -> bool:
    try:
        assessment = Phase8IntegratedExitGate(f["policy"]).evaluate(  # type: ignore[arg-type]
            f["request"], f["manifest"]
        )
        return assessment.decision in {
            Phase8ExitDecision.PASS,
            Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION,
        }
    except Phase8ExitRejected:
        return False


def _safe_cases() -> list[Fixture]:
    cases = []
    for status in (VerificationStatus.REMOTE_CI_BLOCKED, VerificationStatus.REMOTE_CI_PASS):
        for offset in (10, 20):
            f = build_fixture(status)
            f["request"] = replace(
                f["request"],  # type: ignore[arg-type]
                evaluated_at_epoch=f["manifest"].created_at_epoch + offset,  # type: ignore[attr-defined]
            )
            cases.append(f)
    return cases


def _dataset_digest() -> str:
    material = "\n".join(name for name, _ in CASES)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _fixture_digest() -> str:
    f = build_fixture()
    material = {
        "manifest": f["request"].manifest_sha256,  # type: ignore[attr-defined]
        "policy": f["policy"].policy_version,  # type: ignore[attr-defined]
        "cases": _dataset_digest(),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def run() -> dict[str, object]:
    vulnerable = VulnerableCallerDeclaredPhase8Exit()
    vulnerable_success = 0
    hardened_success = 0
    for _, attack in CASES:
        f = attack(build_fixture())
        vulnerable_success += int(vulnerable.accepts(Phase8ExitDecision.PASS))
        hardened_success += int(_hardened_accepts(f))

    safe_cases = _safe_cases()
    safe_failures = sum(not _hardened_accepts(f) for f in safe_cases)
    canonical = build_fixture()
    assessment = Phase8IntegratedExitGate(canonical["policy"]).evaluate(  # type: ignore[arg-type]
        canonical["request"], canonical["manifest"]
    )
    report = machine_readable_phase8_exit(assessment)

    result = {
        "adversarial_cases": len(CASES),
        "vulnerable_asr": f"{vulnerable_success}/{len(CASES)}",
        "hardened_asr": f"{hardened_success}/{len(CASES)}",
        "hardened_fpr": f"{safe_failures}/{len(safe_cases)}",
        "safe_task_rate": f"{len(safe_cases) - safe_failures}/{len(safe_cases)}",
        "exit_decision": assessment.decision.value,
        "remote_ci_status": assessment.remote_ci_status,
        "phase8_exit_manifest_sha256": canonical["request"].manifest_sha256,  # type: ignore[attr-defined]
        "adversarial_dataset_sha256": _dataset_digest(),
        "fixture_evaluator_sha256": _fixture_digest(),
        "clean_assessment_sha256": assessment.assessment_evidence_sha256,
        "machine_readable_exit": report,
    }
    return result


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
