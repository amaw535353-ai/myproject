from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path

from aegis.training.fine_tuning_types import FineTuneDecision
from aegis.training.training_execution_security import TrainingExecutionProvenanceAnalyzer
from aegis.training.training_execution_types import (
    TrainingCapabilityEvidence,
    TrainingExecutionDecision,
    TrainingExecutionSecurityRejected,
    TrainingSecretLeaseEvidence,
    digest_json,
    training_execution_manifest_digest,
)
from aegis.vulnerable.training_execution import VulnerableCallerDeclaredTrainingExecutionSafety
from evals.p9d_fixture import NOW, build_fixture, h, rebind


def _manifest_case(name: str, transform):
    fixture = build_fixture()
    manifest = transform(fixture["manifest"])
    return name, rebind(fixture, manifest=manifest)


def _p9c_case(name: str, transform):
    fixture = build_fixture()
    return name, rebind(fixture, p9c=transform(fixture["p9c"]))


def build_adversarial_cases() -> list[tuple[str, dict[str, object]]]:
    base = build_fixture()
    cases: list[tuple[str, dict[str, object]]] = []

    p9c_mutations = [
        ("p9c-deny", lambda a: replace(a, decision=FineTuneDecision.DENY)),
        ("p9c-risks", lambda a: replace(a, risks=("synthetic-risk",))),
        ("p9c-upstream-unbound", lambda a: replace(a, upstream_p9b_bound=False)),
        ("p9c-auth-unverified", lambda a: replace(a, authorization_verified=False)),
        ("p9c-base-unverified", lambda a: replace(a, base_model_binding_verified=False)),
        ("p9c-adapter-unverified", lambda a: replace(a, adapter_policy_verified=False)),
        ("p9c-hyperparameters-unverified", lambda a: replace(a, hyperparameter_policy_verified=False)),
        ("p9c-caller-trusted", lambda a: replace(a, caller_declared_safety_trusted=True)),
        ("p9c-production-runtime-claimed", lambda a: replace(a, production_training_runtime_integrated=True)),
        ("p9c-production-idp-claimed", lambda a: replace(a, production_identity_provider_integrated=True)),
        ("p9c-proof-execution-claimed", lambda a: replace(a, proof_of_training_execution=True)),
        ("p9c-schema-swapped", lambda a: replace(a, assessment_schema_version="aegis-fine-tuning-admission-assessment-v0")),
        ("p9c-mode-swapped", lambda a: replace(a, assessment_mode="caller-declared")),
        ("p9c-evidence-digest-swapped", lambda a: replace(a, assessment_evidence_sha256=h("attacker-p9c-assessment"))),
        ("p9c-manifest-id-swapped", lambda a: replace(a, manifest_id="p9c-attacker-manifest")),
        ("p9c-principal-swapped", lambda a: replace(a, principal_id="trainer-attacker")),
        ("p9c-task-swapped", lambda a: replace(a, task_id="attacker-task")),
        ("p9c-output-swapped", lambda a: replace(a, planned_output_artifact_id="adapter://attacker/output")),
    ]
    cases.extend(_p9c_case(name, transform) for name, transform in p9c_mutations)

    for i in range(1, 9):
        cases.append(_manifest_case(
            f"manifest-p9c-digest-swapped-{i:02d}",
            lambda m, i=i: replace(m, p9c_assessment_sha256=h(f"swapped-p9c-{i}")),
        ))
        cases.append(_manifest_case(
            f"job-id-swapped-{i:02d}",
            lambda m, i=i: replace(m, job=replace(m.job, job_id=f"attacker-job-{i:02d}")),
        ))
        cases.append(_manifest_case(
            f"launch-nonce-swapped-{i:02d}",
            lambda m, i=i: replace(m, job=replace(m.job, launch_nonce_sha256=h(f"attacker-launch-{i}"))),
        ))
        cases.append(_manifest_case(
            f"code-commit-swapped-{i:02d}",
            lambda m, i=i: replace(m, code=replace(m.code, commit_sha=hashlib.sha1(f"attacker-commit-{i}".encode()).hexdigest())),
        ))
        cases.append(_manifest_case(
            f"config-digest-swapped-{i:02d}",
            lambda m, i=i: replace(m, code=replace(m.code, config_sha256=h(f"attacker-config-{i}"))),
        ))
        cases.append(_manifest_case(
            f"image-digest-swapped-{i:02d}",
            lambda m, i=i: replace(m, environment=replace(m.environment, image_sha256=h(f"attacker-image-{i}"))),
        ))

    single_manifest_mutations = [
        ("admission-manifest-swapped", lambda m: replace(m, admission_manifest_id="p9c-attacker-manifest")),
        ("output-artifact-swapped", lambda m: replace(m, planned_output_artifact_id="adapter://attacker/output")),
        ("job-attempt-swapped", lambda m: replace(m, job=replace(m.job, attempt=2))),
        ("scheduler-swapped", lambda m: replace(m, job=replace(m.job, scheduler="attacker-scheduler"))),
        ("namespace-swapped", lambda m: replace(m, job=replace(m.job, namespace="default"))),
        ("queue-swapped", lambda m: replace(m, job=replace(m.job, queue="unrestricted"))),
        ("service-account-swapped", lambda m: replace(m, job=replace(m.job, service_account="cluster-admin"))),
        ("executor-principal-swapped", lambda m: replace(m, job=replace(m.job, executor_principal="spiffe://attacker/root"))),
        ("token-audience-swapped", lambda m: replace(m, job=replace(m.job, identity_token_audience="kubernetes.default"))),
        ("repository-swapped", lambda m: replace(m, code=replace(m.code, repository_id="attacker/trainer"))),
        ("tree-swapped", lambda m: replace(m, code=replace(m.code, tree_sha=hashlib.sha1(b"attacker-tree").hexdigest()))),
        ("entrypoint-swapped", lambda m: replace(m, code=replace(m.code, entrypoint="tmp/payload.py"))),
        ("entrypoint-digest-swapped", lambda m: replace(m, code=replace(m.code, entrypoint_sha256=h("attacker-entrypoint")))),
        ("lockfile-digest-swapped", lambda m: replace(m, code=replace(m.code, dependency_lock_sha256=h("attacker-lock")))),
        ("source-writeable", lambda m: replace(m, code=replace(m.code, source_read_only=False))),
        ("remote-fetch-enabled", lambda m: replace(m, code=replace(m.code, remote_fetch_allowed=True))),
        ("dynamic-install-enabled", lambda m: replace(m, code=replace(m.code, dynamic_dependency_install=True))),
        ("custom-startup-enabled", lambda m: replace(m, code=replace(m.code, custom_startup_script=True))),
        ("image-ref-swapped", lambda m: replace(m, environment=replace(m.environment, image_ref="docker.io/attacker/trainer:latest"))),
        ("python-version-swapped", lambda m: replace(m, environment=replace(m.environment, python_version="3.13.0"))),
        ("framework-version-swapped", lambda m: replace(m, environment=replace(m.environment, framework_version="transformers-latest"))),
        ("accelerator-runtime-swapped", lambda m: replace(m, environment=replace(m.environment, accelerator_runtime="cuda-latest"))),
        ("device-profile-expanded", lambda m: replace(m, environment=replace(m.environment, device_profile="gpu-any"))),
        ("environment-variable-added", lambda m: replace(m, environment=replace(m.environment, environment_variable_names=m.environment.environment_variable_names + ("AWS_SECRET_ACCESS_KEY",)))),
        ("environment-variable-reordered", lambda m: replace(m, environment=replace(m.environment, environment_variable_names=tuple(reversed(m.environment.environment_variable_names))))),
        ("network-egress-added", lambda m: replace(m, environment=replace(m.environment, network_egress=m.environment.network_egress + ("internet.example:443",)))),
        ("network-egress-wildcard", lambda m: replace(m, environment=replace(m.environment, network_egress=("*:443",)))),
        ("network-egress-reordered", lambda m: replace(m, environment=replace(m.environment, network_egress=tuple(reversed(m.environment.network_egress))))),
        ("writable-path-added", lambda m: replace(m, environment=replace(m.environment, writable_paths=m.environment.writable_paths + ("/etc",)))),
        ("writable-path-wildcard", lambda m: replace(m, environment=replace(m.environment, writable_paths=("/*",)))),
        ("writable-path-reordered", lambda m: replace(m, environment=replace(m.environment, writable_paths=tuple(reversed(m.environment.writable_paths))))),
        ("host-mount-added", lambda m: replace(m, environment=replace(m.environment, host_mounts=("/var/run",)))),
        ("rootfs-writeable", lambda m: replace(m, environment=replace(m.environment, root_filesystem_read_only=False))),
        ("privileged-runtime", lambda m: replace(m, environment=replace(m.environment, privileged=True))),
        ("host-network-enabled", lambda m: replace(m, environment=replace(m.environment, host_network=True))),
        ("privilege-escalation-enabled", lambda m: replace(m, environment=replace(m.environment, allow_privilege_escalation=True))),
        ("docker-socket-mounted", lambda m: replace(m, environment=replace(m.environment, docker_socket_mounted=True))),
        ("secret-removed", lambda m: replace(m, secrets=m.secrets[:-1])),
        ("secret-reordered", lambda m: replace(m, secrets=tuple(reversed(m.secrets)))),
        ("capability-removed", lambda m: replace(m, capabilities=m.capabilities[:-1])),
        ("capability-reordered", lambda m: replace(m, capabilities=tuple(reversed(m.capabilities)))),
    ]
    cases.extend(_manifest_case(name, transform) for name, transform in single_manifest_mutations)

    for index, secret in enumerate(base["manifest"].secrets):
        cases.extend([
            _manifest_case(
                f"secret-{index}-provider-swapped",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, provider="attacker-secret-store") if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-version-swapped",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, version="latest") if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-purpose-swapped",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, purpose="cluster-admin") if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-scope-wildcard",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, scope="*") if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-mount-swapped",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, mount_path="/tmp/secret") if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-principal-swapped",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, issued_to_principal="spiffe://attacker/root") if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-expired",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, expires_at_epoch=NOW - 1) if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-future-issued",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, issued_at_epoch=NOW + 30) if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-exportable",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, exportable=True) if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
            _manifest_case(
                f"secret-{index}-env-injected",
                lambda m, index=index: replace(m, secrets=tuple(
                    replace(s, injected_as_environment_variable=True) if j == index else s
                    for j, s in enumerate(m.secrets)
                )),
            ),
        ])

    extra_secret = TrainingSecretLeaseEvidence(
        secret_id="secret-cluster-admin",
        provider="synthetic-secret-broker",
        version="v1",
        purpose="admin",
        scope="*",
        mount_path="/run/secrets/admin",
        issued_to_principal=base["manifest"].job.executor_principal,
        issued_at_epoch=NOW - 30,
        expires_at_epoch=NOW + 300,
        exportable=False,
        injected_as_environment_variable=False,
    )
    cases.append(_manifest_case("secret-extra-admin", lambda m: replace(m, secrets=m.secrets + (extra_secret,))))

    for index, cap in enumerate(base["manifest"].capabilities):
        cases.extend([
            _manifest_case(
                f"capability-{index}-resource-swapped",
                lambda m, index=index: replace(m, capabilities=tuple(
                    replace(c, resource="cluster:*") if j == index else c
                    for j, c in enumerate(m.capabilities)
                )),
            ),
            _manifest_case(
                f"capability-{index}-actions-expanded",
                lambda m, index=index: replace(m, capabilities=tuple(
                    replace(c, actions=c.actions + ("delete",)) if j == index else c
                    for j, c in enumerate(m.capabilities)
                )),
            ),
            _manifest_case(
                f"capability-{index}-actions-wildcard",
                lambda m, index=index: replace(m, capabilities=tuple(
                    replace(c, actions=("*",)) if j == index else c
                    for j, c in enumerate(m.capabilities)
                )),
            ),
        ])

    extra_capability = TrainingCapabilityEvidence(
        capability_id="cap-cluster-admin",
        resource="cluster:*",
        actions=("*",),
    )
    cases.append(_manifest_case("capability-extra-admin", lambda m: replace(m, capabilities=m.capabilities + (extra_capability,))))

    # Request-level replay/staleness and binding attacks leave caller safety booleans true.
    for i in range(1, 7):
        fixture = build_fixture()
        cases.append((f"request-manifest-digest-swapped-{i:02d}", {
            **fixture,
            "request": replace(fixture["request"], manifest_sha256=h(f"request-swapped-{i}")),
        }))
    fixture = build_fixture()
    cases.append(("request-execution-id-swapped", {
        **fixture,
        "request": replace(fixture["request"], execution_id="attacker-execution"),
    }))
    cases.append(("request-stale", {
        **fixture,
        "request": replace(fixture["request"], evaluated_at_epoch=NOW + 301),
    }))
    cases.append(("request-too-early", {
        **fixture,
        "request": replace(fixture["request"], evaluated_at_epoch=NOW - 6),
    }))

    names = [name for name, _ in cases]
    assert len(names) == len(set(names))
    assert len(cases) >= 140
    return cases


def build_safe_cases() -> list[tuple[str, dict[str, object]]]:
    cases = []
    for offset in (0, 1, 60, 240):
        fixture = build_fixture()
        fixture = {
            **fixture,
            "request": replace(fixture["request"], evaluated_at_epoch=NOW + offset),
        }
        cases.append((f"safe-evaluation-offset-{offset}", fixture))
    return cases


def _hardened_allows(fixture: dict[str, object]) -> bool:
    analyzer = TrainingExecutionProvenanceAnalyzer(fixture["policy"])
    try:
        assessment = analyzer.evaluate(fixture["request"], fixture["manifest"], fixture["p9c"])
    except TrainingExecutionSecurityRejected:
        return False
    return assessment.decision == TrainingExecutionDecision.ALLOW


def _vulnerable_allows(fixture: dict[str, object]) -> bool:
    return VulnerableCallerDeclaredTrainingExecutionSafety().evaluate(
        fixture["request"], fixture["manifest"], fixture["p9c"]
    )


def _case_digest(cases: list[tuple[str, dict[str, object]]]) -> str:
    compact = []
    for name, fixture in cases:
        compact.append({
            "name": name,
            "manifest_sha256": training_execution_manifest_digest(fixture["manifest"]),
            "p9c_assessment_sha256": getattr(fixture["p9c"], "assessment_evidence_sha256", ""),
            "request": asdict(fixture["request"]),
        })
    return digest_json(compact)


def _source_evidence_digest() -> str:
    root = Path(__file__).resolve().parents[1]
    paths = (
        root / "aegis/training/training_execution_types.py",
        root / "aegis/training/training_execution_security.py",
        root / "aegis/vulnerable/training_execution.py",
        root / "evals/p9d_fixture.py",
        root / "evals/p9d_training_execution_provenance.py",
        root / "tests/security/test_p9d_training_execution_provenance.py",
    )
    hsh = hashlib.sha256()
    for path in paths:
        hsh.update(path.relative_to(root).as_posix().encode("utf-8"))
        hsh.update(b"\0")
        hsh.update(path.read_bytes())
        hsh.update(b"\0")
    return hsh.hexdigest()


def main() -> int:
    adversarial = build_adversarial_cases()
    safe = build_safe_cases()
    vulnerable_successes = sum(_vulnerable_allows(fixture) for _, fixture in adversarial)
    hardened_successes = sum(_hardened_allows(fixture) for _, fixture in adversarial)
    hardened_false_positives = sum(not _hardened_allows(fixture) for _, fixture in safe)
    safe_task_rate = sum(_hardened_allows(fixture) for _, fixture in safe)

    clean = build_fixture()
    clean_assessment = TrainingExecutionProvenanceAnalyzer(clean["policy"]).evaluate(
        clean["request"], clean["manifest"], clean["p9c"]
    )
    metrics = {
        "adversarial_cases": len(adversarial),
        "vulnerable_asr": f"{vulnerable_successes}/{len(adversarial)}",
        "hardened_asr": f"{hardened_successes}/{len(adversarial)}",
        "hardened_fpr": f"{hardened_false_positives}/{len(safe)}",
        "safe_task_rate": f"{safe_task_rate}/{len(safe)}",
        "execution_manifest_sha256": training_execution_manifest_digest(clean["manifest"]),
        "adversarial_dataset_sha256": _case_digest(adversarial),
        "fixture_evaluator_evidence_sha256": _source_evidence_digest(),
        "clean_assessment_sha256": clean_assessment.assessment_evidence_sha256,
    }
    assert vulnerable_successes == len(adversarial)
    assert hardened_successes == 0
    assert hardened_false_positives == 0
    assert safe_task_rate == len(safe)
    print(json.dumps(metrics, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
