from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.training.training_execution_security import TrainingExecutionProvenanceAnalyzer
from aegis.training.training_execution_types import (
    P9D_ASSESSMENT_MODE,
    P9D_ASSESSMENT_SCHEMA_VERSION,
    P9D_POLICY_VERSION,
    P9D_SCHEMA_VERSION,
    TrainingExecutionDecision,
    TrainingExecutionRejectReason,
    TrainingExecutionRisk,
    TrainingExecutionSecurityRejected,
    training_execution_manifest_digest,
)
from aegis.vulnerable.training_execution import VulnerableCallerDeclaredTrainingExecutionSafety
from evals.p9d_fixture import NOW, build_fixture, h
from evals.p9d_training_execution_provenance import (
    _hardened_allows,
    build_adversarial_cases,
    build_safe_cases,
)


def test_clean_assessment_binds_execution_without_production_claims():
    fixture = build_fixture()
    assessment = TrainingExecutionProvenanceAnalyzer(fixture["policy"]).evaluate(
        fixture["request"], fixture["manifest"], fixture["p9c"]
    )
    assert assessment.decision == TrainingExecutionDecision.ALLOW
    assert assessment.risks == ()
    assert assessment.upstream_p9c_bound
    assert assessment.job_identity_verified
    assert assessment.code_config_provenance_verified
    assert assessment.environment_policy_verified
    assert assessment.secret_least_privilege_verified
    assert assessment.capability_least_privilege_verified
    assert assessment.caller_declared_safety_trusted is False
    assert assessment.production_scheduler_integrated is False
    assert assessment.production_secret_manager_integrated is False
    assert assessment.production_container_runtime_integrated is False
    assert assessment.proof_of_training_execution is False
    assert assessment.hardware_attestation_verified is False
    assert assessment.assessment_schema_version == P9D_ASSESSMENT_SCHEMA_VERSION
    assert assessment.assessment_mode == P9D_ASSESSMENT_MODE
    assert len(assessment.assessment_evidence_sha256) == 64


def test_manifest_digest_is_deterministic_and_policy_pinned():
    fixture = build_fixture()
    digest = training_execution_manifest_digest(fixture["manifest"])
    assert digest == training_execution_manifest_digest(fixture["manifest"])
    assert digest == fixture["policy"].expected_manifest_sha256
    assert len(digest) == 64


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: replace(p, policy_version="bad"),
        lambda p: replace(p, expected_manifest_sha256="not-a-sha"),
        lambda p: replace(p, expected_commit_sha="abc"),
        lambda p: replace(p, expected_attempt=0),
        lambda p: replace(p, max_manifest_age_seconds=-1),
        lambda p: replace(p, allowed_network_egress=("*:443",)),
        lambda p: replace(p, expected_secret_scope_by_id={**p.expected_secret_scope_by_id, "extra": "x"}),
        lambda p: replace(p, expected_capability_actions_by_id={**p.expected_capability_actions_by_id, p.expected_capability_order[0]: ("*",)}),
    ],
)
def test_invalid_policy_rejected(mutation):
    fixture = build_fixture()
    with pytest.raises(TrainingExecutionSecurityRejected) as exc:
        TrainingExecutionProvenanceAnalyzer(mutation(fixture["policy"]))
    assert exc.value.reason == TrainingExecutionRejectReason.POLICY_INVALID


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: replace(m, schema_version="bad"),
        lambda m: replace(m, execution_id="other"),
        lambda m: replace(m, p9c_assessment_sha256="bad"),
        lambda m: replace(m, job=replace(m.job, launch_nonce_sha256="bad")),
        lambda m: replace(m, code=replace(m.code, commit_sha="bad")),
        lambda m: replace(m, code=replace(m.code, config_sha256="bad")),
        lambda m: replace(m, environment=replace(m.environment, image_sha256="bad")),
        lambda m: replace(m, secrets=m.secrets + (m.secrets[0],)),
        lambda m: replace(m, secrets=(replace(m.secrets[0], issued_at_epoch=NOW + 20, expires_at_epoch=NOW + 10),) + m.secrets[1:]),
        lambda m: replace(m, capabilities=m.capabilities + (m.capabilities[0],)),
    ],
)
def test_invalid_manifest_rejected(mutation):
    fixture = build_fixture()
    analyzer = TrainingExecutionProvenanceAnalyzer(fixture["policy"])
    with pytest.raises(TrainingExecutionSecurityRejected) as exc:
        analyzer.derive(mutation(fixture["manifest"]), fixture["p9c"], NOW)
    assert exc.value.reason == TrainingExecutionRejectReason.MANIFEST_INVALID


@pytest.mark.parametrize(
    ("case_name", "expected_risk"),
    [
        ("p9c-deny", TrainingExecutionRisk.UPSTREAM_P9C_INVALID),
        ("p9c-evidence-digest-swapped", TrainingExecutionRisk.UPSTREAM_BINDING_MISMATCH),
        ("p9c-principal-swapped", TrainingExecutionRisk.UPSTREAM_BINDING_MISMATCH),
        ("p9c-output-swapped", TrainingExecutionRisk.OUTPUT_IDENTITY_MISMATCH),
        ("job-id-swapped-01", TrainingExecutionRisk.JOB_IDENTITY_MISMATCH),
        ("scheduler-swapped", TrainingExecutionRisk.SCHEDULER_IDENTITY_MISMATCH),
        ("code-commit-swapped-01", TrainingExecutionRisk.CODE_IDENTITY_MISMATCH),
        ("entrypoint-digest-swapped", TrainingExecutionRisk.CODE_INTEGRITY_MISMATCH),
        ("config-digest-swapped-01", TrainingExecutionRisk.CONFIG_MISMATCH),
        ("remote-fetch-enabled", TrainingExecutionRisk.DYNAMIC_OR_REMOTE_CODE),
        ("image-digest-swapped-01", TrainingExecutionRisk.ENVIRONMENT_IDENTITY_MISMATCH),
        ("privileged-runtime", TrainingExecutionRisk.PRIVILEGED_RUNTIME),
        ("network-egress-added", TrainingExecutionRisk.NETWORK_POLICY_MISMATCH),
        ("writable-path-added", TrainingExecutionRisk.FILESYSTEM_POLICY_MISMATCH),
        ("device-profile-expanded", TrainingExecutionRisk.DEVICE_POLICY_MISMATCH),
        ("environment-variable-added", TrainingExecutionRisk.ENV_ALLOWLIST_MISMATCH),
        ("secret-removed", TrainingExecutionRisk.SECRET_COVERAGE_MISMATCH),
        ("secret-0-scope-wildcard", TrainingExecutionRisk.SECRET_SCOPE_EXCESSIVE),
        ("secret-0-expired", TrainingExecutionRisk.SECRET_LEASE_INVALID),
        ("secret-0-exportable", TrainingExecutionRisk.SECRET_EXPOSURE_UNSAFE),
        ("capability-removed", TrainingExecutionRisk.CAPABILITY_COVERAGE_MISMATCH),
        ("capability-0-resource-swapped", TrainingExecutionRisk.CAPABILITY_EXCESSIVE),
        ("output-artifact-swapped", TrainingExecutionRisk.OUTPUT_IDENTITY_MISMATCH),
    ],
)
def test_attack_family_derives_expected_risk(case_name, expected_risk):
    case_map = dict(build_adversarial_cases())
    fixture = case_map[case_name]
    analyzer = TrainingExecutionProvenanceAnalyzer(fixture["policy"])
    risks = analyzer.derive(fixture["manifest"], fixture["p9c"], NOW)
    assert expected_risk in risks


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("declared_admission_bound", False),
        ("declared_job_identity_bound", False),
        ("declared_code_config_bound", False),
        ("declared_environment_safe", False),
        ("declared_secrets_least_privilege", False),
        ("declared_capabilities_least_privilege", False),
        ("declared_execution_safe", False),
    ],
)
def test_caller_declared_summary_cannot_override_derived_evidence(field, value):
    fixture = build_fixture()
    request = replace(fixture["request"], **{field: value})
    with pytest.raises(TrainingExecutionSecurityRejected) as exc:
        TrainingExecutionProvenanceAnalyzer(fixture["policy"]).evaluate(
            request, fixture["manifest"], fixture["p9c"]
        )
    assert exc.value.reason == TrainingExecutionRejectReason.DECLARED_SUMMARY_MISMATCH


@pytest.mark.parametrize(
    "request_mutation",
    [
        lambda r: replace(r, execution_id="other"),
        lambda r: replace(r, manifest_sha256=h("other")),
        lambda r: replace(r, evaluated_at_epoch=NOW + 301),
        lambda r: replace(r, evaluated_at_epoch=NOW - 6),
    ],
)
def test_request_binding_and_freshness_fail_closed(request_mutation):
    fixture = build_fixture()
    with pytest.raises(TrainingExecutionSecurityRejected) as exc:
        TrainingExecutionProvenanceAnalyzer(fixture["policy"]).evaluate(
            request_mutation(fixture["request"]), fixture["manifest"], fixture["p9c"]
        )
    assert exc.value.reason == TrainingExecutionRejectReason.REQUEST_INVALID


def test_vulnerable_baseline_accepts_every_adversarial_case():
    vulnerable = VulnerableCallerDeclaredTrainingExecutionSafety()
    cases = build_adversarial_cases()
    assert len(cases) >= 140
    assert all(vulnerable.evaluate(f["request"], f["manifest"], f["p9c"]) for _, f in cases)


def test_hardened_boundary_blocks_every_adversarial_case():
    cases = build_adversarial_cases()
    assert all(not _hardened_allows(fixture) for _, fixture in cases)


@pytest.mark.parametrize("name,fixture", build_safe_cases())
def test_safe_cases_are_accepted(name, fixture):
    assert name.startswith("safe-")
    assert _hardened_allows(fixture)
