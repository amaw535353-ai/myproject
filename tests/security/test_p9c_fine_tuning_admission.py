from dataclasses import replace

import pytest

from aegis.training.data_poisoning_types import PoisoningDecision
from aegis.training.fine_tuning_security import FineTuningAdmissionAnalyzer
from aegis.training.fine_tuning_types import (
    FineTuneDecision,
    FineTuneMode,
    FineTuneRejectReason,
    FineTuneRisk,
    FineTuningSecurityRejected,
    fine_tuning_manifest_digest,
)
from aegis.vulnerable.training_fine_tuning import VulnerableCallerDeclaredFineTuningSafety
from evals.p9c_fixture import NOW, build_fixture, h, rebind


def evaluate(f):
    return FineTuningAdmissionAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9b"])


def test_clean_fixture_allows_and_preserves_nonclaims():
    result = evaluate(build_fixture())
    assert result.decision is FineTuneDecision.ALLOW
    assert result.risks == ()
    assert result.upstream_p9b_bound
    assert result.authorization_verified
    assert result.base_model_binding_verified
    assert result.adapter_policy_verified
    assert result.hyperparameter_policy_verified
    assert not result.caller_declared_safety_trusted
    assert not result.production_training_runtime_integrated
    assert not result.production_identity_provider_integrated
    assert not result.proof_of_training_execution


def test_vulnerable_baseline_trusts_caller_booleans():
    f = build_fixture()
    m = replace(f["manifest"], principal_id="attacker-principal")
    f = rebind(f, manifest=m)
    assert VulnerableCallerDeclaredFineTuningSafety().evaluate(f["request"], f["manifest"], f["p9b"])
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


@pytest.mark.parametrize("field", ["upstream_p9a_bound", "record_integrity_verified", "label_integrity_verified", "contributor_trust_verified", "poisoning_indicators_clear"])
def test_rejects_degraded_p9b_flags(field):
    f = build_fixture()
    p9b = replace(f["p9b"], **{field: False})
    f = rebind(f, p9b=p9b)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


def test_rejects_p9b_assessment_digest_swap():
    f = build_fixture()
    p9b = replace(f["p9b"], assessment_evidence_sha256=h("swapped-p9b"))
    f = rebind(f, p9b=p9b)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


def test_rejects_selected_data_substitution():
    f = build_fixture()
    m = replace(f["manifest"], selected_record_ids=f["manifest"].selected_record_ids[:-1])
    f = rebind(f, manifest=m)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


def test_rejects_principal_task_laundering():
    f = build_fixture()
    m = replace(f["manifest"], principal_id="trainer-untrusted")
    f = rebind(f, manifest=m)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


def test_rejects_expired_authorization():
    f = build_fixture()
    auth = replace(f["manifest"].authorization, expires_at_epoch=NOW - 1)
    m = replace(f["manifest"], authorization=auth)
    f = rebind(f, manifest=m)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


@pytest.mark.parametrize("field,value", [
    ("model_id", "evil-base"),
    ("revision", "r41"),
    ("artifact_sha256", h("evil-artifact")),
    ("package_sha256", h("evil-package")),
    ("tokenizer_sha256", h("evil-tokenizer")),
    ("runtime_profile", "remote-code-runtime"),
])
def test_rejects_base_model_substitution(field, value):
    f = build_fixture()
    base = replace(f["manifest"].base_model, **{field: value})
    m = replace(f["manifest"], base_model=base)
    f = rebind(f, manifest=m)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


@pytest.mark.parametrize("updates", [
    {"serialization_format": "pickle"},
    {"rank": 128},
    {"alpha_bps": 9000},
    {"target_modules": ("lm_head",)},
    {"init_sha256": h("wrong-init")},
    {"remote_code": True},
    {"custom_code": True},
    {"native_extensions": True},
    {"parent_adapter_ids": ("missing-parent",)},
])
def test_rejects_unsafe_adapter_controls(updates):
    f = build_fixture()
    first = replace(f["manifest"].adapters[0], **updates)
    m = replace(f["manifest"], adapters=(first, f["manifest"].adapters[1]))
    f = rebind(f, manifest=m)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


@pytest.mark.parametrize("updates", [
    {"learning_rate_micros": 9999},
    {"epochs_milli": 9000},
    {"batch_size": 128},
    {"max_steps": 99999},
    {"seed": 999},
    {"gradient_accumulation_steps": 99},
])
def test_rejects_hyperparameter_policy_escape(updates):
    f = build_fixture()
    hp = replace(f["manifest"].hyperparameters, **updates)
    m = replace(f["manifest"], hyperparameters=hp)
    f = rebind(f, manifest=m)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


def test_rejects_output_identity_substitution():
    f = build_fixture()
    m = replace(f["manifest"], planned_output_artifact_id="adapter://attacker/output")
    f = rebind(f, manifest=m)
    with pytest.raises(FineTuningSecurityRejected):
        evaluate(f)


def test_request_manifest_digest_cannot_be_forged():
    f = build_fixture()
    req = replace(f["request"], manifest_sha256=h("wrong-request-manifest"))
    f = dict(f, request=req)
    with pytest.raises(FineTuningSecurityRejected) as exc:
        evaluate(f)
    assert exc.value.reason is FineTuneRejectReason.REQUEST_INVALID


def test_policy_manifest_pin_is_fail_closed():
    f = build_fixture()
    policy = replace(f["policy"], expected_manifest_sha256=h("wrong-policy-pin"))
    f = dict(f, policy=policy)
    with pytest.raises(FineTuningSecurityRejected) as exc:
        evaluate(f)
    assert exc.value.reason is FineTuneRejectReason.MANIFEST_DIGEST_MISMATCH


def test_assessment_digest_is_deterministic():
    first = evaluate(build_fixture())
    second = evaluate(build_fixture())
    assert first.assessment_evidence_sha256 == second.assessment_evidence_sha256


def test_allowed_seed_variant_remains_safe_when_policy_manifest_pin_matches():
    f = build_fixture()
    hp = replace(f["manifest"].hyperparameters, seed=23)
    m = replace(f["manifest"], hyperparameters=hp)
    f = rebind(f, manifest=m)
    result = evaluate(f)
    assert result.decision is FineTuneDecision.ALLOW
