from __future__ import annotations

import pytest

from aegis.model_supply_chain.package_provenance import (
    ModelPackageRejectReason,
    ModelPackageRejected,
    RestrictedModelPackageLoader,
)
from evals.p5b_model_package_provenance import (
    _attack_cases,
    _benign_cases,
    _dataset_hash,
    _fixture_hash,
    _policy,
    build_report,
)


def _hardened():
    return RestrictedModelPackageLoader(_policy())


def _load(case):
    return _hardened().load(
        request=case["request"],
        manifest=case["manifest"],
        package_signature=case["signature"],
        artifacts=case["artifacts"],
    )


def test_p5b_accepts_all_benign_complete_packages_without_execution() -> None:
    for case in _benign_cases():
        handle = _load(case)
        assert handle.package_signature_verified is True
        assert handle.transitive_components_verified is True
        assert handle.dependency_graph_verified is True
        assert handle.remote_code_required is False
        assert handle.deserialized is False
        assert handle.code_execution_capable is False
        assert handle.network_operations == 0
        assert set(handle.component_artifact_ids) == set(case["artifacts"])


def test_p5b_rejects_missing_and_unexpected_dependency_closure() -> None:
    attacks = {case["scenario"]: case for case in _attack_cases()}
    for scenario in ("missing_required_component", "unexpected_component_injection"):
        with pytest.raises(ModelPackageRejected) as captured:
            _load(attacks[scenario])
        assert captured.value.reason is ModelPackageRejectReason.COMPONENT_SET_MISMATCH


def test_p5b_rejects_adapter_from_globally_trusted_but_role_disallowed_publisher() -> None:
    case = next(case for case in _attack_cases() if case["scenario"] == "adapter_role_publisher_bypass")
    with pytest.raises(ModelPackageRejected) as captured:
        _load(case)
    assert captured.value.reason is ModelPackageRejectReason.COMPONENT_PUBLISHER_DISALLOWED
    assert captured.value.component_id == "adapter"


def test_p5b_rejects_remote_code_requirement_before_handoff() -> None:
    case = next(case for case in _attack_cases() if case["scenario"] == "remote_code_requirement")
    with pytest.raises(ModelPackageRejected) as captured:
        _load(case)
    assert captured.value.reason is ModelPackageRejectReason.REMOTE_CODE_REQUIRED
    assert captured.value.component_id == "config"


def test_p5b_rejects_tampered_transitive_component_and_preserves_nested_reason() -> None:
    case = next(case for case in _attack_cases() if case["scenario"] == "tampered_transitive_component")
    with pytest.raises(ModelPackageRejected) as captured:
        _load(case)
    assert captured.value.reason is ModelPackageRejectReason.COMPONENT_INVALID
    assert captured.value.component_id == "config"
    assert captured.value.nested_reason == "size_mismatch"


def test_p5b_rejects_cyclic_signed_dependency_graph() -> None:
    case = next(case for case in _attack_cases() if case["scenario"] == "cyclic_dependency_graph")
    with pytest.raises(ModelPackageRejected) as captured:
        _load(case)
    assert captured.value.reason is ModelPackageRejectReason.DEPENDENCY_INVALID


def test_p5b_rejects_forged_package_signature_and_identity_substitution() -> None:
    attacks = {case["scenario"]: case for case in _attack_cases()}

    with pytest.raises(ModelPackageRejected) as signature_error:
        _load(attacks["forged_package_signature"])
    assert signature_error.value.reason is ModelPackageRejectReason.PACKAGE_SIGNATURE_INVALID

    with pytest.raises(ModelPackageRejected) as identity_error:
        _load(attacks["package_identity_substitution"])
    assert identity_error.value.reason is ModelPackageRejectReason.IDENTITY_MISMATCH


def test_p5b_rejects_valid_same_publisher_artifact_not_pinned_by_package() -> None:
    case = next(
        case
        for case in _attack_cases()
        if case["scenario"] == "same_publisher_component_substitution"
    )
    with pytest.raises(ModelPackageRejected) as captured:
        _load(case)
    assert captured.value.reason is ModelPackageRejectReason.COMPONENT_ROLE_MISMATCH
    assert captured.value.component_id == "config"


def test_p5b_report_has_expected_security_delta_and_stable_hashes() -> None:
    first = build_report()
    second = build_report()

    vulnerable = first["variants"]["vulnerable"]["metrics"]
    hardened = first["variants"]["hardened"]["metrics"]

    assert vulnerable["asr"]["successful_policy_violations"] == 9
    assert vulnerable["asr"]["valid_adversarial_attempts"] == 9
    assert hardened["asr"]["successful_policy_violations"] == 0
    assert hardened["asr"]["valid_adversarial_attempts"] == 9
    assert hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
    assert hardened["fpr"]["valid_benign_requests"] == 3
    assert hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 3
    assert hardened["safe_task_rate"]["authorized_tasks_attempted"] == 3

    assert first["eval_dataset_hash_sha256"] == second["eval_dataset_hash_sha256"] == _dataset_hash()
    assert first["fixture_hash_sha256"] == second["fixture_hash_sha256"] == _fixture_hash()
    assert len(first["eval_dataset_hash_sha256"]) == 64
    assert len(first["fixture_hash_sha256"]) == 64
