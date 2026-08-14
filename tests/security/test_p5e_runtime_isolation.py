from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.model_supply_chain.package_provenance import ModelPackageComponentRole
from aegis.model_supply_chain.runtime_isolation import (
    P5E_REQUIRED_ISOLATION_MODE,
    P5E_RUNTIME_ADMISSION_MODE,
    P5E_RUNTIME_POLICY_VERSION,
    RestrictedModelRuntimeBoundary,
    RuntimeAdmissionRejected,
    RuntimeAdmissionRejectReason,
)
from evals import p5e_runtime_isolation as lab


def _boundary() -> RestrictedModelRuntimeBoundary:
    return RestrictedModelRuntimeBoundary()


def test_benign_runtime_plans_are_admitted_as_nonexecuting_sandbox_handles() -> None:
    boundary = _boundary()
    for case in lab.benign_cases():
        handle = boundary.admit(
            request=lab.runtime_request(),
            package=case["package"],
            plan=case["plan"],
        )
        assert handle.sandbox_required is True
        assert handle.isolation_mode == P5E_REQUIRED_ISOLATION_MODE
        assert handle.policy_version == P5E_RUNTIME_POLICY_VERSION
        assert handle.admission_mode == P5E_RUNTIME_ADMISSION_MODE
        assert handle.remote_code_allowed is False
        assert handle.dynamic_code_allowed is False
        assert handle.network_access is False
        assert handle.subprocess_allowed is False
        assert handle.host_filesystem_write is False
        assert handle.environment_passthrough is False
        assert handle.model_bytes_parsed is False
        assert handle.model_executed is False


def test_all_adversarial_runtime_plans_are_rejected() -> None:
    boundary = _boundary()
    for case in lab.attack_cases():
        with pytest.raises(RuntimeAdmissionRejected):
            boundary.admit(
                request=lab.runtime_request(),
                package=case["package"],
                plan=case["plan"],
            )


@pytest.mark.parametrize(
    ("index", "reason"),
    (
        (0, RuntimeAdmissionRejectReason.PARSER_DISALLOWED),
        (1, RuntimeAdmissionRejectReason.DYNAMIC_CODE_DISALLOWED),
        (2, RuntimeAdmissionRejectReason.REMOTE_CODE_REQUIRED),
        (9, RuntimeAdmissionRejectReason.ISOLATION_REQUIRED),
        (10, RuntimeAdmissionRejectReason.BACKEND_DISALLOWED),
        (11, RuntimeAdmissionRejectReason.COMPONENT_ROLE_MISMATCH),
        (12, RuntimeAdmissionRejectReason.COMPONENT_SET_MISMATCH),
        (13, RuntimeAdmissionRejectReason.RESOURCE_LIMIT_EXCEEDED),
        (14, RuntimeAdmissionRejectReason.PACKAGE_UNVERIFIED),
    ),
)
def test_key_attack_classes_have_stable_reject_reasons(
    index: int, reason: RuntimeAdmissionRejectReason
) -> None:
    case = lab.attack_cases()[index]
    with pytest.raises(RuntimeAdmissionRejected) as caught:
        _boundary().admit(
            request=lab.runtime_request(),
            package=case["package"],
            plan=case["plan"],
        )
    assert caught.value.reason is reason


@pytest.mark.parametrize("index", (5, 6, 7, 8))
def test_host_capability_requests_fail_closed(index: int) -> None:
    case = lab.attack_cases()[index]
    with pytest.raises(RuntimeAdmissionRejected) as caught:
        _boundary().admit(
            request=lab.runtime_request(),
            package=case["package"],
            plan=case["plan"],
        )
    assert caught.value.reason is RuntimeAdmissionRejectReason.CAPABILITY_DISALLOWED


@pytest.mark.parametrize("index", (1, 3, 4))
def test_dynamic_module_native_extension_and_custom_ops_fail_closed(index: int) -> None:
    case = lab.attack_cases()[index]
    with pytest.raises(RuntimeAdmissionRejected) as caught:
        _boundary().admit(
            request=lab.runtime_request(),
            package=case["package"],
            plan=case["plan"],
        )
    assert caught.value.reason is RuntimeAdmissionRejectReason.DYNAMIC_CODE_DISALLOWED


def test_runtime_identity_is_bound_to_verified_package_and_request() -> None:
    plan = replace(lab.safe_plan(), runtime_id="other-runtime")
    with pytest.raises(RuntimeAdmissionRejected) as caught:
        _boundary().admit(
            request=lab.runtime_request(),
            package=lab.verified_package(),
            plan=plan,
        )
    assert caught.value.reason is RuntimeAdmissionRejectReason.IDENTITY_MISMATCH


def test_package_component_roles_are_not_reinterpretable_by_runtime_plan() -> None:
    plan = lab._replace_component(
        lab.safe_plan(),
        "adapter",
        role=ModelPackageComponentRole.PRIMARY_MODEL,
    )
    with pytest.raises(RuntimeAdmissionRejected) as caught:
        _boundary().admit(
            request=lab.runtime_request(),
            package=lab.verified_package(),
            plan=plan,
        )
    assert caught.value.reason is RuntimeAdmissionRejectReason.COMPONENT_ROLE_MISMATCH
    assert caught.value.component_id == "adapter"


def test_deterministic_evaluation_metrics_and_hashes_are_stable() -> None:
    report = lab.build_report()
    assert report["dataset_sha256"] == (
        "34d4b0e9f7884fcb545217a0d72afc890ec4dd698e5901b5ed4f20cf1d204b44"
    )
    assert report["fixture_sha256"] == (
        "8b16c23c7f7f864ff1cd24d0b078400dd766e6a26a905ee5a4822397d191c32d"
    )
    assert report["metrics"] == {
        "adversarial_cases": 15,
        "vulnerable_asr": "15/15",
        "hardened_asr": "0/15",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }


def test_eval_claim_boundary_does_not_overclaim_real_sandbox_or_parser_safety() -> None:
    report = lab.build_report()
    assert report["claim_boundary"]["runtime_plan_admission"] is True
    assert report["claim_boundary"]["remote_code_denial"] is True
    assert report["claim_boundary"]["real_parser_memory_safety"] is False
    assert report["claim_boundary"]["kernel_sandbox_enforcement"] is False
    assert report["claim_boundary"]["real_inference_isolation"] is False
    assert report["evidence_hygiene"]["real_model_execution"] is False
    assert report["evidence_hygiene"]["real_sandbox_processes"] is False
