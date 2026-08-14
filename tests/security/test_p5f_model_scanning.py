from __future__ import annotations

import pytest

from aegis.model_supply_chain.model_scanning import (
    ModelPoisoningBackdoorScanner,
    ModelScanRejected,
)
from evals.p5f_model_scanning import (
    P5F_DATASET_SHA256,
    P5F_FIXTURE_SHA256,
    attack_cases,
    benign_cases,
    build_report,
    scan_policy,
    scan_request,
    verified_package,
    verified_runtime,
)


@pytest.mark.parametrize("case", attack_cases(), ids=lambda case: case["attempt"].attempt_id)
def test_p5f_adversarial_cases_fail_closed(case):
    scanner = ModelPoisoningBackdoorScanner(scan_policy())
    with pytest.raises(ModelScanRejected) as raised:
        scanner.evaluate(
            request=scan_request(),
            package=case["package"],
            runtime=case["runtime"],
            evidence=case["evidence"],
        )
    assert raised.value.reason is case["reason"]


@pytest.mark.parametrize("case", benign_cases(), ids=lambda case: case["attempt"].attempt_id)
def test_p5f_benign_cases_are_admitted(case):
    scanner = ModelPoisoningBackdoorScanner(scan_policy())
    handle = scanner.evaluate(
        request=scan_request(),
        package=verified_package(),
        runtime=verified_runtime(),
        evidence=case["evidence"],
    )
    assert handle.indicator_count == 0
    assert handle.static_indicators_clear
    assert handle.synthetic_probe_indicators_clear
    assert not handle.raw_model_bytes_scanned
    assert not handle.model_executed
    assert handle.network_operations == 0


def test_p5f_evaluation_metrics_are_deterministic():
    report = build_report()
    assert report["metrics"] == {
        "adversarial_cases": 16,
        "vulnerable_asr": "16/16",
        "hardened_asr": "0/16",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }


def test_p5f_hashes_are_deterministic():
    assert P5F_DATASET_SHA256 == "a69d318ed7a674e272b40bade12a1099aecdffdcce3275e500292715be25b719"
    assert P5F_FIXTURE_SHA256 == "117a2473d2df1f5825ba6040aada6b92a363be612520b57b05ebbddc37ada580"
