from __future__ import annotations

import pytest

from aegis.model_serving.abuse_response import (
    AbuseTelemetryRejected,
    AbuseTelemetryRejectReason,
    IncidentAction,
    ServingAbuseResponseEngine,
    serving_telemetry_batch_digest,
)
from evals.p5i_serving_abuse_response import (
    P5I_DATASET_SHA256,
    P5I_FIXTURE_SHA256,
    NOW,
    _ACTION_ORDER,
    abuse_policy,
    attack_cases,
    benign_cases,
    build_report,
)


def test_p5i_deterministic_metrics() -> None:
    report = build_report()
    assert report["metrics"] == {
        "adversarial_cases": 17,
        "vulnerable_asr": "17/17",
        "hardened_asr": "0/17",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }
    assert len(P5I_DATASET_SHA256) == 64
    assert len(P5I_FIXTURE_SHA256) == 64


@pytest.mark.parametrize("case", attack_cases(), ids=lambda case: case["case_id"])
def test_all_attack_cases_fail_closed_or_escalate(case: dict[str, object]) -> None:
    engine = ServingAbuseResponseEngine(abuse_policy())
    for index, prefill in enumerate(case["prefill"]):
        engine.evaluate(
            incident_id=f"prefill-{case['case_id']}-{index}",
            attestation=case["attestation"],
            signed_batch=prefill,
            evaluated_at_epoch=NOW,
        )
    try:
        decision = engine.evaluate(
            incident_id=f"incident-{case['case_id']}",
            attestation=case["attestation"],
            signed_batch=case["signed_batch"],
            evaluated_at_epoch=case["evaluated_at"],
        )
    except AbuseTelemetryRejected:
        assert case["minimum_action"] is None
        return

    minimum = case["minimum_action"]
    assert minimum is not None
    assert _ACTION_ORDER[decision.action] >= _ACTION_ORDER[minimum]


@pytest.mark.parametrize("case", benign_cases(), ids=lambda case: case["case_id"])
def test_benign_cases_remain_observe(case: dict[str, object]) -> None:
    decision = ServingAbuseResponseEngine(abuse_policy()).evaluate(
        incident_id=f"incident-{case['case_id']}",
        attestation=case["attestation"],
        signed_batch=case["signed_batch"],
        evaluated_at_epoch=case["evaluated_at"],
    )
    assert decision.action is IncidentAction.OBSERVE
    assert decision.telemetry_signature_verified
    assert decision.telemetry_chain_verified
    assert decision.telemetry_complete
    assert not decision.quarantine_required
    assert not decision.deployment_revocation_required
    assert not decision.real_siem_action
    assert not decision.real_soar_action
    assert not decision.distributed_enforcement
    assert decision.network_operations == 0


def test_canary_signal_requires_deployment_revocation() -> None:
    case = attack_cases()[-1]
    decision = ServingAbuseResponseEngine(abuse_policy()).evaluate(
        incident_id="canary-incident",
        attestation=case["attestation"],
        signed_batch=case["signed_batch"],
        evaluated_at_epoch=case["evaluated_at"],
    )
    assert decision.action is IncidentAction.REVOKE_DEPLOYMENT
    assert decision.quarantine_required
    assert decision.deployment_revocation_required


def test_chain_fork_has_specific_reject_reason() -> None:
    case = attack_cases()[12]
    engine = ServingAbuseResponseEngine(abuse_policy())
    engine.evaluate(
        incident_id="prefill-chain",
        attestation=case["attestation"],
        signed_batch=case["prefill"][0],
        evaluated_at_epoch=NOW,
    )
    with pytest.raises(AbuseTelemetryRejected) as excinfo:
        engine.evaluate(
            incident_id="fork-chain",
            attestation=case["attestation"],
            signed_batch=case["signed_batch"],
            evaluated_at_epoch=NOW,
        )
    assert excinfo.value.reason is AbuseTelemetryRejectReason.CHAIN_MISMATCH


def test_batch_digest_is_deterministic() -> None:
    case = benign_cases()[0]
    first = serving_telemetry_batch_digest(case["signed_batch"].batch)
    second = serving_telemetry_batch_digest(case["signed_batch"].batch)
    assert first == second
    assert len(first) == 64
