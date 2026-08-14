from dataclasses import replace

import pytest

from aegis.model_supply_chain.privacy_controls import (
    ModelPrivacyGateway,
    PrivacyControlRejected,
    PrivacyRejectReason,
)
from evals.p5g_model_privacy import (
    P5G_DATASET_SHA256,
    P5G_FIXTURE_SHA256,
    attack_cases,
    benign_cases,
    build_report,
    privacy_policy,
    safe_evidence,
    safe_request,
    verified_runtime,
    verified_scan,
)


def test_p5g_deterministic_metrics() -> None:
    report = build_report()
    assert report["metrics"] == {
        "adversarial_cases": 16,
        "vulnerable_asr": "16/16",
        "hardened_asr": "0/16",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }
    assert len(P5G_DATASET_SHA256) == 64
    assert len(P5G_FIXTURE_SHA256) == 64


def test_all_attack_cases_fail_closed() -> None:
    for case in attack_cases():
        gateway = ModelPrivacyGateway(privacy_policy())
        for prefill_request in case["prefill"]:
            gateway.release(
                request=prefill_request,
                runtime=verified_runtime(),
                scan=verified_scan(),
                evidence=safe_evidence(),
            )
        with pytest.raises(PrivacyControlRejected):
            gateway.release(
                request=case["request"],
                runtime=case["runtime"],
                scan=case["scan"],
                evidence=case["evidence"],
            )


def test_benign_cases_are_minimized_and_inert() -> None:
    for case in benign_cases():
        handle = ModelPrivacyGateway(privacy_policy()).release(
            request=case["request"],
            runtime=case["runtime"],
            scan=case["scan"],
            evidence=case["evidence"],
        )
        assert handle.output_minimized
        assert handle.sensitive_channels_denied
        assert not handle.real_model_inference
        assert not handle.raw_logits_exposed
        assert not handle.embeddings_exposed
        assert not handle.hidden_states_exposed
        assert handle.network_operations == 0


def test_query_id_replay_is_rejected() -> None:
    gateway = ModelPrivacyGateway(privacy_policy())
    request = safe_request(query_id="q-replay", fingerprint="fp-replay-0001")
    gateway.release(
        request=request,
        runtime=verified_runtime(),
        scan=verified_scan(),
        evidence=safe_evidence(),
    )
    with pytest.raises(PrivacyControlRejected) as excinfo:
        gateway.release(
            request=request,
            runtime=verified_runtime(),
            scan=verified_scan(),
            evidence=safe_evidence(),
        )
    assert excinfo.value.reason is PrivacyRejectReason.QUERY_REPLAY


def test_response_detail_cannot_exceed_request() -> None:
    gateway = ModelPrivacyGateway(privacy_policy())
    with pytest.raises(PrivacyControlRejected) as excinfo:
        gateway.release(
            request=safe_request(),
            runtime=verified_runtime(),
            scan=verified_scan(),
            evidence=replace(safe_evidence(), returned_top_k=1),
        )
    assert excinfo.value.reason is PrivacyRejectReason.RESPONSE_EVIDENCE_INVALID
