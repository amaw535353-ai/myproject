from __future__ import annotations

import json

import pytest

from aegis.inference.streaming_security import InferenceStreamingSecurityAnalyzer
from aegis.inference.streaming_security_types import *
from aegis.vulnerable.streaming_security import VulnerableCallerDeclaredStreamingSafety
from evals.p10g_fixture import build_fixture
from evals.p10g_streaming_security import adversarial_cases, safe_cases


def _evaluate(f):
    return InferenceStreamingSecurityAnalyzer(f["policy"]).evaluate(
        f["request"], f["manifest"], f["p10f"]
    )


@pytest.mark.parametrize("name,fixture", safe_cases(), ids=lambda value: str(value)[:80])
def test_safe_cases_allow(name, fixture):
    assessment = _evaluate(fixture)
    assert assessment.decision == StreamDecision.ALLOW
    assert assessment.risks == ()
    assert assessment.upstream_p10f_bound
    assert assessment.output_channel_verified
    assert assessment.frame_integrity_verified
    assert assessment.backpressure_verified
    assert assessment.cancellation_verified
    assert assessment.tool_framing_verified
    assert assessment.replay_verified
    assert not assessment.caller_declared_safety_trusted
    assert not assessment.production_streaming_gateway_integrated
    assert not assessment.kernel_tcp_backpressure_validated
    assert not assessment.distributed_cancellation_linearizability_validated
    assert not assessment.production_tool_dispatch_integrated
    assert not assessment.semantic_output_safety_validated
    assert not assessment.remote_client_disconnect_semantics_validated


@pytest.mark.parametrize("name,fixture", adversarial_cases(), ids=lambda value: str(value)[:80])
def test_adversarial_cases_block(name, fixture):
    assert VulnerableCallerDeclaredStreamingSafety.accepts(fixture["request"])
    try:
        assessment = _evaluate(fixture)
    except ValueError:
        return
    assert assessment.decision == StreamDecision.DENY, name
    assert assessment.risks, name


def test_canonical_cancellation_is_terminal_and_bounded():
    f = build_fixture()
    stream = f["manifest"].stream
    assert stream.terminal_kind == StreamFrameKind.CANCELLED
    assert stream.frames[-1].kind == StreamFrameKind.CANCELLED
    assert stream.cancellation.requested_after_seq == 2
    assert stream.cancellation.effective_before_seq == 4
    assert stream.cancellation.effective_before_seq - stream.cancellation.requested_after_seq <= f["policy"].max_cancel_lag_frames


def test_sse_encoder_contains_payload_as_json_not_raw_event_boundary():
    payload = "safe\n\nevent: injected\ndata: pwn"
    encoded = encode_sse_event(StreamFrameKind.TOKEN, payload)
    assert b"\n\nevent: injected" not in encoded[:-2]
    lines = encoded.decode("utf-8").splitlines()
    data = json.loads(lines[1].removeprefix("data: "))
    assert data["payload"] == payload


def test_tool_payload_is_canonical_json_object():
    args = '{"ticket_id":"INC-1042","note":"line1\\nline2"}'
    payload = tool_call_payload("lookup_ticket", args)
    parsed = json.loads(payload)
    assert parsed == {
        "tool": "lookup_ticket",
        "arguments": {"ticket_id": "INC-1042", "note": "line1\nline2"},
    }


def test_assessment_sha_is_deterministic():
    f = build_fixture()
    first = _evaluate(f)
    second = _evaluate(f)
    assert first.assessment_evidence_sha256 == second.assessment_evidence_sha256


def test_manifest_digest_is_deterministic():
    f = build_fixture()
    assert inference_streaming_security_manifest_digest(f["manifest"]) == f["request"].manifest_sha256


def test_vulnerable_baseline_trusts_only_final_boolean():
    f = build_fixture()
    assert VulnerableCallerDeclaredStreamingSafety.accepts(f["request"])
    request = InferenceStreamingSecurityRequest(
        **{**f["request"].__dict__, "declared_streaming_safe": False}
    )
    assert not VulnerableCallerDeclaredStreamingSafety.accepts(request)
