from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from aegis.inference.accelerator_isolation_types import AcceleratorDecision, AcceleratorRisk
from aegis.inference.streaming_security import InferenceStreamingSecurityAnalyzer
from aegis.inference.streaming_security_types import *
from aegis.vulnerable.streaming_security import VulnerableCallerDeclaredStreamingSafety
from evals.p10g_fixture import (
    NOW,
    build_fixture,
    rebind,
    safe_budget_edge_fixture,
    safe_escaped_sse_injection_fixture,
    safe_tool_argument_newline_fixture,
    h,
)


def safe_cases():
    return (
        ("canonical", build_fixture()),
        ("escaped-sse-injection-text", safe_escaped_sse_injection_fixture()),
        ("escaped-tool-argument-newline", safe_tool_argument_newline_fixture()),
        ("budget-edge", safe_budget_edge_fixture()),
    )


def _m(f, **changes):
    return rebind(f, replace(f["manifest"], **changes))


def _s(f, **changes):
    s = replace(f["manifest"].stream, **changes)
    return _m(f, stream=s)


def _frame(f, index: int, **changes):
    frames = list(f["manifest"].stream.frames)
    frames[index] = replace(frames[index], **changes)
    return _s(f, frames=tuple(frames))


def _cancel(f, **changes):
    c = replace(f["manifest"].stream.cancellation, **changes)
    return _s(f, cancellation=c)


def _backpressure(f, **changes):
    b = replace(f["manifest"].stream.backpressure, **changes)
    return _s(f, backpressure=b)


def _p10f(f, **changes):
    out = dict(f)
    out["p10f"] = replace(f["p10f"], **changes)
    return out


def _request(f, **changes):
    out = dict(f)
    out["request"] = replace(f["request"], **changes)
    return out


def adversarial_cases():
    cases = []

    def add(name, fixture):
        cases.append((name, fixture))

    f = build_fixture()
    m = f["manifest"]
    s = m.stream

    add("manifest-schema", _m(f, schema_version="aegis-inference-streaming-output-manifest-v0"))
    add("manifest-id", _m(f, manifest_id="p10g-streaming-security-evil"))
    add("manifest-time", _m(f, created_at_epoch=0))
    add("upstream-digest", _m(f, p10f_assessment_sha256=h("wrong-p10f")))
    add("request-id", _m(f, request_id="request-acme-evil"))
    add("tenant", _m(f, tenant_id="beta", session_id="tenant/beta/session/s-001"))
    add("session", _m(f, session_id="tenant/acme/session/s-evil"))
    add("model-id", _m(f, target_model_id="aegisdesk-helpdesk-security-evil"))
    add("model-revision", _m(f, target_model_revision="rev-evil"))
    add("adapter-order", _m(f, adapter_ids=tuple(reversed(m.adapter_ids))))
    add("adapter-generation", _m(f, adapter_generation=m.adapter_generation - 1))
    add("partition-order", _m(f, partition_ids=tuple(reversed(m.partition_ids))))
    add("network-operation", _m(f, network_operations=1))

    stream_changes = {
        "stream-id": {"stream_id": "stream-acme-evil"},
        "channel-id": {"output_channel_id": "sse-channel-acme-evil"},
        "stream-request": {"request_id": "request-acme-evil"},
        "stream-tenant": {"tenant_id": "beta", "session_id": "tenant/beta/session/s-001"},
        "stream-session": {"session_id": "tenant/acme/session/s-evil"},
        "stream-generation": {"stream_generation": s.stream_generation - 1},
        "content-type": {"content_type": "text/plain"},
        "encoding": {"encoding": "utf-16"},
        "frame-budget": {"max_frame_bytes": s.max_frame_bytes + 1},
        "total-budget": {"max_total_output_bytes": s.max_total_output_bytes + 1},
        "buffer-budget": {"max_buffered_bytes": s.max_buffered_bytes + 1},
        "unacked-budget": {"max_unacked_frames": s.max_unacked_frames + 1},
        "frame-seed": {"frame_chain_seed_sha256": h("wrong-seed")},
    }
    for name, changes in stream_changes.items():
        add(name, _s(f, **changes))

    for i, frame in enumerate(s.frames):
        prefix = f"frame-{i}"
        add(prefix + "-id", _frame(f, i, frame_id=frame.frame_id + "-evil"))
        add(prefix + "-seq", _frame(f, i, seq_no=frame.seq_no + 10))
        add(prefix + "-payload-digest", _frame(f, i, payload_sha256=h("wrong-payload")))
        add(prefix + "-sse-digest", _frame(f, i, sse_sha256=h("wrong-sse")))
        add(prefix + "-encoded-size", _frame(f, i, encoded_bytes=frame.encoded_bytes + 1))
        add(prefix + "-previous", _frame(f, i, previous_frame_sha256=h("wrong-prev")))

    huge = "X" * 1000
    huge_encoded = encode_sse_event(StreamFrameKind.TOKEN, huge)
    add(
        "frame-size-exceeded",
        _frame(
            f,
            0,
            payload_text=huge,
            payload_sha256=text_sha256(huge),
            sse_sha256=hashlib.sha256(huge_encoded).hexdigest(),
            encoded_bytes=len(huge_encoded),
        ),
    )

    frames = list(s.frames)
    frames[1] = replace(frames[1], acked=False)
    frames[2] = replace(frames[2], acked=False)
    frames[3] = replace(frames[3], acked=False)
    add("unacked-window", _s(f, frames=tuple(frames)))

    tool = s.frames[2]
    add("tool-name", _frame(f, 2, tool_name="shell_exec"))
    add("tool-args-digest", _frame(f, 2, tool_arguments_sha256=h("wrong-args")))
    add("tool-payload", _frame(f, 2, payload_text='{"tool":"lookup_ticket","arguments":{"ticket_id":"INC-EVIL"}}'))
    oversized_args = json.dumps({"ticket_id": "INC-1042", "blob": "A" * 400}, separators=(",", ":"))
    oversized_payload = tool_call_payload("lookup_ticket", oversized_args)
    oversized_sse = encode_sse_event(StreamFrameKind.TOOL_CALL, oversized_payload)
    add(
        "tool-args-size",
        _frame(
            f,
            2,
            tool_arguments_json=oversized_args,
            tool_arguments_sha256=digest_json(json.loads(oversized_args)),
            payload_text=oversized_payload,
            payload_sha256=text_sha256(oversized_payload),
            sse_sha256=hashlib.sha256(oversized_sse).hexdigest(),
            encoded_bytes=len(oversized_sse),
        ),
    )

    add("cancel-id", _cancel(f, cancellation_id="stream-cancel-acme-evil"))
    add("cancel-requested", _cancel(f, requested_after_seq=0))
    add("cancel-effective-too-late", _cancel(f, effective_before_seq=10))
    add("cancel-reason", _cancel(f, reason_code="attacker_cancelled"))
    add("cancel-auth", _cancel(f, authorization_sha256=h("wrong-cancel-auth")))
    add("terminal-kind", _s(f, terminal_kind=StreamFrameKind.FINAL))
    add("terminal-frame", _frame(f, 3, kind=StreamFrameKind.FINAL))
    extra = replace(
        s.frames[-1],
        frame_id="stream-frame-acme-0005",
        seq_no=5,
        kind=StreamFrameKind.TOKEN,
        payload_text="after cancel",
        payload_sha256=text_sha256("after cancel"),
        previous_frame_sha256=stream_frame_digest(s.frames[-1]),
        tool_name="",
        tool_arguments_json="",
        tool_arguments_sha256="",
    )
    extra_encoded = encode_sse_event(extra.kind, extra.payload_text)
    extra = replace(extra, sse_sha256=hashlib.sha256(extra_encoded).hexdigest(), encoded_bytes=len(extra_encoded))
    add("output-after-cancel", _s(f, frames=s.frames + (extra,)))

    add("backpressure-bytes", _backpressure(f, observed_high_water_bytes=s.max_buffered_bytes + 1))
    add("backpressure-unacked", _backpressure(f, observed_high_water_unacked_frames=s.max_unacked_frames + 1))
    add("backpressure-not-observed", _backpressure(f, producer_pause_count=0))
    add("queue-not-drained", _backpressure(f, queue_drained=False))

    add("stream-replay", _m(f, prior_stream_ids=m.prior_stream_ids + (s.stream_id,)))
    add("prior-ledger", _m(f, prior_stream_ledger_sha256=h("wrong-ledger")))

    upstream = f["p10f"]
    add("upstream-deny", _p10f(f, decision=AcceleratorDecision.DENY))
    add("upstream-risk", _p10f(f, risks=(AcceleratorRisk.UPSTREAM_P10E_INVALID,)))
    positives = (
        "upstream_p10e_bound",
        "host_probe_bound",
        "device_assignment_verified",
        "dma_isolation_verified",
        "memory_isolation_verified",
        "side_channel_profile_verified",
        "lease_safety_verified",
    )
    for field in positives:
        add("upstream-flag-" + field, _p10f(f, **{field: False}))
    nonclaims = (
        "caller_declared_safety_trusted",
        "live_gpu_hardware_validated",
        "production_gpu_runtime_integrated",
        "production_cgroup_enforcement_verified",
        "production_iommu_enforcement_verified",
        "physical_vram_zeroization_verified",
        "dma_attack_resistance_validated",
        "side_channel_resistance_validated",
        "hardware_attestation_verified",
    )
    for field in nonclaims:
        add("upstream-nonclaim-" + field, _p10f(f, **{field: True}))
    add("upstream-schema", _p10f(f, assessment_schema_version="aegis-inference-accelerator-isolation-assessment-v0"))
    add("upstream-mode", _p10f(f, assessment_mode="caller-trusted"))
    add("upstream-evidence", _p10f(f, assessment_evidence_sha256=h("wrong-p10f-assessment")))
    add("upstream-request", _p10f(f, request_id="request-acme-evil"))
    add("upstream-tenant", _p10f(f, tenant_id="beta"))
    add("upstream-session", _p10f(f, session_id="tenant/acme/session/s-evil"))
    add("upstream-model", _p10f(f, target_model_id="aegisdesk-helpdesk-security-evil"))
    add("upstream-revision", _p10f(f, target_model_revision="rev-evil"))
    add("upstream-adapters", _p10f(f, adapter_ids=tuple(reversed(upstream.adapter_ids))))
    add("upstream-generation", _p10f(f, adapter_generation=upstream.adapter_generation - 1))
    add("upstream-partitions", _p10f(f, partition_ids=tuple(reversed(upstream.partition_ids))))

    add("request-manifest-id", _request(f, manifest_id="p10g-streaming-security-evil"))
    add("request-manifest-sha", _request(f, manifest_sha256=h("wrong-manifest")))
    add("request-stale", _request(f, evaluated_at_epoch=NOW + 1000))
    add("request-early", _request(f, evaluated_at_epoch=NOW - 1000))
    add("request-id-summary", _request(f, declared_request_id="request-acme-evil"))
    add("request-tenant-summary", _request(f, declared_tenant_id="beta"))
    add("request-session-summary", _request(f, declared_session_id="tenant/acme/session/s-evil"))
    add("request-stream-summary", _request(f, declared_stream_id="stream-acme-evil"))
    add("request-channel-summary", _request(f, declared_output_channel_id="sse-channel-acme-evil"))
    add("request-frame-summary", _request(f, declared_frame_ids=tuple(reversed(f["request"].declared_frame_ids))))
    add("request-terminal-summary", _request(f, declared_terminal_kind=StreamFrameKind.FINAL))
    for field in (
        "declared_upstream_p10f_bound",
        "declared_output_channel_safe",
        "declared_frame_integrity_safe",
        "declared_backpressure_safe",
        "declared_cancellation_safe",
        "declared_tool_framing_safe",
        "declared_replay_safe",
    ):
        add("request-summary-" + field, _request(f, **{field: False}))

    p = f["policy"]
    add("policy-version", {**f, "policy": replace(p, policy_version="inference-streaming-output-integrity-v0")})
    add("policy-content-type", {**f, "policy": replace(p, expected_content_type="application/json")})
    add("policy-encoding", {**f, "policy": replace(p, expected_encoding="utf-16")})
    add("policy-frame-zero", {**f, "policy": replace(p, max_frame_bytes=0)})
    add("policy-total-too-small", {**f, "policy": replace(p, max_total_output_bytes=100)})
    add("policy-buffer-too-large", {**f, "policy": replace(p, max_buffered_bytes=p.max_total_output_bytes + 1)})
    add("policy-tools-empty", {**f, "policy": replace(p, allowed_tool_names=())})
    add("policy-terminal", {**f, "policy": replace(p, expected_terminal_kind=StreamFrameKind.TOKEN)})
    add("policy-cancel-auth", {**f, "policy": replace(p, expected_cancellation_authorization_sha256=h("wrong-auth"))})
    add("policy-prior-ledger", {**f, "policy": replace(p, expected_prior_stream_ledger_sha256=h("wrong-ledger"))})

    return tuple(cases)


def _hardened_accepts(fixture) -> bool:
    try:
        assessment = InferenceStreamingSecurityAnalyzer(fixture["policy"]).evaluate(
            fixture["request"], fixture["manifest"], fixture["p10f"]
        )
    except ValueError:
        return False
    return assessment.decision == StreamDecision.ALLOW


def _source_digest() -> str:
    root = Path(__file__).resolve().parents[1]
    paths = (
        root / "evals" / "p10g_fixture.py",
        root / "evals" / "p10g_streaming_security.py",
    )
    hsh = hashlib.sha256()
    for path in paths:
        hsh.update(path.read_bytes())
    return hsh.hexdigest()


def run_evaluation() -> dict:
    safe = safe_cases()
    attacks = adversarial_cases()
    vulnerable_success = sum(
        VulnerableCallerDeclaredStreamingSafety.accepts(fixture["request"])
        for _, fixture in attacks
    )
    hardened_success = sum(_hardened_accepts(fixture) for _, fixture in attacks)
    safe_accepts = sum(_hardened_accepts(fixture) for _, fixture in safe)
    hardened_fpr = len(safe) - safe_accepts
    canonical = build_fixture()
    clean = InferenceStreamingSecurityAnalyzer(canonical["policy"]).evaluate(
        canonical["request"], canonical["manifest"], canonical["p10f"]
    )
    attack_names = tuple(name for name, _ in attacks)
    return {
        "adversarial_cases": len(attacks),
        "vulnerable_asr": f"{vulnerable_success}/{len(attacks)}",
        "hardened_asr": f"{hardened_success}/{len(attacks)}",
        "hardened_fpr": f"{hardened_fpr}/{len(safe)}",
        "safe_task_rate": f"{safe_accepts}/{len(safe)}",
        "streaming_manifest_sha256": inference_streaming_security_manifest_digest(canonical["manifest"]),
        "adversarial_dataset_sha256": digest_json({"case_names": attack_names}),
        "fixture_evaluator_sha256": _source_digest(),
        "clean_assessment_sha256": clean.assessment_evidence_sha256,
        "decision": clean.decision.value,
    }


def main() -> int:
    result = run_evaluation()
    print(json.dumps(result, sort_keys=True))
    if result["hardened_asr"] != f"0/{result['adversarial_cases']}":
        return 1
    if result["hardened_fpr"] != "0/4" or result["safe_task_rate"] != "4/4":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
