from __future__ import annotations

from dataclasses import replace
import hashlib
import json

from aegis.inference.accelerator_isolation_types import *
from aegis.inference.streaming_security_types import *

NOW = 1_800_031_200
MANIFEST_ID = "p10g-streaming-security-001"
P10F_CLEAN_ASSESSMENT_SHA256 = "a84cad654ea4ee8aadf8f8a0750c55fc0fa1a7826a188504ca99c254a2627053"
P10F_MANIFEST_SHA256 = "bd141b7af9903eaecd169507c1ac4aeb9879e49bd654b040ddbaf0304d15a2dc"
REQUEST_ID = "request-acme-0001"
TENANT_ID = "acme"
SESSION_ID = "tenant/acme/session/s-001"
TARGET_MODEL_ID = "aegisdesk-helpdesk-security"
TARGET_MODEL_REVISION = "rev-2026-08-p9h"
ADAPTER_IDS = ("adapter-security-policy", "adapter-acme-helpdesk")
ADAPTER_GENERATION = 12
PARTITION_IDS = ("partition-acme-mig-0", "partition-acme-exclusive-1")
LEASE_IDS = ("gpu-lease-acme-mig-001", "gpu-lease-acme-exclusive-002")
STREAM_ID = "stream-acme-0001"
OUTPUT_CHANNEL_ID = "sse-channel-acme-0001"
STREAM_GENERATION = 21
FRAME_IDS = (
    "stream-frame-acme-0001",
    "stream-frame-acme-0002",
    "stream-frame-acme-0003",
    "stream-frame-acme-0004",
)
CANCELLATION_ID = "stream-cancel-acme-0001"
CANCEL_REASON = "client_cancelled"


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def p10f_assessment() -> VerifiedInferenceAcceleratorIsolationAssessment:
    return VerifiedInferenceAcceleratorIsolationAssessment(
        "p10f-accelerator-isolation-001",
        P10F_MANIFEST_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        AcceleratorDecision.ALLOW,
        (),
        h("p10e-clean"),
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        LEASE_IDS,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        P10F_ASSESSMENT_SCHEMA_VERSION,
        P10F_ASSESSMENT_MODE,
        P10F_CLEAN_ASSESSMENT_SHA256,
    )


def _frame(
    frame_id: str,
    seq_no: int,
    kind: StreamFrameKind,
    payload_text: str,
    previous: str,
    *,
    acked: bool,
    tool_name: str = "",
    tool_arguments_json: str = "",
) -> StreamFrameEvidence:
    encoded = encode_sse_event(kind, payload_text)
    tool_digest = ""
    if kind == StreamFrameKind.TOOL_CALL:
        tool_digest = digest_json(json.loads(tool_arguments_json))
    return StreamFrameEvidence(
        frame_id,
        seq_no,
        kind,
        payload_text,
        text_sha256(payload_text),
        hashlib.sha256(encoded).hexdigest(),
        len(encoded),
        acked,
        previous,
        tool_name,
        tool_arguments_json,
        tool_digest,
    )


def _frames(
    *,
    first_payload: str = "Ticket ",
    tool_arguments_json: str = '{"ticket_id":"INC-1042"}',
) -> tuple[StreamFrameEvidence, ...]:
    seed = stream_seed_digest(
        STREAM_ID,
        OUTPUT_CHANNEL_ID,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        STREAM_GENERATION,
    )
    first = _frame(FRAME_IDS[0], 1, StreamFrameKind.TOKEN, first_payload, seed, acked=True)
    second = _frame(
        FRAME_IDS[1],
        2,
        StreamFrameKind.TOKEN,
        "status: ",
        stream_frame_digest(first),
        acked=True,
    )
    tool_payload = tool_call_payload("lookup_ticket", tool_arguments_json)
    third = _frame(
        FRAME_IDS[2],
        3,
        StreamFrameKind.TOOL_CALL,
        tool_payload,
        stream_frame_digest(second),
        acked=False,
        tool_name="lookup_ticket",
        tool_arguments_json=tool_arguments_json,
    )
    fourth = _frame(
        FRAME_IDS[3],
        4,
        StreamFrameKind.CANCELLED,
        canonical_json_text({"reason": CANCEL_REASON}),
        stream_frame_digest(third),
        acked=True,
    )
    return (first, second, third, fourth)


def _stream() -> StreamingOutputEvidence:
    frames = _frames()
    auth = cancellation_authorization_digest(
        STREAM_ID,
        TENANT_ID,
        SESSION_ID,
        CANCELLATION_ID,
        2,
        CANCEL_REASON,
    )
    return StreamingOutputEvidence(
        STREAM_ID,
        OUTPUT_CHANNEL_ID,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        STREAM_GENERATION,
        "text/event-stream",
        "utf-8",
        512,
        2048,
        1024,
        2,
        stream_seed_digest(
            STREAM_ID,
            OUTPUT_CHANNEL_ID,
            REQUEST_ID,
            TENANT_ID,
            SESSION_ID,
            STREAM_GENERATION,
        ),
        frames,
        StreamCancellationEvidence(CANCELLATION_ID, 2, 4, CANCEL_REASON, auth),
        StreamBackpressureEvidence(700, 1, 2, False, True),
        StreamFrameKind.CANCELLED,
    )


def _manifest() -> InferenceStreamingSecurityManifest:
    prior = ("stream-prior-acme-0001", "stream-prior-acme-0002")
    return InferenceStreamingSecurityManifest(
        P10G_SCHEMA_VERSION,
        MANIFEST_ID,
        NOW,
        P10F_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        _stream(),
        prior,
        prior_stream_ledger_digest(prior),
        0,
    )


def request_for(m: InferenceStreamingSecurityManifest) -> InferenceStreamingSecurityRequest:
    return InferenceStreamingSecurityRequest(
        m.manifest_id,
        inference_streaming_security_manifest_digest(m),
        m.created_at_epoch + 10,
        m.request_id,
        m.tenant_id,
        m.session_id,
        m.stream.stream_id,
        m.stream.output_channel_id,
        tuple(frame.frame_id for frame in m.stream.frames),
        m.stream.terminal_kind,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
    )


def policy_for(m: InferenceStreamingSecurityManifest) -> InferenceStreamingSecurityPolicy:
    s = m.stream
    return InferenceStreamingSecurityPolicy(
        P10G_POLICY_VERSION,
        m.manifest_id,
        inference_streaming_security_manifest_digest(m),
        P10F_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        s.stream_id,
        s.output_channel_id,
        STREAM_GENERATION,
        "text/event-stream",
        "utf-8",
        tuple(frame.frame_id for frame in s.frames),
        StreamFrameKind.CANCELLED,
        s.cancellation.cancellation_id,
        s.cancellation.authorization_sha256,
        2,
        s.max_frame_bytes,
        s.max_total_output_bytes,
        s.max_buffered_bytes,
        s.max_unacked_frames,
        256,
        ("lookup_ticket", "search_kb"),
        True,
        True,
        m.prior_stream_ledger_sha256,
        300,
        5,
    )


def build_fixture():
    m = _manifest()
    return {
        "manifest": m,
        "policy": policy_for(m),
        "request": request_for(m),
        "p10f": p10f_assessment(),
    }


def rebind(f, m, *, refresh_manifest_pin: bool = True, refresh_security_pins: bool = False):
    p = f["policy"]
    if refresh_manifest_pin:
        p = replace(p, expected_manifest_sha256=inference_streaming_security_manifest_digest(m))
    if refresh_security_pins:
        p = replace(
            p,
            expected_cancellation_authorization_sha256=m.stream.cancellation.authorization_sha256,
            expected_prior_stream_ledger_sha256=m.prior_stream_ledger_sha256,
        )
    return {"manifest": m, "policy": p, "request": request_for(m), "p10f": f["p10f"]}


def _rechain_stream(s: StreamingOutputEvidence, frames: tuple[StreamFrameEvidence, ...]) -> StreamingOutputEvidence:
    previous = s.frame_chain_seed_sha256
    out = []
    for seq, frame in enumerate(frames, 1):
        rebuilt = _frame(
            frame.frame_id,
            seq,
            frame.kind,
            frame.payload_text,
            previous,
            acked=frame.acked,
            tool_name=frame.tool_name,
            tool_arguments_json=frame.tool_arguments_json,
        )
        out.append(rebuilt)
        previous = stream_frame_digest(rebuilt)
    return replace(s, frames=tuple(out))


def safe_escaped_sse_injection_fixture():
    f = build_fixture()
    s = f["manifest"].stream
    frames = list(s.frames)
    frames[0] = replace(frames[0], payload_text="safe\n\nevent: injected\ndata: pwn")
    s = _rechain_stream(s, tuple(frames))
    m = replace(f["manifest"], stream=s)
    return rebind(f, m)


def safe_tool_argument_newline_fixture():
    f = build_fixture()
    s = f["manifest"].stream
    args = canonical_json_text({"ticket_id": "INC-1042", "note": "line1\n\nevent: evil"})
    frames = _frames(tool_arguments_json=args)
    s = replace(s, frames=frames)
    m = replace(f["manifest"], stream=s)
    return rebind(f, m)


def safe_budget_edge_fixture():
    f = build_fixture()
    s = f["manifest"].stream
    b = replace(
        s.backpressure,
        observed_high_water_bytes=s.max_buffered_bytes,
        observed_high_water_unacked_frames=s.max_unacked_frames,
        producer_pause_count=1,
    )
    m = replace(f["manifest"], stream=replace(s, backpressure=b))
    return rebind(f, m)
