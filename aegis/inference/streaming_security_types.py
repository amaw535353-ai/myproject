from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P10G_POLICY_VERSION = "inference-streaming-output-integrity-v1"
P10G_SCHEMA_VERSION = "aegis-inference-streaming-output-manifest-v1"
P10G_ASSESSMENT_SCHEMA_VERSION = "aegis-inference-streaming-output-assessment-v1"
P10G_ASSESSMENT_MODE = "deterministic-evidence-bound-streaming-output-integrity-v1"


class StreamDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class StreamFrameKind(str, Enum):
    TOKEN = "token"
    TOOL_CALL = "tool_call"
    CANCELLED = "cancelled"
    FINAL = "final"


class StreamRisk(str, Enum):
    UPSTREAM_P10F_INVALID = "upstream_p10f_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    REQUEST_ROUTE_MISMATCH = "request_route_mismatch"
    OUTPUT_CHANNEL_MISMATCH = "output_channel_mismatch"
    STREAM_IDENTITY_MISMATCH = "stream_identity_mismatch"
    FRAME_COVERAGE_MISMATCH = "frame_coverage_mismatch"
    FRAME_SEQUENCE_MISMATCH = "frame_sequence_mismatch"
    FRAME_CHAIN_MISMATCH = "frame_chain_mismatch"
    FRAME_DIGEST_MISMATCH = "frame_digest_mismatch"
    FRAME_SIZE_EXCEEDED = "frame_size_exceeded"
    TOTAL_OUTPUT_EXCEEDED = "total_output_exceeded"
    BACKPRESSURE_BUDGET_EXCEEDED = "backpressure_budget_exceeded"
    UNACKED_WINDOW_EXCEEDED = "unacked_window_exceeded"
    CANCELLATION_BINDING_MISMATCH = "cancellation_binding_mismatch"
    OUTPUT_AFTER_CANCEL = "output_after_cancel"
    TERMINAL_FRAME_MISMATCH = "terminal_frame_mismatch"
    TOOL_CALL_FRAMING_UNSAFE = "tool_call_framing_unsafe"
    TOOL_CALL_UNAUTHORIZED = "tool_call_unauthorized"
    TOOL_ARGUMENT_DIGEST_MISMATCH = "tool_argument_digest_mismatch"
    CONTENT_TYPE_UNSAFE = "content_type_unsafe"
    ENCODING_UNSAFE = "encoding_unsafe"
    STREAM_REPLAY = "stream_replay"
    PRIOR_STREAM_LEDGER_MISMATCH = "prior_stream_ledger_mismatch"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class StreamRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class InferenceStreamingSecurityRejected(ValueError):
    def __init__(self, reason: StreamRejectReason, message: str):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason.value}: {message}")


def reject(reason: StreamRejectReason, message: str) -> None:
    raise InferenceStreamingSecurityRejected(reason, message)


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(key.value if isinstance(key, Enum) else key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def digest_json(value) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_json_text(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def encode_sse_event(kind: StreamFrameKind, payload_text: str) -> bytes:
    body = canonical_json_text({"kind": kind.value, "payload": payload_text})
    return f"event: {kind.value}\ndata: {body}\n\n".encode("utf-8")


def tool_call_payload(tool_name: str, arguments_json: str) -> str:
    parsed = json.loads(arguments_json)
    return canonical_json_text({"tool": tool_name, "arguments": parsed})


@dataclass(frozen=True)
class StreamFrameEvidence:
    frame_id: str
    seq_no: int
    kind: StreamFrameKind
    payload_text: str
    payload_sha256: str
    sse_sha256: str
    encoded_bytes: int
    acked: bool
    previous_frame_sha256: str
    tool_name: str
    tool_arguments_json: str
    tool_arguments_sha256: str


@dataclass(frozen=True)
class StreamCancellationEvidence:
    cancellation_id: str
    requested_after_seq: int
    effective_before_seq: int
    reason_code: str
    authorization_sha256: str


@dataclass(frozen=True)
class StreamBackpressureEvidence:
    observed_high_water_bytes: int
    observed_high_water_unacked_frames: int
    producer_pause_count: int
    client_disconnect_observed: bool
    queue_drained: bool


@dataclass(frozen=True)
class StreamingOutputEvidence:
    stream_id: str
    output_channel_id: str
    request_id: str
    tenant_id: str
    session_id: str
    stream_generation: int
    content_type: str
    encoding: str
    max_frame_bytes: int
    max_total_output_bytes: int
    max_buffered_bytes: int
    max_unacked_frames: int
    frame_chain_seed_sha256: str
    frames: tuple[StreamFrameEvidence, ...]
    cancellation: StreamCancellationEvidence
    backpressure: StreamBackpressureEvidence
    terminal_kind: StreamFrameKind


@dataclass(frozen=True)
class InferenceStreamingSecurityManifest:
    schema_version: str
    manifest_id: str
    created_at_epoch: int
    p10f_assessment_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    stream: StreamingOutputEvidence
    prior_stream_ids: tuple[str, ...]
    prior_stream_ledger_sha256: str
    network_operations: int = 0


@dataclass(frozen=True)
class InferenceStreamingSecurityPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_p10f_assessment_sha256: str
    expected_request_id: str
    expected_tenant_id: str
    expected_session_id: str
    expected_target_model_id: str
    expected_target_model_revision: str
    expected_adapter_ids: tuple[str, ...]
    expected_adapter_generation: int
    expected_partition_ids: tuple[str, ...]
    expected_stream_id: str
    expected_output_channel_id: str
    expected_stream_generation: int
    expected_content_type: str
    expected_encoding: str
    expected_frame_ids: tuple[str, ...]
    expected_terminal_kind: StreamFrameKind
    expected_cancellation_id: str
    expected_cancellation_authorization_sha256: str
    max_cancel_lag_frames: int
    max_frame_bytes: int
    max_total_output_bytes: int
    max_buffered_bytes: int
    max_unacked_frames: int
    max_tool_arguments_bytes: int
    allowed_tool_names: tuple[str, ...]
    require_backpressure_observed: bool
    require_queue_drained: bool
    expected_prior_stream_ledger_sha256: str
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class InferenceStreamingSecurityRequest:
    manifest_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_request_id: str
    declared_tenant_id: str
    declared_session_id: str
    declared_stream_id: str
    declared_output_channel_id: str
    declared_frame_ids: tuple[str, ...]
    declared_terminal_kind: StreamFrameKind
    declared_upstream_p10f_bound: bool
    declared_output_channel_safe: bool
    declared_frame_integrity_safe: bool
    declared_backpressure_safe: bool
    declared_cancellation_safe: bool
    declared_tool_framing_safe: bool
    declared_replay_safe: bool
    declared_streaming_safe: bool


@dataclass(frozen=True)
class VerifiedInferenceStreamingSecurityAssessment:
    manifest_id: str
    manifest_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    decision: StreamDecision
    risks: tuple[StreamRisk, ...]
    p10f_assessment_sha256: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    stream_id: str
    output_channel_id: str
    frame_ids: tuple[str, ...]
    terminal_kind: StreamFrameKind
    upstream_p10f_bound: bool
    output_channel_verified: bool
    frame_integrity_verified: bool
    backpressure_verified: bool
    cancellation_verified: bool
    tool_framing_verified: bool
    replay_verified: bool
    caller_declared_safety_trusted: bool
    production_streaming_gateway_integrated: bool
    kernel_tcp_backpressure_validated: bool
    distributed_cancellation_linearizability_validated: bool
    production_tool_dispatch_integrated: bool
    semantic_output_safety_validated: bool
    remote_client_disconnect_semantics_validated: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def stream_frame_digest(frame: StreamFrameEvidence) -> str:
    return digest_json(frame)


def stream_seed_digest(
    stream_id: str,
    output_channel_id: str,
    request_id: str,
    tenant_id: str,
    session_id: str,
    generation: int,
) -> str:
    return digest_json(
        {
            "stream_id": stream_id,
            "output_channel_id": output_channel_id,
            "request_id": request_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "generation": generation,
        }
    )


def cancellation_authorization_digest(
    stream_id: str,
    tenant_id: str,
    session_id: str,
    cancellation_id: str,
    requested_after_seq: int,
    reason_code: str,
) -> str:
    return digest_json(
        {
            "stream_id": stream_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "cancellation_id": cancellation_id,
            "requested_after_seq": requested_after_seq,
            "reason_code": reason_code,
        }
    )


def prior_stream_ledger_digest(ids: tuple[str, ...]) -> str:
    return digest_json({"prior_stream_ids": tuple(sorted(ids))})


def inference_streaming_security_manifest_digest(
    manifest: InferenceStreamingSecurityManifest,
) -> str:
    return digest_json(manifest)
