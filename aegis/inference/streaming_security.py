from __future__ import annotations

import hashlib
import json
import re

from .accelerator_isolation_types import (
    P10F_ASSESSMENT_MODE,
    P10F_ASSESSMENT_SCHEMA_VERSION,
    AcceleratorDecision,
    VerifiedInferenceAcceleratorIsolationAssessment,
)
from .streaming_security_types import *

_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9._:/@+-]{1,127}$")


class InferenceStreamingSecurityAnalyzer:
    def __init__(self, policy: InferenceStreamingSecurityPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA.fullmatch(str(value)))

    @staticmethod
    def _id(value: str) -> bool:
        return bool(_ID.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P10G_POLICY_VERSION:
            reject(StreamRejectReason.POLICY_INVALID, "unexpected policy version")
        ids = (
            p.expected_manifest_id,
            p.expected_request_id,
            p.expected_tenant_id,
            p.expected_session_id,
            p.expected_target_model_id,
            p.expected_target_model_revision,
            p.expected_stream_id,
            p.expected_output_channel_id,
            p.expected_cancellation_id,
        )
        if not all(map(self._id, ids)):
            reject(StreamRejectReason.POLICY_INVALID, "policy identity pins invalid")
        if not p.expected_session_id.startswith(f"tenant/{p.expected_tenant_id}/session/"):
            reject(StreamRejectReason.POLICY_INVALID, "policy session/tenant binding invalid")
        if not all(
            map(
                self._sha,
                (
                    p.expected_manifest_sha256,
                    p.expected_p10f_assessment_sha256,
                    p.expected_cancellation_authorization_sha256,
                    p.expected_prior_stream_ledger_sha256,
                ),
            )
        ):
            reject(StreamRejectReason.POLICY_INVALID, "policy digest pins invalid")
        if not p.expected_partition_ids or len(set(p.expected_partition_ids)) != len(p.expected_partition_ids):
            reject(StreamRejectReason.POLICY_INVALID, "partition coverage invalid")
        if not p.expected_frame_ids or len(set(p.expected_frame_ids)) != len(p.expected_frame_ids):
            reject(StreamRejectReason.POLICY_INVALID, "frame coverage invalid")
        if not all(map(self._id, p.expected_frame_ids)):
            reject(StreamRejectReason.POLICY_INVALID, "frame ids malformed")
        if p.expected_content_type != "text/event-stream":
            reject(StreamRejectReason.POLICY_INVALID, "only SSE is allowed in P10-G")
        if p.expected_encoding.casefold() != "utf-8":
            reject(StreamRejectReason.POLICY_INVALID, "only UTF-8 is allowed in P10-G")
        bounds = (
            p.max_cancel_lag_frames,
            p.max_frame_bytes,
            p.max_total_output_bytes,
            p.max_buffered_bytes,
            p.max_unacked_frames,
            p.max_tool_arguments_bytes,
            p.max_manifest_age_seconds,
            p.max_future_skew_seconds,
        )
        if min(bounds) < 0 or min(
            p.max_frame_bytes,
            p.max_total_output_bytes,
            p.max_buffered_bytes,
            p.max_unacked_frames,
            p.max_tool_arguments_bytes,
        ) <= 0:
            reject(StreamRejectReason.POLICY_INVALID, "policy bounds invalid")
        if p.max_frame_bytes > p.max_total_output_bytes:
            reject(StreamRejectReason.POLICY_INVALID, "frame budget exceeds total output budget")
        if p.max_buffered_bytes > p.max_total_output_bytes:
            reject(StreamRejectReason.POLICY_INVALID, "buffer budget exceeds total output budget")
        if not p.allowed_tool_names or len(set(p.allowed_tool_names)) != len(p.allowed_tool_names):
            reject(StreamRejectReason.POLICY_INVALID, "tool allowlist invalid")
        if not all(map(self._id, p.allowed_tool_names)):
            reject(StreamRejectReason.POLICY_INVALID, "tool allowlist malformed")
        if p.expected_terminal_kind not in (StreamFrameKind.CANCELLED, StreamFrameKind.FINAL):
            reject(StreamRejectReason.POLICY_INVALID, "terminal frame kind invalid")

    def _validate_manifest(self, m: InferenceStreamingSecurityManifest) -> None:
        if (
            m.schema_version != P10G_SCHEMA_VERSION
            or m.manifest_id != self.policy.expected_manifest_id
            or not self._id(m.manifest_id)
            or m.created_at_epoch <= 0
            or not self._sha(m.p10f_assessment_sha256)
        ):
            reject(StreamRejectReason.MANIFEST_INVALID, "manifest identity/schema/time invalid")
        ids = (
            m.request_id,
            m.tenant_id,
            m.session_id,
            m.target_model_id,
            m.target_model_revision,
        )
        if not all(map(self._id, ids)) or not m.session_id.startswith(f"tenant/{m.tenant_id}/session/"):
            reject(StreamRejectReason.MANIFEST_INVALID, "manifest route identifiers invalid")
        if not m.partition_ids or len(set(m.partition_ids)) != len(m.partition_ids) or not all(map(self._id, m.partition_ids)):
            reject(StreamRejectReason.MANIFEST_INVALID, "partition evidence invalid")
        if m.adapter_generation < 0 or m.network_operations < 0:
            reject(StreamRejectReason.MANIFEST_INVALID, "manifest generation/network invalid")
        s = m.stream
        stream_ids = (s.stream_id, s.output_channel_id, s.request_id, s.tenant_id, s.session_id)
        if not all(map(self._id, stream_ids)) or not s.session_id.startswith(f"tenant/{s.tenant_id}/session/"):
            reject(StreamRejectReason.MANIFEST_INVALID, "stream identifiers invalid")
        if s.stream_generation < 0 or min(
            s.max_frame_bytes,
            s.max_total_output_bytes,
            s.max_buffered_bytes,
            s.max_unacked_frames,
        ) <= 0 or not self._sha(s.frame_chain_seed_sha256):
            reject(StreamRejectReason.MANIFEST_INVALID, "stream bounds/seed invalid")
        if not s.frames or len({f.frame_id for f in s.frames}) != len(s.frames):
            reject(StreamRejectReason.MANIFEST_INVALID, "frame evidence empty or duplicated")
        for frame in s.frames:
            if not self._id(frame.frame_id) or frame.seq_no <= 0:
                reject(StreamRejectReason.MANIFEST_INVALID, "frame identity/sequence invalid")
            if not all(
                map(
                    self._sha,
                    (
                        frame.payload_sha256,
                        frame.sse_sha256,
                        frame.previous_frame_sha256,
                    ),
                )
            ) or frame.encoded_bytes <= 0:
                reject(StreamRejectReason.MANIFEST_INVALID, "frame digest/size invalid")
            if frame.kind == StreamFrameKind.TOOL_CALL:
                if not self._id(frame.tool_name) or not frame.tool_arguments_json or not self._sha(frame.tool_arguments_sha256):
                    reject(StreamRejectReason.MANIFEST_INVALID, "tool frame evidence malformed")
                try:
                    parsed = json.loads(frame.tool_arguments_json)
                except json.JSONDecodeError as exc:
                    reject(StreamRejectReason.MANIFEST_INVALID, f"tool arguments are not JSON: {exc}")
                if not isinstance(parsed, dict):
                    reject(StreamRejectReason.MANIFEST_INVALID, "tool arguments must be a JSON object")
            elif frame.tool_name or frame.tool_arguments_json or frame.tool_arguments_sha256:
                reject(StreamRejectReason.MANIFEST_INVALID, "non-tool frame carries tool evidence")
        c = s.cancellation
        if (
            not self._id(c.cancellation_id)
            or c.requested_after_seq < 0
            or c.effective_before_seq <= 0
            or not self._id(c.reason_code)
            or not self._sha(c.authorization_sha256)
        ):
            reject(StreamRejectReason.MANIFEST_INVALID, "cancellation evidence invalid")
        b = s.backpressure
        if min(
            b.observed_high_water_bytes,
            b.observed_high_water_unacked_frames,
            b.producer_pause_count,
        ) < 0:
            reject(StreamRejectReason.MANIFEST_INVALID, "backpressure evidence invalid")
        if len(m.prior_stream_ids) != len(set(m.prior_stream_ids)) or any(
            not self._id(v) for v in m.prior_stream_ids
        ) or not self._sha(m.prior_stream_ledger_sha256):
            reject(StreamRejectReason.MANIFEST_INVALID, "prior stream ledger malformed")

    @staticmethod
    def _upstream_ok(a: VerifiedInferenceAcceleratorIsolationAssessment) -> bool:
        flags = (
            a.upstream_p10e_bound,
            a.host_probe_bound,
            a.device_assignment_verified,
            a.dma_isolation_verified,
            a.memory_isolation_verified,
            a.side_channel_profile_verified,
            a.lease_safety_verified,
        )
        nonclaims = (
            a.caller_declared_safety_trusted,
            a.live_gpu_hardware_validated,
            a.production_gpu_runtime_integrated,
            a.production_cgroup_enforcement_verified,
            a.production_iommu_enforcement_verified,
            a.physical_vram_zeroization_verified,
            a.dma_attack_resistance_validated,
            a.side_channel_resistance_validated,
            a.hardware_attestation_verified,
        )
        return (
            a.decision == AcceleratorDecision.ALLOW
            and not a.risks
            and all(flags)
            and not any(nonclaims)
            and a.assessment_schema_version == P10F_ASSESSMENT_SCHEMA_VERSION
            and a.assessment_mode == P10F_ASSESSMENT_MODE
        )

    def derive(
        self,
        m: InferenceStreamingSecurityManifest,
        a: VerifiedInferenceAcceleratorIsolationAssessment,
    ) -> tuple[StreamRisk, ...]:
        self._validate_manifest(m)
        p = self.policy
        s = m.stream
        risks: set[StreamRisk] = set()

        if not self._upstream_ok(a):
            risks.add(StreamRisk.UPSTREAM_P10F_INVALID)
        if (
            m.p10f_assessment_sha256.casefold() != p.expected_p10f_assessment_sha256.casefold()
            or a.assessment_evidence_sha256.casefold() != p.expected_p10f_assessment_sha256.casefold()
        ):
            risks.add(StreamRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            (m.request_id, m.tenant_id, m.session_id)
            != (p.expected_request_id, p.expected_tenant_id, p.expected_session_id)
            or (a.request_id, a.tenant_id, a.session_id)
            != (m.request_id, m.tenant_id, m.session_id)
            or (m.target_model_id, m.target_model_revision)
            != (p.expected_target_model_id, p.expected_target_model_revision)
            or (a.target_model_id, a.target_model_revision)
            != (m.target_model_id, m.target_model_revision)
            or m.adapter_ids != p.expected_adapter_ids
            or a.adapter_ids != m.adapter_ids
            or m.adapter_generation != p.expected_adapter_generation
            or a.adapter_generation != m.adapter_generation
            or m.partition_ids != p.expected_partition_ids
            or a.partition_ids != m.partition_ids
        ):
            risks.add(StreamRisk.REQUEST_ROUTE_MISMATCH)
        if (
            (s.request_id, s.tenant_id, s.session_id) != (m.request_id, m.tenant_id, m.session_id)
            or s.stream_id != p.expected_stream_id
            or s.stream_generation != p.expected_stream_generation
        ):
            risks.add(StreamRisk.STREAM_IDENTITY_MISMATCH)
        if s.output_channel_id != p.expected_output_channel_id:
            risks.add(StreamRisk.OUTPUT_CHANNEL_MISMATCH)
        if s.content_type != p.expected_content_type:
            risks.add(StreamRisk.CONTENT_TYPE_UNSAFE)
        if s.encoding.casefold() != p.expected_encoding.casefold():
            risks.add(StreamRisk.ENCODING_UNSAFE)
        if (
            s.max_frame_bytes != p.max_frame_bytes
            or s.max_total_output_bytes != p.max_total_output_bytes
            or s.max_buffered_bytes != p.max_buffered_bytes
            or s.max_unacked_frames != p.max_unacked_frames
        ):
            risks.add(StreamRisk.BACKPRESSURE_BUDGET_EXCEEDED)
        expected_seed = stream_seed_digest(
            s.stream_id,
            s.output_channel_id,
            s.request_id,
            s.tenant_id,
            s.session_id,
            s.stream_generation,
        )
        if s.frame_chain_seed_sha256.casefold() != expected_seed.casefold():
            risks.add(StreamRisk.FRAME_CHAIN_MISMATCH)
        if tuple(frame.frame_id for frame in s.frames) != p.expected_frame_ids:
            risks.add(StreamRisk.FRAME_COVERAGE_MISMATCH)

        previous = s.frame_chain_seed_sha256
        total_bytes = 0
        seen_terminal = False
        terminal_count = 0
        unacked = 0
        for expected_seq, frame in enumerate(s.frames, 1):
            if frame.seq_no != expected_seq:
                risks.add(StreamRisk.FRAME_SEQUENCE_MISMATCH)
            if frame.previous_frame_sha256.casefold() != previous.casefold():
                risks.add(StreamRisk.FRAME_CHAIN_MISMATCH)
            if frame.payload_sha256.casefold() != text_sha256(frame.payload_text).casefold():
                risks.add(StreamRisk.FRAME_DIGEST_MISMATCH)
            encoded = encode_sse_event(frame.kind, frame.payload_text)
            if frame.sse_sha256.casefold() != hashlib.sha256(encoded).hexdigest().casefold():
                risks.add(StreamRisk.FRAME_DIGEST_MISMATCH)
            if frame.encoded_bytes != len(encoded):
                risks.add(StreamRisk.FRAME_DIGEST_MISMATCH)
            if frame.encoded_bytes > s.max_frame_bytes or frame.encoded_bytes > p.max_frame_bytes:
                risks.add(StreamRisk.FRAME_SIZE_EXCEEDED)
            total_bytes += frame.encoded_bytes
            if not frame.acked:
                unacked += 1
            else:
                unacked = 0
            if unacked > s.max_unacked_frames or unacked > p.max_unacked_frames:
                risks.add(StreamRisk.UNACKED_WINDOW_EXCEEDED)
            if seen_terminal:
                risks.add(StreamRisk.OUTPUT_AFTER_CANCEL)
            if frame.kind in (StreamFrameKind.CANCELLED, StreamFrameKind.FINAL):
                seen_terminal = True
                terminal_count += 1
            if frame.kind == StreamFrameKind.TOOL_CALL:
                if frame.tool_name not in p.allowed_tool_names:
                    risks.add(StreamRisk.TOOL_CALL_UNAUTHORIZED)
                try:
                    parsed = json.loads(frame.tool_arguments_json)
                    args_digest = digest_json(parsed)
                    canonical_payload = tool_call_payload(frame.tool_name, frame.tool_arguments_json)
                except (json.JSONDecodeError, TypeError, ValueError):
                    parsed = None
                    args_digest = ""
                    canonical_payload = ""
                if (
                    not isinstance(parsed, dict)
                    or frame.tool_arguments_sha256.casefold() != args_digest.casefold()
                ):
                    risks.add(StreamRisk.TOOL_ARGUMENT_DIGEST_MISMATCH)
                if len(frame.tool_arguments_json.encode("utf-8")) > p.max_tool_arguments_bytes:
                    risks.add(StreamRisk.TOOL_CALL_FRAMING_UNSAFE)
                if frame.payload_text != canonical_payload:
                    risks.add(StreamRisk.TOOL_CALL_FRAMING_UNSAFE)
                if b"\n\nevent:" in encoded[:-2] or b"\r" in encoded:
                    risks.add(StreamRisk.TOOL_CALL_FRAMING_UNSAFE)
            previous = stream_frame_digest(frame)

        if total_bytes > s.max_total_output_bytes or total_bytes > p.max_total_output_bytes:
            risks.add(StreamRisk.TOTAL_OUTPUT_EXCEEDED)
        if terminal_count != 1 or not s.frames or s.frames[-1].kind != s.terminal_kind or s.terminal_kind != p.expected_terminal_kind:
            risks.add(StreamRisk.TERMINAL_FRAME_MISMATCH)

        c = s.cancellation
        expected_auth = cancellation_authorization_digest(
            s.stream_id,
            s.tenant_id,
            s.session_id,
            c.cancellation_id,
            c.requested_after_seq,
            c.reason_code,
        )
        if (
            c.cancellation_id != p.expected_cancellation_id
            or c.authorization_sha256.casefold() != expected_auth.casefold()
            or c.authorization_sha256.casefold() != p.expected_cancellation_authorization_sha256.casefold()
            or c.effective_before_seq <= c.requested_after_seq
            or c.effective_before_seq - c.requested_after_seq > p.max_cancel_lag_frames
        ):
            risks.add(StreamRisk.CANCELLATION_BINDING_MISMATCH)
        if s.terminal_kind == StreamFrameKind.CANCELLED:
            if c.effective_before_seq > len(s.frames) or s.frames[c.effective_before_seq - 1].kind != StreamFrameKind.CANCELLED:
                risks.add(StreamRisk.CANCELLATION_BINDING_MISMATCH)
            if any(
                frame.seq_no > c.effective_before_seq
                or (frame.seq_no == c.effective_before_seq and frame.kind != StreamFrameKind.CANCELLED)
                for frame in s.frames
            ):
                risks.add(StreamRisk.OUTPUT_AFTER_CANCEL)

        b = s.backpressure
        if (
            b.observed_high_water_bytes > s.max_buffered_bytes
            or b.observed_high_water_bytes > p.max_buffered_bytes
        ):
            risks.add(StreamRisk.BACKPRESSURE_BUDGET_EXCEEDED)
        if (
            b.observed_high_water_unacked_frames > s.max_unacked_frames
            or b.observed_high_water_unacked_frames > p.max_unacked_frames
        ):
            risks.add(StreamRisk.UNACKED_WINDOW_EXCEEDED)
        if p.require_backpressure_observed and b.producer_pause_count <= 0:
            risks.add(StreamRisk.BACKPRESSURE_BUDGET_EXCEEDED)
        if p.require_queue_drained and not b.queue_drained:
            risks.add(StreamRisk.BACKPRESSURE_BUDGET_EXCEEDED)

        if s.stream_id in m.prior_stream_ids:
            risks.add(StreamRisk.STREAM_REPLAY)
        ledger = prior_stream_ledger_digest(m.prior_stream_ids)
        if (
            ledger.casefold() != m.prior_stream_ledger_sha256.casefold()
            or ledger.casefold() != p.expected_prior_stream_ledger_sha256.casefold()
        ):
            risks.add(StreamRisk.PRIOR_STREAM_LEDGER_MISMATCH)
        if m.network_operations:
            risks.add(StreamRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(risks, key=lambda item: item.value))

    def evaluate(
        self,
        request: InferenceStreamingSecurityRequest,
        m: InferenceStreamingSecurityManifest,
        a: VerifiedInferenceAcceleratorIsolationAssessment,
    ) -> VerifiedInferenceStreamingSecurityAssessment:
        self._validate_manifest(m)
        actual = inference_streaming_security_manifest_digest(m)
        if actual.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(StreamRejectReason.MANIFEST_DIGEST_MISMATCH, "streaming manifest differs from policy-pinned evidence")
        if request.manifest_id != m.manifest_id or request.manifest_sha256.casefold() != actual.casefold():
            reject(StreamRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if (
            request.evaluated_at_epoch < m.created_at_epoch - self.policy.max_future_skew_seconds
            or request.evaluated_at_epoch > m.created_at_epoch + self.policy.max_manifest_age_seconds
        ):
            reject(StreamRejectReason.REQUEST_INVALID, "streaming manifest freshness invalid")
        identity = (
            request.declared_request_id,
            request.declared_tenant_id,
            request.declared_session_id,
            request.declared_stream_id,
            request.declared_output_channel_id,
            request.declared_frame_ids,
            request.declared_terminal_kind,
        )
        evidence = (
            m.request_id,
            m.tenant_id,
            m.session_id,
            m.stream.stream_id,
            m.stream.output_channel_id,
            tuple(frame.frame_id for frame in m.stream.frames),
            m.stream.terminal_kind,
        )
        if identity != evidence:
            reject(StreamRejectReason.DECLARED_SUMMARY_MISMATCH, "caller streaming identity summary disagrees with evidence")
        risks = self.derive(m, a)
        decision = StreamDecision.ALLOW if not risks else StreamDecision.DENY
        safe = not risks
        declared = (
            request.declared_upstream_p10f_bound,
            request.declared_output_channel_safe,
            request.declared_frame_integrity_safe,
            request.declared_backpressure_safe,
            request.declared_cancellation_safe,
            request.declared_tool_framing_safe,
            request.declared_replay_safe,
            request.declared_streaming_safe,
        )
        if declared != (safe,) * 8:
            reject(StreamRejectReason.DECLARED_SUMMARY_MISMATCH, "caller streaming safety summary disagrees with derived evidence")

        output_bad = {
            StreamRisk.REQUEST_ROUTE_MISMATCH,
            StreamRisk.OUTPUT_CHANNEL_MISMATCH,
            StreamRisk.STREAM_IDENTITY_MISMATCH,
            StreamRisk.CONTENT_TYPE_UNSAFE,
            StreamRisk.ENCODING_UNSAFE,
        }
        frame_bad = {
            StreamRisk.FRAME_COVERAGE_MISMATCH,
            StreamRisk.FRAME_SEQUENCE_MISMATCH,
            StreamRisk.FRAME_CHAIN_MISMATCH,
            StreamRisk.FRAME_DIGEST_MISMATCH,
            StreamRisk.FRAME_SIZE_EXCEEDED,
            StreamRisk.TOTAL_OUTPUT_EXCEEDED,
            StreamRisk.TERMINAL_FRAME_MISMATCH,
            StreamRisk.OUTPUT_AFTER_CANCEL,
        }
        backpressure_bad = {
            StreamRisk.BACKPRESSURE_BUDGET_EXCEEDED,
            StreamRisk.UNACKED_WINDOW_EXCEEDED,
        }
        cancellation_bad = {
            StreamRisk.CANCELLATION_BINDING_MISMATCH,
            StreamRisk.OUTPUT_AFTER_CANCEL,
            StreamRisk.TERMINAL_FRAME_MISMATCH,
        }
        tool_bad = {
            StreamRisk.TOOL_CALL_FRAMING_UNSAFE,
            StreamRisk.TOOL_CALL_UNAUTHORIZED,
            StreamRisk.TOOL_ARGUMENT_DIGEST_MISMATCH,
        }
        replay_bad = {StreamRisk.STREAM_REPLAY, StreamRisk.PRIOR_STREAM_LEDGER_MISMATCH}
        assessment_sha = digest_json(
            {
                "manifest_id": m.manifest_id,
                "request_id": m.request_id,
                "tenant_id": m.tenant_id,
                "stream_id": m.stream.stream_id,
                "terminal_kind": m.stream.terminal_kind,
                "frame_ids": tuple(frame.frame_id for frame in m.stream.frames),
                "risks": risks,
                "decision": decision,
                "schema": P10G_ASSESSMENT_SCHEMA_VERSION,
                "mode": P10G_ASSESSMENT_MODE,
            }
        )
        return VerifiedInferenceStreamingSecurityAssessment(
            m.manifest_id,
            actual,
            m.request_id,
            m.tenant_id,
            m.session_id,
            decision,
            risks,
            m.p10f_assessment_sha256,
            m.target_model_id,
            m.target_model_revision,
            m.adapter_ids,
            m.adapter_generation,
            m.partition_ids,
            m.stream.stream_id,
            m.stream.output_channel_id,
            tuple(frame.frame_id for frame in m.stream.frames),
            m.stream.terminal_kind,
            StreamRisk.UPSTREAM_P10F_INVALID not in risks and StreamRisk.UPSTREAM_BINDING_MISMATCH not in risks,
            not bool(set(risks) & output_bad),
            not bool(set(risks) & frame_bad),
            not bool(set(risks) & backpressure_bad),
            not bool(set(risks) & cancellation_bad),
            not bool(set(risks) & tool_bad),
            not bool(set(risks) & replay_bad),
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            P10G_ASSESSMENT_SCHEMA_VERSION,
            P10G_ASSESSMENT_MODE,
            assessment_sha,
        )
