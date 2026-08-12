from __future__ import annotations

import hmac
import json
from hashlib import sha256
from threading import Lock
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aegis.approvals.models import ApprovalDecision, ApprovalStatus
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import ToolCallProposal, ToolName


P2H_POLICY_VERSION = "allowlist-pseudonymized-security-events-v1"
P2H_EVENT_SCHEMA_VERSION = "aegis.security-event.v1"
P2H_SYNTHETIC_KEY_ID = "p2h-local-v1"
_FINGERPRINT_PREFIX = "hmac-sha256:"
_MIN_HMAC_KEY_BYTES = 32


class TelemetryEventName(str):
    TOOL_EXECUTION = "agent.tool_execution"
    APPROVAL_DECISION = "approval.decision"


class TelemetryOutcome(str):
    EXECUTED = "executed"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class SecurityTelemetryEvent(BaseModel):
    """Allowlisted security event safe for export to a telemetry backend.

    Raw prompts, argument values, tool-result bodies, credentials, approval IDs,
    ticket IDs, user IDs, and tenant IDs are intentionally absent from this schema.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.security-event.v1"] = P2H_EVENT_SCHEMA_VERSION
    event_name: Literal["agent.tool_execution", "approval.decision"]
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    fingerprint_key_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")
    subject_ref: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    tenant_ref: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    actor_ref: str | None = Field(
        default=None, pattern=r"^hmac-sha256:[0-9a-f]{64}$"
    )
    tool_name: ToolName
    outcome: Literal["executed", "pending", "approved", "rejected", "expired"]
    decision: ApprovalDecision | None = None
    prompt_bytes: int = Field(ge=0)
    argument_names: tuple[str, ...]
    argument_ref: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    result_keys: tuple[str, ...]
    result_bytes: int = Field(ge=0)
    retrieved_document_ids: tuple[int, ...] = ()
    approval_ref: str | None = Field(
        default=None, pattern=r"^hmac-sha256:[0-9a-f]{64}$"
    )
    ticket_ref: str | None = Field(
        default=None, pattern=r"^hmac-sha256:[0-9a-f]{64}$"
    )
    duration_ms: int = Field(ge=0)


def _byte_size(value: Any) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    rendered = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return len(rendered.encode("utf-8"))


class TelemetryPseudonymizer:
    """Keyed pseudonymization for correlatable telemetry references."""

    def __init__(self, *, key: bytes, key_id: str) -> None:
        if len(key) < _MIN_HMAC_KEY_BYTES:
            raise ValueError("telemetry HMAC key must be at least 32 bytes")
        if not key_id or len(key_id) > 64:
            raise ValueError("telemetry fingerprint key id is invalid")
        self._key = bytes(key)
        self.key_id = key_id

    def fingerprint_text(self, value: str) -> str:
        digest = hmac.new(self._key, value.encode("utf-8"), sha256).hexdigest()
        return f"{_FINGERPRINT_PREFIX}{digest}"

    def fingerprint_json(self, value: Any) -> str:
        canonical = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        return self.fingerprint_text(canonical)


class SecurityEventSink(Protocol):
    def emit(self, event: SecurityTelemetryEvent) -> None: ...


class ToolTelemetryRecorder(Protocol):
    def record_tool_execution(
        self,
        *,
        trace_id: str,
        principal: Principal,
        message: str,
        proposal: ToolCallProposal,
        result: dict[str, Any],
        duration_ms: int,
    ) -> None: ...

    def record_approval_decision(
        self,
        *,
        trace_id: str,
        requester: Principal,
        approver: Principal,
        approval_id: str,
        proposal: ToolCallProposal,
        decision: ApprovalDecision,
        final_status: ApprovalStatus,
    ) -> None: ...


class InMemorySecurityEventSink:
    """Small deterministic sink used by the local app, CI, and security evals."""

    def __init__(self) -> None:
        self._events: list[SecurityTelemetryEvent] = []
        self._lock = Lock()

    def emit(self, event: SecurityTelemetryEvent) -> None:
        if not isinstance(event, SecurityTelemetryEvent):
            raise TypeError("security telemetry sink accepts only typed redacted events")
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[SecurityTelemetryEvent, ...]:
        with self._lock:
            return tuple(self._events)


_STATUS_TO_OUTCOME: dict[str, str] = {
    "pending": TelemetryOutcome.PENDING,
    "approved": TelemetryOutcome.APPROVED,
    "consumed": TelemetryOutcome.APPROVED,
    "rejected": TelemetryOutcome.REJECTED,
    "expired": TelemetryOutcome.EXPIRED,
}


def _safe_outcome_from_result(result: dict[str, Any]) -> str:
    status = str(result.get("status", "")).casefold()
    return _STATUS_TO_OUTCOME.get(status, TelemetryOutcome.EXECUTED)


def _approval_outcome(status: ApprovalStatus) -> str:
    if status is ApprovalStatus.REJECTED:
        return TelemetryOutcome.REJECTED
    if status is ApprovalStatus.EXPIRED:
        return TelemetryOutcome.EXPIRED
    if status in {ApprovalStatus.APPROVED, ApprovalStatus.CONSUMED}:
        return TelemetryOutcome.APPROVED
    return TelemetryOutcome.PENDING


def _extract_document_ids(result: dict[str, Any]) -> tuple[int, ...]:
    raw_results = result.get("results")
    if not isinstance(raw_results, list):
        return ()

    document_ids: list[int] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        document_id = item.get("document_id")
        if isinstance(document_id, int):
            document_ids.append(document_id)
    return tuple(document_ids)


class SecurityTelemetryRecorder:
    """Build typed, data-minimized events before anything reaches the sink."""

    def __init__(
        self,
        *,
        sink: SecurityEventSink,
        pseudonymizer: TelemetryPseudonymizer,
    ) -> None:
        self._sink = sink
        self._pseudonymizer = pseudonymizer

    @property
    def policy_version(self) -> str:
        return P2H_POLICY_VERSION

    def record_tool_execution(
        self,
        *,
        trace_id: str,
        principal: Principal,
        message: str,
        proposal: ToolCallProposal,
        result: dict[str, Any],
        duration_ms: int,
    ) -> None:
        approval_id = result.get("approval_id")
        ticket_id = result.get("ticket_id")

        event = SecurityTelemetryEvent(
            event_name=TelemetryEventName.TOOL_EXECUTION,
            trace_id=trace_id,
            fingerprint_key_id=self._pseudonymizer.key_id,
            subject_ref=self._pseudonymizer.fingerprint_text(principal.user_id),
            tenant_ref=self._pseudonymizer.fingerprint_text(principal.tenant_id),
            tool_name=proposal.name,
            outcome=_safe_outcome_from_result(result),
            prompt_bytes=_byte_size(message),
            argument_names=tuple(sorted(proposal.arguments)),
            argument_ref=self._pseudonymizer.fingerprint_json(proposal.arguments),
            result_keys=tuple(sorted(str(key) for key in result)),
            result_bytes=_byte_size(result),
            retrieved_document_ids=_extract_document_ids(result),
            approval_ref=(
                self._pseudonymizer.fingerprint_text(str(approval_id))
                if approval_id is not None
                else None
            ),
            ticket_ref=(
                self._pseudonymizer.fingerprint_text(str(ticket_id))
                if ticket_id is not None
                else None
            ),
            duration_ms=max(0, int(duration_ms)),
        )
        self._sink.emit(event)

    def record_approval_decision(
        self,
        *,
        trace_id: str,
        requester: Principal,
        approver: Principal,
        approval_id: str,
        proposal: ToolCallProposal,
        decision: ApprovalDecision,
        final_status: ApprovalStatus,
    ) -> None:
        event = SecurityTelemetryEvent(
            event_name=TelemetryEventName.APPROVAL_DECISION,
            trace_id=trace_id,
            fingerprint_key_id=self._pseudonymizer.key_id,
            subject_ref=self._pseudonymizer.fingerprint_text(requester.user_id),
            tenant_ref=self._pseudonymizer.fingerprint_text(requester.tenant_id),
            actor_ref=self._pseudonymizer.fingerprint_text(approver.user_id),
            tool_name=proposal.name,
            outcome=_approval_outcome(final_status),
            decision=decision,
            prompt_bytes=0,
            argument_names=tuple(sorted(proposal.arguments)),
            argument_ref=self._pseudonymizer.fingerprint_json(proposal.arguments),
            result_keys=(),
            result_bytes=0,
            approval_ref=self._pseudonymizer.fingerprint_text(approval_id),
            duration_ms=0,
        )
        self._sink.emit(event)
