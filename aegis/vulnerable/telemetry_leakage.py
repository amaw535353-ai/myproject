from __future__ import annotations

from copy import deepcopy
from threading import Lock
from typing import Any

from aegis.approvals.models import ApprovalDecision, ApprovalStatus
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import ToolCallProposal


class VulnerableRawTelemetryRecorder:
    """Intentionally unsafe local-only telemetry baseline.

    It demonstrates the failure mode where an application forwards whole prompts,
    principal objects, tool arguments, and tool results into a telemetry backend.
    """

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._lock = Lock()

    @property
    def policy_version(self) -> str:
        return "raw-whole-object-telemetry-v1"

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
        event = {
            "event_name": "agent.tool_execution",
            "trace_id": trace_id,
            "principal": principal.model_dump(mode="json"),
            "message": message,
            "proposal": proposal.model_dump(mode="json"),
            "result": deepcopy(result),
            "duration_ms": duration_ms,
        }
        with self._lock:
            self._events.append(event)

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
        event = {
            "event_name": "approval.decision",
            "trace_id": trace_id,
            "requester": requester.model_dump(mode="json"),
            "approver": approver.model_dump(mode="json"),
            "approval_id": approval_id,
            "proposal": proposal.model_dump(mode="json"),
            "decision": decision.value,
            "final_status": final_status.value,
        }
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(deepcopy(self._events))
