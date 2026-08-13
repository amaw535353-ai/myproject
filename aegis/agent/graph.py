import time
from dataclasses import dataclass
from threading import RLock
from typing import Any, Literal, TypedDict
from uuid import uuid4

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from aegis.agent.fake_model import DeterministicFakeModel
from aegis.agent.models import AgentRunResponse, AgentRunStatus
from aegis.approvals.durable import (
    ApprovalWorkflowContext,
    DurableWorkflowStore,
    bind_approval_workflow_context,
    reset_approval_workflow_context,
)
from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.approvals.store import ApprovalStateError, ApprovalStore
from aegis.effects.durable import DurableApprovedEffectPipeline
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.models import ToolCallProposal, ToolName
from aegis.observability.security_events import ToolTelemetryRecorder


MAX_TOOL_CALLS = 1
_HIGH_IMPACT_TOOLS = {
    ToolName.REQUEST_ACCESS,
    ToolName.REQUEST_PASSWORD_RESET,
}


class AgentState(TypedDict, total=False):
    principal: Principal
    message: str
    proposal: ToolCallProposal
    tool_result: dict[str, Any]
    tool_calls: int
    approval_outcome: str
    trace_id: str
    thread_id: str


@dataclass(frozen=True)
class PendingRun:
    thread_id: str
    trace_id: str
    requester: Principal
    proposal: ToolCallProposal


class AgentRunner:
    def __init__(
        self,
        *,
        model: DeterministicFakeModel,
        gateway: ToolGateway,
        approval_store: ApprovalStore,
        telemetry: ToolTelemetryRecorder | None = None,
        workflow_store: DurableWorkflowStore | None = None,
        approved_effect_pipeline: DurableApprovedEffectPipeline | None = None,
    ) -> None:
        self._model = model
        self._gateway = gateway
        self._approval_store = approval_store
        self._telemetry = telemetry
        self._workflow_store = workflow_store
        self._approved_effect_pipeline = approved_effect_pipeline
        self._pending_runs: dict[str, PendingRun] = {}
        self._pending_lock = RLock()

        graph = StateGraph(AgentState)
        graph.add_node("plan", self._plan)
        graph.add_node("execute", self._execute)
        graph.add_node("await_approval", self._await_approval)
        graph.add_edge(START, "plan")
        graph.add_edge("plan", "execute")
        graph.add_conditional_edges(
            "execute",
            self._route_after_execute,
            {
                "approval": "await_approval",
                "done": END,
            },
        )
        graph.add_edge("await_approval", END)
        self._graph = graph.compile(checkpointer=InMemorySaver())

    def _plan(self, state: AgentState) -> dict[str, ToolCallProposal]:
        return {"proposal": self._model.propose(state["message"])}

    async def _execute(self, state: AgentState) -> dict[str, Any]:
        calls = state.get("tool_calls", 0)
        if calls >= MAX_TOOL_CALLS:
            raise RuntimeError("tool call budget exhausted")

        normalized = self._gateway.normalize_proposal(state["proposal"])
        workflow_token = None
        if normalized.name in _HIGH_IMPACT_TOOLS and self._workflow_store is not None:
            workflow_token = bind_approval_workflow_context(
                ApprovalWorkflowContext(
                    thread_id=state["thread_id"],
                    trace_id=state["trace_id"],
                    tool_calls=calls + 1,
                )
            )

        started_ns = time.monotonic_ns()
        try:
            result = await self._gateway.dispatch(
                principal=state["principal"],
                proposal=normalized,
            )
        finally:
            if workflow_token is not None:
                reset_approval_workflow_context(workflow_token)
        duration_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)

        if self._telemetry is not None:
            self._telemetry.record_tool_execution(
                trace_id=state["trace_id"],
                principal=state["principal"],
                message=state["message"],
                proposal=normalized,
                result=result,
                duration_ms=duration_ms,
            )

        return {
            "proposal": normalized,
            "tool_result": result,
            "tool_calls": calls + 1,
        }

    def _route_after_execute(self, state: AgentState) -> Literal["approval", "done"]:
        if state["proposal"].name in _HIGH_IMPACT_TOOLS:
            return "approval"
        return "done"

    def _await_approval(self, state: AgentState) -> dict[str, Any]:
        if self._workflow_store is not None:
            return {}

        approval_id = str(state["tool_result"]["approval_id"])
        interrupt(
            {
                "approval_id": approval_id,
                "action": state["proposal"].name.value,
                "status": "pending",
            }
        )

        record = self._approval_store.resolve_after_review(
            approval_id=approval_id,
            requester=state["principal"],
            action=ApprovalAction(state["proposal"].name.value),
            arguments=state["proposal"].arguments,
        )
        if record.status is ApprovalStatus.REJECTED:
            outcome = "rejected"
        elif record.status is ApprovalStatus.CONSUMED:
            outcome = "approved"
        else:
            raise ApprovalStateError("unexpected approval state after review")

        return {
            "tool_result": {
                **state["tool_result"],
                "status": record.status.value,
            },
            "approval_outcome": outcome,
        }

    async def run(self, *, principal: Principal, message: str) -> AgentRunResponse:
        thread_id = uuid4().hex
        trace_id = uuid4().hex
        config = {"configurable": {"thread_id": thread_id}}
        state = await self._graph.ainvoke(
            {
                "principal": principal,
                "message": message,
                "tool_calls": 0,
                "trace_id": trace_id,
                "thread_id": thread_id,
            },
            config=config,
        )
        proposal = state["proposal"]

        if proposal.name in _HIGH_IMPACT_TOOLS:
            approval_id = str(state["tool_result"]["approval_id"])
            if self._workflow_store is None:
                with self._pending_lock:
                    self._pending_runs[approval_id] = PendingRun(
                        thread_id=thread_id,
                        trace_id=trace_id,
                        requester=principal,
                        proposal=proposal,
                    )
            return AgentRunResponse(
                tool=proposal.name,
                result=state["tool_result"],
                tool_calls=state["tool_calls"],
                status=AgentRunStatus.PENDING_APPROVAL,
                approval_id=approval_id,
            )

        return AgentRunResponse(
            tool=proposal.name,
            result=state["tool_result"],
            tool_calls=state["tool_calls"],
        )

    async def review_and_resume(
        self,
        *,
        approval_id: str,
        approver: Principal,
        decision: ApprovalDecision,
    ) -> AgentRunResponse:
        if self._workflow_store is not None:
            return await self._review_and_resume_durable(
                approval_id=approval_id,
                approver=approver,
                decision=decision,
            )

        with self._pending_lock:
            pending = self._pending_runs.get(approval_id)
        if pending is None:
            raise ApprovalStateError("no pending workflow for approval")

        self._approval_store.decide(
            approval_id=approval_id,
            approver=approver,
            decision=decision,
        )

        config = {"configurable": {"thread_id": pending.thread_id}}
        state = await self._graph.ainvoke(
            Command(resume={"reviewed_approval_id": approval_id}),
            config=config,
        )

        with self._pending_lock:
            current = self._pending_runs.get(approval_id)
            if current == pending:
                self._pending_runs.pop(approval_id, None)

        outcome = state.get("approval_outcome")
        status = (
            AgentRunStatus.APPROVED
            if outcome == "approved"
            else AgentRunStatus.REJECTED
        )

        if self._telemetry is not None:
            self._telemetry.record_approval_decision(
                trace_id=pending.trace_id,
                requester=pending.requester,
                approver=approver,
                approval_id=approval_id,
                proposal=pending.proposal,
                decision=decision,
                final_status=ApprovalStatus(state["tool_result"]["status"]),
            )

        return AgentRunResponse(
            tool=pending.proposal.name,
            result=state["tool_result"],
            tool_calls=state["tool_calls"],
            status=status,
            approval_id=approval_id,
        )

    async def _review_and_resume_durable(
        self,
        *,
        approval_id: str,
        approver: Principal,
        decision: ApprovalDecision,
    ) -> AgentRunResponse:
        assert self._workflow_store is not None
        pending = self._workflow_store.require_pending(approval_id)
        proposal = ToolCallProposal(
            name=ToolName(pending.action.value),
            arguments=pending.arguments,
        )
        requester = pending.requester

        self._approval_store.decide(
            approval_id=approval_id,
            approver=approver,
            decision=decision,
        )
        if self._approved_effect_pipeline is not None:
            record, _effect = self._approved_effect_pipeline.resolve_and_deliver(
                approval_id=approval_id,
                requester=requester,
                action=pending.action,
                arguments=pending.arguments,
            )
        else:
            record = self._approval_store.resolve_after_review(
                approval_id=approval_id,
                requester=requester,
                action=pending.action,
                arguments=pending.arguments,
            )

        if record.status is ApprovalStatus.REJECTED:
            outcome = "rejected"
            status = AgentRunStatus.REJECTED
        elif record.status is ApprovalStatus.CONSUMED:
            outcome = "approved"
            status = AgentRunStatus.APPROVED
        else:
            raise ApprovalStateError("unexpected durable approval state after review")

        self._workflow_store.complete(approval_id=approval_id, outcome=outcome)

        if self._telemetry is not None:
            self._telemetry.record_approval_decision(
                trace_id=pending.trace_id,
                requester=requester,
                approver=approver,
                approval_id=approval_id,
                proposal=proposal,
                decision=decision,
                final_status=record.status,
            )

        result = {
            "approval_id": record.approval_id,
            "action": record.action.value,
            "status": record.status.value,
            "expires_at": record.expires_at.isoformat(),
        }
        return AgentRunResponse(
            tool=proposal.name,
            result=result,
            tool_calls=pending.tool_calls,
            status=status,
            approval_id=approval_id,
        )
