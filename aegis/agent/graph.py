from dataclasses import dataclass
from threading import RLock
from typing import Any, Literal, TypedDict
from uuid import uuid4

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from aegis.agent.fake_model import DeterministicFakeModel
from aegis.agent.models import AgentRunResponse, AgentRunStatus
from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.approvals.store import ApprovalStateError, ApprovalStore
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.models import ToolCallProposal, ToolName


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


@dataclass(frozen=True)
class PendingRun:
    thread_id: str
    requester: Principal
    proposal: ToolCallProposal


class AgentRunner:
    def __init__(
        self,
        *,
        model: DeterministicFakeModel,
        gateway: ToolGateway,
        approval_store: ApprovalStore,
    ) -> None:
        self._model = model
        self._gateway = gateway
        self._approval_store = approval_store
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
        result = await self._gateway.dispatch(
            principal=state["principal"],
            proposal=normalized,
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
        config = {"configurable": {"thread_id": thread_id}}
        state = await self._graph.ainvoke(
            {"principal": principal, "message": message, "tool_calls": 0},
            config=config,
        )
        proposal = state["proposal"]

        if proposal.name in _HIGH_IMPACT_TOOLS:
            approval_id = str(state["tool_result"]["approval_id"])
            with self._pending_lock:
                self._pending_runs[approval_id] = PendingRun(
                    thread_id=thread_id,
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
        return AgentRunResponse(
            tool=pending.proposal.name,
            result=state["tool_result"],
            tool_calls=state["tool_calls"],
            status=status,
            approval_id=approval_id,
        )
