from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from aegis.agent.fake_model import DeterministicFakeModel
from aegis.agent.models import AgentRunResponse
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.models import ToolCallProposal


MAX_TOOL_CALLS = 1


class AgentState(TypedDict, total=False):
    principal: Principal
    message: str
    proposal: ToolCallProposal
    tool_result: dict[str, Any]
    tool_calls: int


class AgentRunner:
    def __init__(self, *, model: DeterministicFakeModel, gateway: ToolGateway) -> None:
        self._model = model
        self._gateway = gateway

        graph = StateGraph(AgentState)
        graph.add_node("plan", self._plan)
        graph.add_node("execute", self._execute)
        graph.add_edge(START, "plan")
        graph.add_edge("plan", "execute")
        graph.add_edge("execute", END)
        self._graph = graph.compile()

    def _plan(self, state: AgentState) -> dict[str, ToolCallProposal]:
        return {"proposal": self._model.propose(state["message"])}

    async def _execute(self, state: AgentState) -> dict[str, Any]:
        calls = state.get("tool_calls", 0)
        if calls >= MAX_TOOL_CALLS:
            raise RuntimeError("tool call budget exhausted")

        result = await self._gateway.dispatch(
            principal=state["principal"],
            proposal=state["proposal"],
        )
        return {"tool_result": result, "tool_calls": calls + 1}

    async def run(self, *, principal: Principal, message: str) -> AgentRunResponse:
        state = await self._graph.ainvoke(
            {"principal": principal, "message": message, "tool_calls": 0}
        )
        proposal = state["proposal"]
        return AgentRunResponse(
            tool=proposal.name,
            result=state["tool_result"],
            tool_calls=state["tool_calls"],
        )
