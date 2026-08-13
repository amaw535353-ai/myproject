from aegis.agent.models import AgentRunResponse
from aegis.identity.models import Principal


class VulnerablePartialAgentRunner:
    """P3-B comparison: one tool call, but no P2-G byte/time/resource budget."""

    policy_version = "single-tool-call-only-no-p2g-budget-v1"

    def __init__(self, *, model, gateway) -> None:
        self._model = model
        self._gateway = gateway

    async def run(self, *, principal: Principal, message: str) -> AgentRunResponse:
        proposal = self._model.propose(message)
        normalized = self._gateway.normalize_proposal(proposal)
        result = await self._gateway.dispatch(principal=principal, proposal=normalized)
        return AgentRunResponse(tool=normalized.name, result=result, tool_calls=1)
