from contextvars import ContextVar
from typing import Any

from aegis.agent.execution_budget import (
    AgentExecutionLimits,
    ClockMs,
    ExecutionBudget,
    P2G_EXECUTION_LIMITS,
    P2G_POLICY_VERSION,
    monotonic_ms,
)
from aegis.agent.graph import AgentRunner


_ACTIVE_BUDGET: ContextVar[ExecutionBudget | None] = ContextVar(
    "aegisdesk_default_agent_execution_budget",
    default=None,
)


class DefaultBudgetedAgentRunner(AgentRunner):
    policy_version = P2G_POLICY_VERSION

    def __init__(
        self,
        *,
        limits: AgentExecutionLimits = P2G_EXECUTION_LIMITS,
        clock_ms: ClockMs = monotonic_ms,
        **kwargs: Any,
    ) -> None:
        self._execution_limits = limits
        self._execution_clock_ms = clock_ms
        super().__init__(**kwargs)

    @staticmethod
    def _budget() -> ExecutionBudget:
        budget = _ACTIVE_BUDGET.get()
        if budget is None:
            raise RuntimeError("execution budget unavailable")
        return budget

    def _plan(self, state: dict[str, Any]):
        self._budget().before_model(state["message"])
        return super()._plan(state)

    async def _execute(self, state: dict[str, Any]) -> dict[str, Any]:
        self._budget().before_tool(state["proposal"])
        outcome = await super()._execute(state)
        return outcome
