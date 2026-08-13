from typing import Any

from aegis.agent.execution_budget import (
    AgentExecutionLimits,
    ExecutionBudget,
    P2G_EXECUTION_LIMITS,
    P2G_POLICY_VERSION,
)
from aegis.agent.graph import AgentRunner


class DefaultBudgetedAgentRunner(AgentRunner):
    policy_version = P2G_POLICY_VERSION

    def __init__(
        self,
        *,
        limits: AgentExecutionLimits = P2G_EXECUTION_LIMITS,
        **kwargs: Any,
    ) -> None:
        self._execution_limits = limits
        super().__init__(**kwargs)
