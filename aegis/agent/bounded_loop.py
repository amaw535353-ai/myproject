from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aegis.agent.execution_budget import (
    AgentExecutionLimits,
    BudgetDimension,
    BudgetExceeded,
    ClockMs,
    ExecutionBudget,
    P2G_EXECUTION_LIMITS,
    P2G_POLICY_VERSION,
    byte_size,
    monotonic_ms,
)
from aegis.agent.runaway_model import DeterministicRunawayModel
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway, ToolGatewayError
from aegis.mcp_gateway.models import ToolCallProposal


P2G_LAB_SAFETY_CEILING = 6


class LoopRunStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    LAB_CEILING = "lab_ceiling"


@dataclass(frozen=True)
class LoopRunOutcome:
    status: LoopRunStatus
    blocked_dimension: BudgetDimension | None
    model_calls: int
    tool_attempts: int
    executed_tool_calls: int
    retries: int
    result_bytes: int
    max_context_bytes_observed: int
    elapsed_ms: int
    tool_names: tuple[str, ...]
    tool_results: tuple[dict[str, Any], ...]
    lab_ceiling_reached: bool


def context_entry(
    proposal: ToolCallProposal,
    result: dict[str, Any],
) -> str:
    rendered = json.dumps(
        {
            "tool": proposal.name.value,
            "result": result,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return f"\n{rendered}"


class BoundedLoopAgentRunner:
    """Multi-step agent host with server-owned, deterministic resource budgets."""

    policy_version = P2G_POLICY_VERSION

    def __init__(
        self,
        *,
        model: DeterministicRunawayModel,
        gateway: ToolGateway,
        limits: AgentExecutionLimits = P2G_EXECUTION_LIMITS,
        lab_safety_ceiling: int = P2G_LAB_SAFETY_CEILING,
        clock_ms: ClockMs = monotonic_ms,
    ) -> None:
        self._model = model
        self._gateway = gateway
        self._limits = limits
        self._lab_safety_ceiling = lab_safety_ceiling
        self._clock_ms = clock_ms

    async def run(self, *, principal: Principal, message: str) -> LoopRunOutcome:
        budget = ExecutionBudget(limits=self._limits, clock_ms=self._clock_ms)
        executed = 0
        tool_names: list[str] = []
        tool_results: list[dict[str, Any]] = []
        context = message

        try:
            budget.validate_input(message)
            for iteration in range(self._lab_safety_ceiling):
                budget.before_model(context)
                decision = self._model.propose(message=message, iteration=iteration)
                if decision.proposal is None:
                    return self._outcome(
                        budget=budget,
                        status=LoopRunStatus.COMPLETED,
                        blocked_dimension=None,
                        executed=executed,
                        tool_names=tool_names,
                        tool_results=tool_results,
                        lab_ceiling_reached=False,
                    )

                budget.before_tool(decision.proposal)
                try:
                    result = await self._gateway.dispatch(
                        principal=principal,
                        proposal=decision.proposal,
                    )
                except ToolGatewayError:
                    budget.record_retry()
                    context += "\nTOOL_ERROR"
                    continue

                executed += 1
                tool_names.append(decision.proposal.name.value)
                tool_results.append(result)
                budget.after_tool(result)
                context += context_entry(decision.proposal, result)

            return self._outcome(
                budget=budget,
                status=LoopRunStatus.LAB_CEILING,
                blocked_dimension=None,
                executed=executed,
                tool_names=tool_names,
                tool_results=tool_results,
                lab_ceiling_reached=True,
                extra_context_bytes=byte_size(context),
            )
        except BudgetExceeded as exc:
            return self._outcome(
                budget=budget,
                status=LoopRunStatus.BLOCKED,
                blocked_dimension=exc.dimension,
                executed=executed,
                tool_names=tool_names,
                tool_results=tool_results,
                lab_ceiling_reached=False,
                extra_context_bytes=exc.observed
                if exc.dimension is BudgetDimension.CONTEXT_BYTES
                else None,
            )

    @staticmethod
    def _outcome(
        *,
        budget: ExecutionBudget,
        status: LoopRunStatus,
        blocked_dimension: BudgetDimension | None,
        executed: int,
        tool_names: list[str],
        tool_results: list[dict[str, Any]],
        lab_ceiling_reached: bool,
        extra_context_bytes: int | None = None,
    ) -> LoopRunOutcome:
        snapshot = budget.snapshot()
        max_context = snapshot.max_context_bytes_observed
        if extra_context_bytes is not None:
            max_context = max(max_context, extra_context_bytes)
        return LoopRunOutcome(
            status=status,
            blocked_dimension=blocked_dimension,
            model_calls=snapshot.model_calls,
            tool_attempts=snapshot.tool_calls,
            executed_tool_calls=executed,
            retries=snapshot.retries,
            result_bytes=snapshot.result_bytes,
            max_context_bytes_observed=max_context,
            elapsed_ms=snapshot.elapsed_ms,
            tool_names=tuple(tool_names),
            tool_results=tuple(tool_results),
            lab_ceiling_reached=lab_ceiling_reached,
        )
