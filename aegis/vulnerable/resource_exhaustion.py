from __future__ import annotations

from aegis.agent.bounded_loop import (
    LoopRunOutcome,
    LoopRunStatus,
    P2G_LAB_SAFETY_CEILING,
    context_entry,
)
from aegis.agent.execution_budget import byte_size, monotonic_ms
from aegis.agent.runaway_model import DeterministicRunawayModel
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway, ToolGatewayError


class VulnerableLoopAgentRunner:
    """INTENTIONALLY VULNERABLE: no server-owned execution budget.

    The fixed lab ceiling exists only to prevent the deterministic security test
    itself from becoming an infinite process. It is not treated as a security
    control and is deliberately higher than the hardened policy limits.
    """

    policy_version = "none-lab-safety-ceiling-only"

    def __init__(
        self,
        *,
        model: DeterministicRunawayModel,
        gateway: ToolGateway,
        lab_safety_ceiling: int = P2G_LAB_SAFETY_CEILING,
    ) -> None:
        self._model = model
        self._gateway = gateway
        self._lab_safety_ceiling = lab_safety_ceiling

    async def run(self, *, principal: Principal, message: str) -> LoopRunOutcome:
        started = monotonic_ms()
        context = message
        model_calls = 0
        tool_attempts = 0
        executed = 0
        retries = 0
        result_bytes = 0
        max_context = byte_size(context)
        tool_names: list[str] = []
        tool_results: list[dict[str, object]] = []

        for iteration in range(self._lab_safety_ceiling):
            max_context = max(max_context, byte_size(context))
            model_calls += 1
            decision = self._model.propose(message=message, iteration=iteration)
            if decision.proposal is None:
                return LoopRunOutcome(
                    status=LoopRunStatus.COMPLETED,
                    blocked_dimension=None,
                    model_calls=model_calls,
                    tool_attempts=tool_attempts,
                    executed_tool_calls=executed,
                    retries=retries,
                    result_bytes=result_bytes,
                    max_context_bytes_observed=max_context,
                    elapsed_ms=max(0, monotonic_ms() - started),
                    tool_names=tuple(tool_names),
                    tool_results=tuple(tool_results),
                    lab_ceiling_reached=False,
                )

            tool_attempts += 1
            try:
                result = await self._gateway.dispatch(
                    principal=principal,
                    proposal=decision.proposal,
                )
            except ToolGatewayError:
                retries += 1
                context += "\nTOOL_ERROR"
                continue

            executed += 1
            tool_names.append(decision.proposal.name.value)
            tool_results.append(result)
            result_bytes += byte_size(result)
            context += context_entry(decision.proposal, result)
            max_context = max(max_context, byte_size(context))

        return LoopRunOutcome(
            status=LoopRunStatus.LAB_CEILING,
            blocked_dimension=None,
            model_calls=model_calls,
            tool_attempts=tool_attempts,
            executed_tool_calls=executed,
            retries=retries,
            result_bytes=result_bytes,
            max_context_bytes_observed=max_context,
            elapsed_ms=max(0, monotonic_ms() - started),
            tool_names=tuple(tool_names),
            tool_results=tuple(tool_results),
            lab_ceiling_reached=True,
        )
