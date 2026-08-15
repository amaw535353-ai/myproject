from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableExecutionBudgetDecision:
    accepted: bool
    declared_cost_microusd: int
    declared_steps: int


class VulnerableDeclaredExecutionBudgetSafety:
    """Intentionally weak baseline trusting caller-owned aggregate budget summaries."""

    def evaluate(
        self,
        *,
        declared_within_budget: bool,
        declared_no_runaway_loop: bool,
        declared_no_resource_exhaustion: bool,
        declared_cost_microusd: int,
        declared_steps: int,
    ) -> VulnerableExecutionBudgetDecision:
        return VulnerableExecutionBudgetDecision(
            accepted=bool(declared_within_budget and declared_no_runaway_loop and declared_no_resource_exhaustion),
            declared_cost_microusd=declared_cost_microusd,
            declared_steps=declared_steps,
        )
