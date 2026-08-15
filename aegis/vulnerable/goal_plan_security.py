from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableGoalPlanDecision:
    accepted: bool
    denied_steps: int
    denied_mutations: int
    max_risk_score: int


class VulnerableDeclaredGoalPlanSafety:
    """Intentionally weak baseline trusting caller-owned goal/plan safety summaries."""

    def evaluate(
        self,
        *,
        declared_goal_preserved: bool,
        declared_instruction_precedence_intact: bool,
        declared_denied_steps: int,
        declared_denied_mutations: int,
        declared_max_risk_score: int,
    ) -> VulnerableGoalPlanDecision:
        return VulnerableGoalPlanDecision(
            accepted=bool(
                declared_goal_preserved
                and declared_instruction_precedence_intact
                and declared_denied_steps == 0
                and declared_denied_mutations == 0
                and declared_max_risk_score == 0
            ),
            denied_steps=declared_denied_steps,
            denied_mutations=declared_denied_mutations,
            max_risk_score=declared_max_risk_score,
        )
