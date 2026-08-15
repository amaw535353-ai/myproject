from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableStateDecision:
    accepted: bool
    declared_final_version: int
    declared_conflict_count: int


class VulnerableDeclaredStateSafety:
    """Intentionally weak baseline trusting caller-owned state/concurrency summaries."""

    def evaluate(
        self,
        *,
        declared_single_execution: bool,
        declared_state_fresh: bool,
        declared_no_races: bool,
        declared_final_version: int,
        declared_conflict_count: int,
    ) -> VulnerableStateDecision:
        return VulnerableStateDecision(
            accepted=bool(
                declared_single_execution
                and declared_state_fresh
                and declared_no_races
                and declared_conflict_count == 0
            ),
            declared_final_version=declared_final_version,
            declared_conflict_count=declared_conflict_count,
        )
