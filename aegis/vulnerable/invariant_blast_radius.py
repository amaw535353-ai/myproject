from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableArchitectureSafetyDecision:
    accepted: bool
    blast_radius: int
    max_risk_score: int


class VulnerableDeclaredArchitectureSafety:
    """Intentionally weak baseline trusting caller-owned cross-layer safety summaries."""

    def evaluate(self, *, declared_all_invariants_hold: bool, declared_blast_radius: int, declared_cross_layer_risk: int) -> VulnerableArchitectureSafetyDecision:
        return VulnerableArchitectureSafetyDecision(
            accepted=bool(declared_all_invariants_hold and declared_blast_radius == 0 and declared_cross_layer_risk == 0),
            blast_radius=declared_blast_radius,
            max_risk_score=declared_cross_layer_risk,
        )
