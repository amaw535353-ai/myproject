from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableAttackPathReport:
    architecture_id: str
    accepted: bool
    declared_exposed_path_count: int
    declared_max_risk_score: int
    architecture_complete: bool


class VulnerableAttackPathReporter:
    """Deliberately unsafe baseline that trusts caller-supplied graph/risk summaries."""

    def evaluate(
        self,
        *,
        architecture_id: str,
        architecture_complete: bool,
        declared_exposed_path_count: int,
        declared_max_risk_score: int,
    ) -> VulnerableAttackPathReport:
        accepted = (
            bool(architecture_id)
            and architecture_complete
            and declared_exposed_path_count >= 0
            and declared_max_risk_score >= 0
        )
        return VulnerableAttackPathReport(
            architecture_id=architecture_id,
            accepted=accepted,
            declared_exposed_path_count=declared_exposed_path_count,
            declared_max_risk_score=declared_max_risk_score,
            architecture_complete=architecture_complete,
        )
