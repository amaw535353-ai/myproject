from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableDependencyTrustReport:
    accepted: bool
    declared_graph_complete: bool
    declared_exposed_path_count: int
    declared_max_risk_score: int
    declared_all_destinations_trusted: bool


class VulnerableDependencyTrustReporter:
    """Intentionally weak baseline that trusts caller-owned aggregate declarations."""

    def evaluate(
        self,
        *,
        declared_graph_complete: bool,
        declared_exposed_path_count: int,
        declared_max_risk_score: int,
        declared_all_destinations_trusted: bool,
    ) -> VulnerableDependencyTrustReport:
        accepted = (
            declared_graph_complete
            and declared_exposed_path_count == 0
            and declared_max_risk_score == 0
            and declared_all_destinations_trusted
        )
        return VulnerableDependencyTrustReport(
            accepted=accepted,
            declared_graph_complete=declared_graph_complete,
            declared_exposed_path_count=declared_exposed_path_count,
            declared_max_risk_score=declared_max_risk_score,
            declared_all_destinations_trusted=declared_all_destinations_trusted,
        )
