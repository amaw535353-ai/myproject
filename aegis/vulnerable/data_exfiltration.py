from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableDataExfiltrationReport:
    data_graph_complete: bool
    declared_exposed_path_count: int
    declared_max_risk_score: int
    accepted: bool


class VulnerableDataExfiltrationReporter:
    """Intentionally weak comparison that trusts caller summaries.

    It does not validate data classification, tenant ownership, route coverage, P7-A/P7-B/P6-D
    evidence, sink authorization, transforms, or per-route control status.
    """

    def evaluate(
        self,
        *,
        data_graph_complete: bool,
        declared_exposed_path_count: int,
        declared_max_risk_score: int,
    ) -> VulnerableDataExfiltrationReport:
        accepted = bool(
            data_graph_complete
            and declared_exposed_path_count == 0
            and declared_max_risk_score == 0
        )
        return VulnerableDataExfiltrationReport(
            data_graph_complete=data_graph_complete,
            declared_exposed_path_count=declared_exposed_path_count,
            declared_max_risk_score=declared_max_risk_score,
            accepted=accepted,
        )
