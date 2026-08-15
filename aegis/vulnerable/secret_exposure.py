from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableSecretExposureReport:
    graph_complete: bool
    exposed_path_count: int
    max_blast_radius_score: int
    safe: bool


class VulnerableSecretExposureReporter:
    """Intentionally weak baseline: trusts caller-declared secret exposure summaries."""

    def evaluate(
        self,
        *,
        declared_graph_complete: bool,
        declared_exposed_path_count: int,
        declared_max_blast_radius_score: int,
    ) -> VulnerableSecretExposureReport:
        return VulnerableSecretExposureReport(
            graph_complete=declared_graph_complete,
            exposed_path_count=declared_exposed_path_count,
            max_blast_radius_score=declared_max_blast_radius_score,
            safe=bool(declared_graph_complete and declared_exposed_path_count == 0 and declared_max_blast_radius_score == 0),
        )
