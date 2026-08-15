from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableMonitoringCoverageReport:
    accepted: bool
    declared_fully_monitored: bool
    declared_coverage_percent: int
    declared_blind_spot_count: int
    declared_max_blind_spot_risk_score: int


class VulnerableMonitoringCoverageReporter:
    """Intentionally weak baseline that trusts caller-owned monitoring aggregates."""

    def evaluate(
        self,
        *,
        declared_fully_monitored: bool,
        declared_coverage_percent: int,
        declared_blind_spot_count: int,
        declared_max_blind_spot_risk_score: int,
    ) -> VulnerableMonitoringCoverageReport:
        accepted = (
            declared_fully_monitored
            and declared_coverage_percent == 100
            and declared_blind_spot_count == 0
            and declared_max_blind_spot_risk_score == 0
        )
        return VulnerableMonitoringCoverageReport(
            accepted=accepted,
            declared_fully_monitored=declared_fully_monitored,
            declared_coverage_percent=declared_coverage_percent,
            declared_blind_spot_count=declared_blind_spot_count,
            declared_max_blind_spot_risk_score=declared_max_blind_spot_risk_score,
        )
