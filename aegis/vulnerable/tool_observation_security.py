from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableToolObservationReport:
    accepted: bool
    denied_observation_count: int
    maximum_risk_score: int


class VulnerableDeclaredToolObservationSafety:
    """Intentionally weak: trusts caller-owned summaries rather than binding result provenance."""

    def evaluate(self, *, declared_tool_success: bool, declared_observation_authoritative: bool, declared_denied_observation_count: int, declared_maximum_risk_score: int) -> VulnerableToolObservationReport:
        accepted = declared_tool_success and declared_observation_authoritative and declared_denied_observation_count == 0 and declared_maximum_risk_score == 0
        return VulnerableToolObservationReport(accepted, declared_denied_observation_count, declared_maximum_risk_score)
