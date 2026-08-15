from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableAvailabilityRestorationReport:
    accepted: bool
    declared_all_dependencies_recovered: bool
    declared_fallbacks_safe: bool
    declared_security_degradation_count: int
    declared_max_security_risk_score: int


class VulnerableAvailabilityRestorationReporter:
    """Intentionally weak baseline that equates restored availability with preserved security."""

    def evaluate(
        self,
        *,
        declared_all_dependencies_recovered: bool,
        declared_fallbacks_safe: bool,
        declared_security_degradation_count: int,
        declared_max_security_risk_score: int,
    ) -> VulnerableAvailabilityRestorationReport:
        accepted = (
            declared_all_dependencies_recovered
            and declared_fallbacks_safe
            and declared_security_degradation_count == 0
            and declared_max_security_risk_score == 0
        )
        return VulnerableAvailabilityRestorationReport(
            accepted=accepted,
            declared_all_dependencies_recovered=declared_all_dependencies_recovered,
            declared_fallbacks_safe=declared_fallbacks_safe,
            declared_security_degradation_count=declared_security_degradation_count,
            declared_max_security_risk_score=declared_max_security_risk_score,
        )
