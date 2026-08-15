from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableAdminChangeDecision:
    accepted: bool
    exposed_route_count: int
    max_risk_score: int


class VulnerableAdminApprovedChangeReporter:
    """Intentionally weak baseline that trusts caller-owned administrative approval summaries."""

    def evaluate(
        self,
        *,
        declared_admin_approved: bool,
        declared_change_safe: bool,
        declared_exposed_route_count: int,
        declared_max_risk_score: int,
    ) -> VulnerableAdminChangeDecision:
        return VulnerableAdminChangeDecision(
            accepted=bool(declared_admin_approved and declared_change_safe and declared_exposed_route_count == 0 and declared_max_risk_score == 0),
            exposed_route_count=declared_exposed_route_count,
            max_risk_score=declared_max_risk_score,
        )
