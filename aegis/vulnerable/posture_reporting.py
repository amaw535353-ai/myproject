from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerablePostureReport:
    accepted: bool
    rating: str
    satisfied_controls: int
    exceptioned_controls: int
    not_evaluated_controls: int


class VulnerableDeclaredPostureReporter:
    """Trust caller-declared posture and aggregate counts without evidence binding."""

    def report(
        self,
        *,
        declared_rating: str,
        declared_satisfied_controls: int,
        declared_exceptioned_controls: int,
        declared_not_evaluated_controls: int,
    ) -> VulnerablePostureReport:
        return VulnerablePostureReport(
            accepted=True,
            rating=declared_rating,
            satisfied_controls=declared_satisfied_controls,
            exceptioned_controls=declared_exceptioned_controls,
            not_evaluated_controls=declared_not_evaluated_controls,
        )
