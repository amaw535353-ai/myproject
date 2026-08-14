from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableFindingDecision:
    accepted: bool
    finding_id: str
    status: str
    declared_retest_passed: bool
    real_ticket_mutation: bool = False


class VulnerableCallerDeclaredFindingLifecycle:
    """Trust caller-declared finding status and remediation flags."""

    def transition(
        self,
        *,
        finding_id: str,
        declared_status: str,
        declared_retest_passed: bool,
    ) -> VulnerableFindingDecision:
        return VulnerableFindingDecision(
            accepted=True,
            finding_id=finding_id,
            status=declared_status,
            declared_retest_passed=declared_retest_passed,
        )
