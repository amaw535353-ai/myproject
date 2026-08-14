from __future__ import annotations

from dataclasses import dataclass

from aegis.assurance.regression import ReleaseAssuranceEvidence


@dataclass(frozen=True)
class VulnerableWaiverDecision:
    accepted: bool
    declared_waived_case_ids: tuple[str, ...]
    declared_critical_waivers: int


class VulnerableDeclaredWaiverGate:
    """Trust caller-declared waiver counts and case IDs without governance validation."""

    def evaluate(
        self,
        *,
        candidate: ReleaseAssuranceEvidence,
        declared_waived_case_ids: tuple[str, ...],
        declared_critical_waivers: int = 0,
    ) -> VulnerableWaiverDecision:
        del candidate
        return VulnerableWaiverDecision(
            accepted=declared_critical_waivers >= 0,
            declared_waived_case_ids=declared_waived_case_ids,
            declared_critical_waivers=declared_critical_waivers,
        )
