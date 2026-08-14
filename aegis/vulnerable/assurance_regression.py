from __future__ import annotations

from dataclasses import dataclass

from aegis.assurance.regression import ReleaseAssuranceEvidence


@dataclass(frozen=True)
class VulnerableAssuranceDecision:
    candidate_release_id: str
    accepted: bool
    declared_pass_rate_ppm: int
    declared_regressions: int


class VulnerableAggregateAssuranceGate:
    """Vulnerable baseline that trusts caller-provided aggregate assurance claims."""

    def evaluate(
        self,
        *,
        candidate: ReleaseAssuranceEvidence,
        declared_pass_rate_ppm: int = 1_000_000,
        declared_regressions: int = 0,
    ) -> VulnerableAssuranceDecision:
        return VulnerableAssuranceDecision(
            candidate_release_id=candidate.release_id,
            accepted=declared_pass_rate_ppm >= 950_000 and declared_regressions == 0,
            declared_pass_rate_ppm=declared_pass_rate_ppm,
            declared_regressions=declared_regressions,
        )
