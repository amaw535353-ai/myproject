from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableCorpusEvolutionDecision:
    accepted: bool
    declared_coverage_ok: bool
    declared_untracked_changes: int


class VulnerableSelfReportedCorpusEvolutionGate:
    """Intentionally unsafe baseline that trusts aggregate caller declarations."""

    def evaluate(
        self,
        *,
        declared_coverage_ok: bool,
        declared_untracked_changes: int,
    ) -> VulnerableCorpusEvolutionDecision:
        return VulnerableCorpusEvolutionDecision(
            accepted=bool(declared_coverage_ok and declared_untracked_changes == 0),
            declared_coverage_ok=declared_coverage_ok,
            declared_untracked_changes=declared_untracked_changes,
        )
