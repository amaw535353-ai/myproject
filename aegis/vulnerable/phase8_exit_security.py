from __future__ import annotations

from aegis.agentic.phase8_exit_types import Phase8ExitDecision


class VulnerableCallerDeclaredPhase8Exit:
    """Intentionally unsafe baseline: trusts caller-declared completion and CI state."""

    def accepts(self, declared_decision: Phase8ExitDecision = Phase8ExitDecision.PASS) -> bool:
        return declared_decision in {
            Phase8ExitDecision.PASS,
            Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION,
        }
