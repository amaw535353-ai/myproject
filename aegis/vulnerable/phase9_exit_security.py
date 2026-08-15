from __future__ import annotations

from aegis.training.phase9_exit_types import Phase9ExitDecision, Phase9ExitRequest


class VulnerableCallerDeclaredPhase9Exit:
    """Intentionally unsafe baseline that trusts the caller's exit decision."""

    def accepts(self, request: Phase9ExitRequest) -> bool:
        return request.declared_exit_decision != Phase9ExitDecision.FAIL
