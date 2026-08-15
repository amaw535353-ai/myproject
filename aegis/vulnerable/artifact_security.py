from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableDeclaredArtifactSafety:
    """Intentionally vulnerable baseline that trusts caller-owned artifact safety claims."""

    path_confined: bool = True
    provenance_verified: bool = True
    executable_approved: bool = True
    persistence_risk_count: int = 0
    denied_action_count: int = 0

    def accepts(self) -> bool:
        return (
            self.path_confined
            and self.provenance_verified
            and self.executable_approved
            and self.persistence_risk_count == 0
            and self.denied_action_count == 0
        )
