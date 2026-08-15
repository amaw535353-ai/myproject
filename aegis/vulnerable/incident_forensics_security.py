from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableCallerDeclaredIncidentSafety:
    event_chain_trusted: bool = True
    incident_scope_complete: bool = True
    containment_complete: bool = True
    forensic_reconstruction_complete: bool = True
    reentry_authorized: bool = True
    denied_incident_count: int = 0

    def accepts(self) -> bool:
        return (
            self.event_chain_trusted
            and self.incident_scope_complete
            and self.containment_complete
            and self.forensic_reconstruction_complete
            and self.reentry_authorized
            and self.denied_incident_count == 0
        )
