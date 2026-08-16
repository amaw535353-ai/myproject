from __future__ import annotations


class VulnerableCallerDeclaredIncidentResponseSafety:
    def accepts(self, request) -> bool:
        return bool(request.declared_incident_response_safe)
