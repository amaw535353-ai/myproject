from __future__ import annotations

from aegis.inference.tenant_isolation_types import InferenceTenantIsolationRequest


class VulnerableCallerDeclaredInferenceIsolation:
    """Vulnerable baseline: trusts caller-declared inference isolation safety."""

    def accepts(self, request: InferenceTenantIsolationRequest) -> bool:
        return bool(request.declared_isolation_safe)
