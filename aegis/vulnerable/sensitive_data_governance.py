from __future__ import annotations

from aegis.training.sensitive_data_types import SensitiveDataDecision


class VulnerableCallerDeclaredSensitiveDataSafety:
    def evaluate(self, request, manifest=None, p9f_assessment=None):
        trusted = (
            request.declared_upstream_bound
            and request.declared_input_governance_valid
            and request.declared_output_governance_valid
            and request.declared_canary_free
            and request.declared_sensitive_data_safe
        )
        return SensitiveDataDecision.ALLOW if trusted else SensitiveDataDecision.DENY
