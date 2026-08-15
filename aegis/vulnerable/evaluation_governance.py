from __future__ import annotations


class VulnerableCallerDeclaredEvaluationSafety:
    """Intentionally unsafe baseline: trusts caller-owned safety declarations."""

    def evaluate(self, request) -> bool:
        return bool(
            request.declared_upstream_bound
            and request.declared_benchmark_provenance_valid
            and request.declared_contamination_free
            and request.declared_protocol_valid
            and request.declared_performance_claim_trusted
        )
