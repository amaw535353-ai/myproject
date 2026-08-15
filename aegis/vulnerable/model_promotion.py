from __future__ import annotations


class VulnerableCallerDeclaredModelPromotionSafety:
    """Deliberately trusts caller-owned promotion safety declarations."""

    def evaluate(self, request) -> bool:
        return bool(
            request.declared_upstream_bound
            and request.declared_training_lineage_valid
            and request.declared_phase5_provenance_bound
            and request.declared_registry_target_immutable
            and request.declared_promotion_authorized
            and request.declared_promotion_safe
        )
