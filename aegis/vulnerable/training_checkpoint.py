from __future__ import annotations

class VulnerableCallerDeclaredCheckpointSafety:
    def evaluate(self, request, manifest, p9d_assessment):
        return bool(
            request.declared_upstream_bound
            and request.declared_lineage_integrity
            and request.declared_state_integrity
            and request.declared_operation_authorized
            and request.declared_checkpoint_safe
        )
