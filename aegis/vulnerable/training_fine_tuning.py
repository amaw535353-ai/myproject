from __future__ import annotations

class VulnerableCallerDeclaredFineTuningSafety:
    def evaluate(self, request, manifest, p9b_assessment):
        return bool(
            request.declared_authorized
            and request.declared_base_model_bound
            and request.declared_adapter_policy_safe
            and request.declared_training_admission_safe
        )
