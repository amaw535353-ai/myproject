from __future__ import annotations


class VulnerableCallerDeclaredTrainingExecutionSafety:
    def evaluate(self, request, manifest, p9c_assessment):
        return bool(
            request.declared_admission_bound
            and request.declared_job_identity_bound
            and request.declared_code_config_bound
            and request.declared_environment_safe
            and request.declared_secrets_least_privilege
            and request.declared_capabilities_least_privilege
            and request.declared_execution_safe
        )
