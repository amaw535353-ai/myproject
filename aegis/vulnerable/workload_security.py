class VulnerableCallerDeclaredWorkloadSecurity:
    def accepts(self, request) -> bool:
        return bool(request.declared_workload_security_safe)
