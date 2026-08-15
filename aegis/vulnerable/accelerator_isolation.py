class VulnerableCallerDeclaredAcceleratorSafety:
    def accepts(self, request) -> bool:
        return bool(request.declared_accelerator_safe)
