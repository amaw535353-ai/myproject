class VulnerableCallerDeclaredAdapterRoutingSafety:
    def accepts(self,request): return bool(request.declared_adapter_routing_safe)
