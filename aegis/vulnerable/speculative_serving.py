class VulnerableCallerDeclaredSpeculativeServingSafety:
    def accepts(self,request): return bool(request.declared_serving_safe)
