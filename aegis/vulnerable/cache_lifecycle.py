class VulnerableCallerDeclaredCacheLifecycleSafety:
    def accepts(self,request): return bool(request.declared_cache_lifecycle_safe)
