from __future__ import annotations
from aegis.inference.scheduler_security_types import InferenceSchedulerRequest
class VulnerableCallerDeclaredSchedulerSafety:
    def accepts(self,request:InferenceSchedulerRequest)->bool: return bool(request.declared_scheduler_safe)
