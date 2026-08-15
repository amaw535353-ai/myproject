from __future__ import annotations

from aegis.inference.streaming_security_types import InferenceStreamingSecurityRequest


class VulnerableCallerDeclaredStreamingSafety:
    """Deliberately insecure baseline: trusts the caller's final safety boolean."""

    @staticmethod
    def accepts(request: InferenceStreamingSecurityRequest) -> bool:
        return bool(request.declared_streaming_safe)
