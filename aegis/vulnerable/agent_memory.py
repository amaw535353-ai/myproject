from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableMemoryDecision:
    accepted: bool
    denied_write_count: int
    denied_retrieval_count: int


class VulnerableDeclaredMemorySafety:
    """Intentionally weak baseline trusting caller-owned memory-safety summaries."""

    def evaluate(
        self,
        *,
        declared_tenant_isolation: bool,
        declared_session_isolation: bool,
        declared_memory_trusted: bool,
        declared_denied_write_count: int,
        declared_denied_retrieval_count: int,
    ) -> VulnerableMemoryDecision:
        return VulnerableMemoryDecision(
            accepted=bool(
                declared_tenant_isolation
                and declared_session_isolation
                and declared_memory_trusted
                and declared_denied_write_count == 0
                and declared_denied_retrieval_count == 0
            ),
            denied_write_count=declared_denied_write_count,
            denied_retrieval_count=declared_denied_retrieval_count,
        )
