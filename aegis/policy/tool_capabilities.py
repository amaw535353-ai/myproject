from dataclasses import dataclass

from aegis.mcp_gateway.models import ToolCallProposal, ToolName


class ToolCapabilityDenied(RuntimeError):
    """Raised when a server-owned execution context forbids a proposed tool."""


@dataclass(frozen=True)
class ToolCapabilityPolicy:
    """Server-owned allowlist for a specific execution context.

    The model, prompt, retrieved documents, MCP responses, and client cannot alter
    this object. A caller must satisfy this policy before any MCP dispatch occurs.
    """

    name: str
    allowed_tools: frozenset[ToolName]

    def require_allowed(self, proposal: ToolCallProposal) -> None:
        if proposal.name not in self.allowed_tools:
            raise ToolCapabilityDenied(
                f"tool {proposal.name.value} is not allowed by capability policy {self.name}"
            )


READ_ONLY_RAG_POLICY = ToolCapabilityPolicy(
    name="read-only-rag-capability-v1",
    allowed_tools=frozenset(),
)
