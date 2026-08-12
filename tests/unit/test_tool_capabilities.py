import pytest

from aegis.mcp_gateway.models import ToolCallProposal, ToolName
from aegis.policy.tool_capabilities import READ_ONLY_RAG_POLICY, ToolCapabilityDenied


def test_read_only_rag_policy_blocks_model_tool_proposals() -> None:
    proposal = ToolCallProposal(
        name=ToolName.CREATE_TICKET,
        arguments={"title": "Injected", "description": "Untrusted content"},
    )

    with pytest.raises(ToolCapabilityDenied):
        READ_ONLY_RAG_POLICY.require_allowed(proposal)
