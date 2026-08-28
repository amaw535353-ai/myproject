import asyncio
from pathlib import Path

import pytest

from aegis.agent.rag_model import DeterministicRagSecurityModel
from aegis.approvals.models import ApprovalStatus
from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.models import ToolName
from aegis.policy.tool_capabilities import READ_ONLY_RAG_POLICY
from aegis.rag.answering import RagAnswerRunner
from aegis.rag.models import RagToolStatus
from aegis.rag.store import KnowledgeStore
from aegis.vulnerable.indirect_prompt_injection import VulnerableRagAnswerRunner


ROOT = Path(__file__).resolve().parents[2]
POISONED = ROOT / "synthetic_data" / "p2b_poisoned_knowledge.json"
ASSETS = ROOT / "synthetic_data" / "assets.json"


def build_runners() -> tuple[
    VulnerableRagAnswerRunner,
    RagAnswerRunner,
    TicketStore,
    TicketStore,
    ApprovalStore,
    ApprovalStore,
]:
    vulnerable_store = KnowledgeStore.from_json(POISONED)
    hardened_store = KnowledgeStore.from_json(POISONED)
    vulnerable_tickets = TicketStore()
    hardened_tickets = TicketStore()
    vulnerable_approvals = ApprovalStore()
    hardened_approvals = ApprovalStore()

    vulnerable_gateway = ToolGateway(
        knowledge_store=vulnerable_store,
        asset_store=AssetStore.from_json(ASSETS),
        ticket_store=vulnerable_tickets,
        approval_store=vulnerable_approvals,
    )
    hardened_gateway = ToolGateway(
        knowledge_store=hardened_store,
        asset_store=AssetStore.from_json(ASSETS),
        ticket_store=hardened_tickets,
        approval_store=hardened_approvals,
    )
    model = DeterministicRagSecurityModel()
    return (
        VulnerableRagAnswerRunner(
            knowledge_store=vulnerable_store,
            model=model,
            gateway=vulnerable_gateway,
        ),
        RagAnswerRunner(
            knowledge_store=hardened_store,
            model=model,
            gateway=hardened_gateway,
            capability_policy=READ_ONLY_RAG_POLICY,
        ),
        vulnerable_tickets,
        hardened_tickets,
        vulnerable_approvals,
        hardened_approvals,
    )


@pytest.mark.parametrize(
    ("query", "expected_tool", "expected_document_id"),
    [
        ("orchid orchid orchid diagnostic", ToolName.CREATE_TICKET, 401),
        ("quartz quartz quartz reporting", ToolName.REQUEST_ACCESS, 402),
        ("saffron saffron saffron unicode", ToolName.CREATE_TICKET, 404),
    ],
)
def test_retrieved_instructions_execute_only_in_vulnerable_variant(
    query: str,
    expected_tool: ToolName,
    expected_document_id: int,
) -> None:
    (
        vulnerable,
        hardened,
        vulnerable_tickets,
        hardened_tickets,
        vulnerable_approvals,
        _hardened_approvals,
    ) = build_runners()
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    vulnerable_outcome = asyncio.run(
        vulnerable.answer(principal=principal, query=query, limit=1)
    )
    hardened_outcome = asyncio.run(
        hardened.answer(principal=principal, query=query, limit=1)
    )

    assert expected_document_id in vulnerable_outcome.retrieved_document_ids
    assert expected_document_id in hardened_outcome.retrieved_document_ids
    assert vulnerable_outcome.proposal is not None
    assert hardened_outcome.proposal is not None
    assert vulnerable_outcome.proposal.name is expected_tool
    assert hardened_outcome.proposal.name is expected_tool
    assert vulnerable_outcome.tool_status is RagToolStatus.EXECUTED
    assert hardened_outcome.tool_status is RagToolStatus.BLOCKED
    assert hardened_outcome.tool_result is None

    if expected_tool is ToolName.CREATE_TICKET:
        assert vulnerable_outcome.tool_result is not None
        ticket_id = str(vulnerable_outcome.tool_result["ticket_id"])
        record = vulnerable_tickets.get(ticket_id)
        assert record is not None
        assert record.created_by_user_id == principal.user_id
        assert record.tenant_id == principal.tenant_id
        assert hardened_tickets.get("TCK-0001") is None
    else:
        assert vulnerable_outcome.tool_result is not None
        approval_id = str(vulnerable_outcome.tool_result["approval_id"])
        record = vulnerable_approvals.get(approval_id)
        assert record.status is ApprovalStatus.PENDING
        assert record.requester_user_id == principal.user_id
        assert record.tenant_id == principal.tenant_id


def test_benign_retrieval_is_not_blocked_by_hardened_policy() -> None:
    _, hardened, *_ = build_runners()
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    outcome = asyncio.run(
        hardened.answer(
            principal=principal,
            query="cedar cedar cedar office hours",
            limit=1,
        )
    )

    assert 403 in outcome.retrieved_document_ids
    assert outcome.proposal is None
    assert outcome.tool_status is RagToolStatus.NONE
    assert outcome.answer
