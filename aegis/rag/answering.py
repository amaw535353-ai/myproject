from dataclasses import dataclass
from typing import Any

from aegis.agent.rag_model import DeterministicRagSecurityModel
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.models import ToolCallProposal
from aegis.policy.tool_capabilities import ToolCapabilityDenied, ToolCapabilityPolicy
from aegis.rag.models import RagAnswerResponse, RagToolStatus
from aegis.rag.store import KnowledgeStore


@dataclass(frozen=True)
class RagAnswerOutcome:
    answer: str
    retrieved_document_ids: tuple[int, ...]
    proposal: ToolCallProposal | None
    tool_status: RagToolStatus
    tool_result: dict[str, Any] | None


def to_public_response(outcome: RagAnswerOutcome) -> RagAnswerResponse:
    return RagAnswerResponse(
        answer=outcome.answer,
        retrieved_document_ids=list(outcome.retrieved_document_ids),
        proposed_tool=outcome.proposal.name.value if outcome.proposal is not None else None,
        tool_status=outcome.tool_status,
    )


class RagAnswerRunner:
    """Hardened RAG answer path with a server-owned tool capability boundary."""

    def __init__(
        self,
        *,
        knowledge_store: KnowledgeStore,
        model: DeterministicRagSecurityModel,
        gateway: ToolGateway,
        capability_policy: ToolCapabilityPolicy,
    ) -> None:
        self._knowledge_store = knowledge_store
        self._model = model
        self._gateway = gateway
        self._capability_policy = capability_policy

    async def answer(
        self,
        *,
        principal: Principal,
        query: str,
        limit: int = 3,
    ) -> RagAnswerOutcome:
        documents = self._knowledge_store.search(
            principal=principal,
            query=query,
            limit=limit,
        )
        decision = self._model.respond(user_query=query, documents=documents)

        if decision.proposal is None:
            return RagAnswerOutcome(
                answer=decision.answer,
                retrieved_document_ids=tuple(doc.document_id for doc in documents),
                proposal=None,
                tool_status=RagToolStatus.NONE,
                tool_result=None,
            )

        try:
            self._capability_policy.require_allowed(decision.proposal)
        except ToolCapabilityDenied:
            return RagAnswerOutcome(
                answer=decision.answer,
                retrieved_document_ids=tuple(doc.document_id for doc in documents),
                proposal=decision.proposal,
                tool_status=RagToolStatus.BLOCKED,
                tool_result=None,
            )

        result = await self._gateway.dispatch(
            principal=principal,
            proposal=decision.proposal,
        )
        return RagAnswerOutcome(
            answer=decision.answer,
            retrieved_document_ids=tuple(doc.document_id for doc in documents),
            proposal=decision.proposal,
            tool_status=RagToolStatus.EXECUTED,
            tool_result=result,
        )
