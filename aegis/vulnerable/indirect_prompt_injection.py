from aegis.agent.rag_model import DeterministicRagSecurityModel
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.rag.answering import RagAnswerOutcome
from aegis.rag.models import RagToolStatus
from aegis.rag.store import KnowledgeStore


class VulnerableRagAnswerRunner:
    """INTENTIONALLY VULNERABLE: retrieved instructions can trigger MCP tools."""

    def __init__(
        self,
        *,
        knowledge_store: KnowledgeStore,
        model: DeterministicRagSecurityModel,
        gateway: ToolGateway,
    ) -> None:
        self._knowledge_store = knowledge_store
        self._model = model
        self._gateway = gateway

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

        # INTENTIONALLY VULNERABLE: no server-owned capability or origin check.
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
