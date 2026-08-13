from importlib.metadata import version
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status

from aegis.agent.execution_budget import BudgetDimension, BudgetExceeded
from aegis.agent.graph import AgentRunner
from aegis.agent.models import AgentRunRequest, AgentRunResponse
from aegis.approvals.models import ApprovalDecisionRequest
from aegis.approvals.store import ApprovalError
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGatewayError
from aegis.memory.default_runtime import DefaultMemoryContextService
from aegis.memory.models import MemoryRecord, RememberNote
from aegis.rag.answering import RagAnswerRunner, to_public_response
from aegis.rag.models import (
    RagAnswerRequest,
    RagAnswerResponse,
    SearchRequest,
    SearchResponse,
    SearchResult,
)
from aegis.rag.store import KnowledgeStore
from apps.api.dependencies import (
    get_agent_runner,
    get_current_principal,
    get_knowledge_store,
    get_memory_context_service,
    get_rag_answer_runner,
)


app = FastAPI(title="AegisDesk", version=version("aegisdesk"))


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/knowledge/search", response_model=SearchResponse)
def search_knowledge_base(
    request: SearchRequest,
    principal: Annotated[Principal, Depends(get_current_principal)],
    store: Annotated[KnowledgeStore, Depends(get_knowledge_store)],
) -> SearchResponse:
    documents = store.search(
        principal=principal,
        query=request.query,
        limit=request.limit,
    )
    return SearchResponse(
        results=[
            SearchResult(
                document_id=document.document_id,
                title=document.title,
                text=document.text,
            )
            for document in documents
        ]
    )


@app.post("/v1/rag/answer", response_model=RagAnswerResponse)
async def answer_with_rag(
    request: RagAnswerRequest,
    principal: Annotated[Principal, Depends(get_current_principal)],
    runner: Annotated[RagAnswerRunner, Depends(get_rag_answer_runner)],
) -> RagAnswerResponse:
    outcome = await runner.answer(
        principal=principal,
        query=request.query,
        limit=request.limit,
    )
    return to_public_response(outcome)


@app.post("/v1/memory/notes", response_model=MemoryRecord)
def remember_note(
    request: RememberNote,
    principal: Annotated[Principal, Depends(get_current_principal)],
    memory: Annotated[DefaultMemoryContextService, Depends(get_memory_context_service)],
) -> MemoryRecord:
    return memory.remember(principal=principal, content=request.content)


@app.get("/v1/memory/notes", response_model=list[MemoryRecord])
def list_memory_notes(
    principal: Annotated[Principal, Depends(get_current_principal)],
    memory: Annotated[DefaultMemoryContextService, Depends(get_memory_context_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[MemoryRecord]:
    return memory.recall(principal=principal, limit=limit)


@app.post("/v1/agent/run", response_model=AgentRunResponse)
async def run_agent(
    request: AgentRunRequest,
    principal: Annotated[Principal, Depends(get_current_principal)],
    agent: Annotated[AgentRunner, Depends(get_agent_runner)],
) -> AgentRunResponse:
    try:
        return await agent.run(principal=principal, message=request.message)
    except BudgetExceeded as exc:
        status_code = (
            status.HTTP_413_CONTENT_TOO_LARGE
            if exc.dimension in {BudgetDimension.INPUT_BYTES, BudgetDimension.CONTEXT_BYTES}
            else status.HTTP_429_TOO_MANY_REQUESTS
        )
        raise HTTPException(
            status_code=status_code,
            detail="Agent execution resource budget exceeded",
        ) from exc
    except ToolGatewayError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tool request rejected by the server-side gateway",
        ) from exc


@app.post(
    "/v1/approvals/{approval_id}/decision",
    response_model=AgentRunResponse,
)
async def decide_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    principal: Annotated[Principal, Depends(get_current_principal)],
    agent: Annotated[AgentRunner, Depends(get_agent_runner)],
) -> AgentRunResponse:
    try:
        return await agent.review_and_resume(
            approval_id=approval_id,
            approver=principal,
            decision=request.decision,
        )
    except ApprovalError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approval decision rejected by server-side policy",
        ) from exc
