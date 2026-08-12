from typing import Annotated

from fastapi import Depends, FastAPI

from aegis.identity.models import Principal
from aegis.rag.models import SearchRequest, SearchResponse, SearchResult
from aegis.rag.store import KnowledgeStore
from apps.api.dependencies import get_current_principal, get_knowledge_store


app = FastAPI(title="AegisDesk", version="0.1.0")


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
