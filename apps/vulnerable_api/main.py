from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI

from aegis.identity.models import Principal
from aegis.rag.models import SearchResponse, SearchResult
from aegis.vulnerable.models import ClientTenantSearchRequest, UnfilteredSearchRequest
from aegis.vulnerable.rag import VulnerableKnowledgeStore
from apps.api.dependencies import get_current_principal


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_KNOWLEDGE_PATH = _REPOSITORY_ROOT / "synthetic_data" / "knowledge.json"


@lru_cache(maxsize=1)
def get_vulnerable_knowledge_store() -> VulnerableKnowledgeStore:
    return VulnerableKnowledgeStore.from_json(_KNOWLEDGE_PATH)


def _response(documents: list[object]) -> SearchResponse:
    return SearchResponse(
        results=[
            SearchResult(
                document_id=int(getattr(document, "document_id")),
                title=str(getattr(document, "title")),
                text=str(getattr(document, "text")),
            )
            for document in documents
        ]
    )


def create_intentionally_vulnerable_lab_app() -> FastAPI:
    """Build the isolated vulnerable app.

    There is deliberately no module-level ``app`` object. Launching this baseline
    therefore requires an explicit ``--factory`` target and cannot be enabled as a
    route or feature flag inside the hardened application.
    """

    app = FastAPI(
        title="AegisDesk INTENTIONALLY VULNERABLE Lab",
        version="0.4.0",
        description=(
            "Local synthetic security lab only. Do not expose this application to "
            "public or third-party networks."
        ),
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "intentionally-vulnerable-lab-only"}

    @app.post("/v1/knowledge/search-unfiltered", response_model=SearchResponse)
    def search_unfiltered(
        request: UnfilteredSearchRequest,
        _principal: Annotated[Principal, Depends(get_current_principal)],
        store: Annotated[
            VulnerableKnowledgeStore,
            Depends(get_vulnerable_knowledge_store),
        ],
    ) -> SearchResponse:
        # INTENTIONALLY VULNERABLE: authenticated identity is ignored for retrieval.
        return _response(store.search_unfiltered(query=request.query, limit=request.limit))

    @app.post("/v1/knowledge/search-client-tenant", response_model=SearchResponse)
    def search_client_tenant(
        request: ClientTenantSearchRequest,
        _principal: Annotated[Principal, Depends(get_current_principal)],
        store: Annotated[
            VulnerableKnowledgeStore,
            Depends(get_vulnerable_knowledge_store),
        ],
    ) -> SearchResponse:
        # INTENTIONALLY VULNERABLE: request.tenant_id is treated as authorization.
        return _response(
            store.search_by_client_tenant(
                query=request.query,
                tenant_id=request.tenant_id,
                limit=request.limit,
            )
        )

    return app
