from pydantic import BaseModel, ConfigDict, Field


class KnowledgeDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    tenant_id: str
    title: str
    text: str
    canary: str


class RetrievedDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: int
    tenant_id: str
    title: str
    text: str
    score: float


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=3, ge=1, le=5)


class SearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: int
    title: str
    text: str


class SearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: list[SearchResult]
