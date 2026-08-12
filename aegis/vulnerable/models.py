from pydantic import BaseModel, ConfigDict, Field


class UnfilteredSearchRequest(BaseModel):
    """INTENTIONALLY VULNERABLE lab request: retrieval has no tenant selector."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=3, ge=1, le=5)


class ClientTenantSearchRequest(BaseModel):
    """INTENTIONALLY VULNERABLE lab request: the client chooses tenant scope."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)
    tenant_id: str = Field(min_length=1, max_length=120)
    limit: int = Field(default=3, ge=1, le=5)
