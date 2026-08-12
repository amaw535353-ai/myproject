from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.helpdesk.models import AssetView
from aegis.rag.models import SearchResult


class ToolName(StrEnum):
    SEARCH_KNOWLEDGE_BASE = "search_knowledge_base"
    GET_MY_ASSETS = "get_my_assets"
    CREATE_TICKET = "create_ticket"


class ToolCallProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: ToolName
    arguments: dict[str, Any]


class SearchKnowledgeBaseArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=3, ge=1, le=5)


class GetMyAssetsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateTicketArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=2000)


class SearchKnowledgeBaseOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: list[SearchResult]


class GetMyAssetsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[AssetView]


class CreateTicketOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket_id: str
    status: str
    title: str
