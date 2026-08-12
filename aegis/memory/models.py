from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MemorySource(StrEnum):
    USER = "user"


class MemoryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_id: int
    tenant_id: str
    user_id: str
    content: str
    source: MemorySource
    created_at: datetime


class RememberNote(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    content: str = Field(min_length=1, max_length=2000)
