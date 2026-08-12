from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.mcp_gateway.models import ToolName


class AgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=2000)


class AgentRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: ToolName
    result: dict[str, Any]
    tool_calls: int
