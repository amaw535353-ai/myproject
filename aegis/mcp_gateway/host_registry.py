from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from mcp import Client
from mcp.server import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.models import ToolCallProposal, ToolName


class ServerTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class McpHostPolicyError(RuntimeError):
    """Raised when host-owned server/tool policy rejects a model proposal."""


@dataclass(frozen=True)
class McpServerRegistration:
    """Host-assigned server identity.

    `server_id` is configured by the host. It is not derived from serverInfo.name,
    tool descriptions, annotations, or any other server-controlled metadata.
    """

    server_id: str
    server: MCPServer
    trust: ServerTrust


@dataclass(frozen=True)
class DiscoveredMcpTool:
    server_id: str
    trust: ServerTrust
    name: str
    description: str
    input_schema: dict[str, Any]


class HostToolProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any]


@dataclass(frozen=True)
class HostDispatchResult:
    server_id: str
    tool_name: str
    structured_content: dict[str, Any]


async def discover_mcp_tools(
    registrations: Sequence[McpServerRegistration],
) -> tuple[DiscoveredMcpTool, ...]:
    """Discover tools while preserving the host-assigned server identity."""

    discovered: list[DiscoveredMcpTool] = []
    for registration in registrations:
        async with Client(registration.server) as client:
            result = await client.list_tools()
        for tool in result.tools:
            discovered.append(
                DiscoveredMcpTool(
                    server_id=registration.server_id,
                    trust=registration.trust,
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=dict(tool.input_schema),
                )
            )
    return tuple(discovered)


class TrustedMcpHost:
    """Hardened MCP host using immutable host-owned server/tool bindings.

    A model proposes only a bare tool name and arguments. The host decides which
    registered server, if any, is authoritative for that name. Discovery order,
    duplicate names, descriptions, and annotations cannot replace the binding.
    """

    def __init__(
        self,
        *,
        gateway: ToolGateway,
        registrations: Sequence[McpServerRegistration],
        trusted_bindings: Mapping[str, str],
    ) -> None:
        by_id = {registration.server_id: registration for registration in registrations}
        if len(by_id) != len(registrations):
            raise ValueError("duplicate host-assigned MCP server_id")

        bindings = dict(trusted_bindings)
        for tool_name, server_id in bindings.items():
            registration = by_id.get(server_id)
            if registration is None:
                raise ValueError(f"trusted binding references unknown server {server_id}")
            if registration.trust is not ServerTrust.TRUSTED:
                raise ValueError(f"trusted binding references untrusted server {server_id}")
            if registration.server is not gateway.server:
                raise ValueError(
                    "P2-C trusted bindings must target the server owned by ToolGateway"
                )
            try:
                ToolName(tool_name)
            except ValueError as exc:
                raise ValueError(f"unsupported trusted tool binding {tool_name}") from exc

        self._gateway = gateway
        self._registrations = MappingProxyType(by_id)
        self._trusted_bindings = MappingProxyType(bindings)

    @property
    def policy_version(self) -> str:
        return "host-server-tool-binding-v1"

    async def dispatch(
        self,
        *,
        principal: Principal,
        proposal: HostToolProposal,
    ) -> HostDispatchResult:
        server_id = self._trusted_bindings.get(proposal.name)
        if server_id is None:
            raise McpHostPolicyError(
                f"tool {proposal.name} has no trusted host binding"
            )

        registration = self._registrations[server_id]
        if registration.trust is not ServerTrust.TRUSTED:
            raise McpHostPolicyError("trusted binding no longer points to a trusted server")
        if registration.server is not self._gateway.server:
            raise McpHostPolicyError("trusted server identity mismatch")

        try:
            tool_name = ToolName(proposal.name)
        except ValueError as exc:
            raise McpHostPolicyError("proposal is not a registered AegisDesk tool") from exc

        result = await self._gateway.dispatch(
            principal=principal,
            proposal=ToolCallProposal(name=tool_name, arguments=proposal.arguments),
        )
        return HostDispatchResult(
            server_id=server_id,
            tool_name=proposal.name,
            structured_content=result,
        )
