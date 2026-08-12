from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Annotated, Any

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver import Resolve

from aegis.downstream.inventory import SyntheticInventoryService
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import GetMyAssetsOutput
from aegis.mcp_gateway.security_context import (
    bind_principal,
    require_bound_principal,
    reset_principal,
)


_VULNERABLE_BOUND_BEARER: ContextVar[str | None] = ContextVar(
    "aegis_vulnerable_bound_bearer", default=None
)


class VulnerableInventoryProxyError(RuntimeError):
    pass


def _bind_vulnerable_bearer(bearer: str) -> Token[str | None]:
    return _VULNERABLE_BOUND_BEARER.set(bearer)


def _reset_vulnerable_bearer(token: Token[str | None]) -> None:
    _VULNERABLE_BOUND_BEARER.reset(token)


def _require_vulnerable_bearer() -> str:
    bearer = _VULNERABLE_BOUND_BEARER.get()
    if bearer is None:
        raise RuntimeError("vulnerable bearer context is not bound")
    return bearer


PrincipalDependency = Annotated[Principal, Resolve(require_bound_principal)]
InboundBearerDependency = Annotated[str, Resolve(_require_vulnerable_bearer)]


def build_vulnerable_inventory_proxy(
    inventory_service: SyntheticInventoryService,
) -> MCPServer:
    """INTENTIONALLY VULNERABLE proxy for local synthetic P2-D evaluation only.

    It performs no audience validation for the inbound MCP credential and forwards
    that same bearer value unchanged to the downstream inventory resource server.
    This vulnerable bearer context is defined only in this lab module and is not
    imported by the hardened proxy.
    """

    mcp = MCPServer("AegisDesk INTENTIONALLY VULNERABLE Inventory Proxy")

    @mcp.tool()
    def get_my_assets(
        principal: PrincipalDependency,
        inbound_bearer: InboundBearerDependency,
    ) -> GetMyAssetsOutput:
        # INTENTIONALLY VULNERABLE: accepts/transits a caller bearer without
        # validating that it was issued to the MCP server.
        assets = inventory_service.get_my_assets(
            authorization_bearer=inbound_bearer,
            principal=principal,
        )
        return GetMyAssetsOutput(assets=assets)

    return mcp


class VulnerableInventoryProxyGateway:
    """Lab-only gateway that deliberately carries the raw bearer into MCP context."""

    def __init__(self, server: MCPServer) -> None:
        self.server = server

    async def get_my_assets(
        self,
        *,
        principal: Principal,
        inbound_bearer: str,
    ) -> dict[str, Any]:
        principal_token = bind_principal(principal)
        bearer_token = _bind_vulnerable_bearer(inbound_bearer)
        try:
            async with Client(self.server) as client:
                result = await client.call_tool("get_my_assets", {})
        finally:
            _reset_vulnerable_bearer(bearer_token)
            reset_principal(principal_token)

        if result.is_error or result.structured_content is None:
            raise VulnerableInventoryProxyError("vulnerable inventory proxy failed")
        return dict(result.structured_content)
