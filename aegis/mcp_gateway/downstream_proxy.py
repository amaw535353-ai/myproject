from __future__ import annotations

from typing import Annotated, Any

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver import Resolve

from aegis.downstream.auth import validate_mcp_inbound_token
from aegis.downstream.credential_broker import InventoryCredentialBroker
from aegis.downstream.inventory import SyntheticInventoryService
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import GetMyAssetsOutput
from aegis.mcp_gateway.security_context import (
    bind_principal,
    require_bound_principal,
    reset_principal,
)


class InventoryProxyError(RuntimeError):
    """Generic public error for the synthetic MCP -> downstream proxy boundary."""


PrincipalDependency = Annotated[Principal, Resolve(require_bound_principal)]


def build_hardened_inventory_proxy(
    inventory_service: SyntheticInventoryService,
) -> MCPServer:
    """Build a proxy whose MCP tool never receives the caller bearer credential."""

    broker = InventoryCredentialBroker(inventory_service)
    mcp = MCPServer("AegisDesk Hardened Inventory Proxy")

    @mcp.tool()
    def get_my_assets(principal: PrincipalDependency) -> GetMyAssetsOutput:
        # The raw inbound bearer was already validated and discarded by the gateway.
        # This tool receives only trusted identity and cannot accidentally forward the
        # caller's credential to the downstream resource server.
        assets = broker.get_my_assets(principal=principal)
        return GetMyAssetsOutput(assets=assets)

    return mcp


class InventoryProxyGateway:
    """Validate MCP authentication before entering the tool execution boundary."""

    def __init__(self, server: MCPServer) -> None:
        self.server = server

    async def get_my_assets(
        self,
        *,
        principal: Principal,
        inbound_bearer: str,
    ) -> dict[str, Any]:
        try:
            # The raw bearer exists only at this authentication boundary. Validation
            # yields no model/tool-controlled authorization state, and the bearer is
            # not placed in ContextVar state or passed to the MCP server.
            validate_mcp_inbound_token(inbound_bearer, principal=principal)
        except Exception as exc:
            raise InventoryProxyError("inventory proxy request rejected") from exc

        principal_token = bind_principal(principal)
        try:
            async with Client(self.server) as client:
                result = await client.call_tool("get_my_assets", {})
        finally:
            reset_principal(principal_token)

        if result.is_error or result.structured_content is None:
            raise InventoryProxyError("inventory proxy request rejected")
        return dict(result.structured_content)
