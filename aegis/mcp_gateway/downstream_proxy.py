from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Annotated, Any

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver import Resolve

from aegis.downstream.auth import (
    INVENTORY_SERVICE_TOKEN,
    validate_mcp_inbound_token,
)
from aegis.downstream.inventory import SyntheticInventoryService
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import GetMyAssetsOutput
from aegis.mcp_gateway.security_context import (
    bind_principal,
    require_bound_principal,
    reset_principal,
)


_BOUND_INBOUND_BEARER: ContextVar[str | None] = ContextVar(
    "aegis_bound_inbound_bearer", default=None
)


class InventoryProxyError(RuntimeError):
    """Generic public error for the synthetic MCP -> downstream proxy boundary."""


def bind_inbound_bearer(bearer: str) -> Token[str | None]:
    return _BOUND_INBOUND_BEARER.set(bearer)


def reset_inbound_bearer(token: Token[str | None]) -> None:
    _BOUND_INBOUND_BEARER.reset(token)


def require_inbound_bearer() -> str:
    bearer = _BOUND_INBOUND_BEARER.get()
    if bearer is None:
        raise RuntimeError("trusted inbound credential context is not bound")
    return bearer


PrincipalDependency = Annotated[Principal, Resolve(require_bound_principal)]
InboundBearerDependency = Annotated[str, Resolve(require_inbound_bearer)]


def build_hardened_inventory_proxy(
    inventory_service: SyntheticInventoryService,
) -> MCPServer:
    """Build a proxy that validates MCP audience then uses its own downstream token."""

    mcp = MCPServer("AegisDesk Hardened Inventory Proxy")

    @mcp.tool()
    def get_my_assets(
        principal: PrincipalDependency,
        inbound_bearer: InboundBearerDependency,
    ) -> GetMyAssetsOutput:
        # Inbound identity is validated for the MCP resource boundary.
        validate_mcp_inbound_token(inbound_bearer, principal=principal)

        # Crucial invariant: the caller token is never forwarded downstream.
        # The proxy uses a separately scoped service credential for inventory:read.
        assets = inventory_service.get_my_assets(
            authorization_bearer=INVENTORY_SERVICE_TOKEN,
            principal=principal,
        )
        return GetMyAssetsOutput(assets=assets)

    return mcp


class InventoryProxyGateway:
    """Bind trusted request context outside the model-visible MCP tool arguments."""

    def __init__(self, server: MCPServer) -> None:
        self.server = server

    async def get_my_assets(
        self,
        *,
        principal: Principal,
        inbound_bearer: str,
    ) -> dict[str, Any]:
        principal_token = bind_principal(principal)
        bearer_token = bind_inbound_bearer(inbound_bearer)
        try:
            # Context is bound before Client(server) creates server-side tasks so
            # Resolve dependencies inherit trusted request-local state.
            async with Client(self.server) as client:
                result = await client.call_tool("get_my_assets", {})
        finally:
            reset_inbound_bearer(bearer_token)
            reset_principal(principal_token)

        if result.is_error or result.structured_content is None:
            raise InventoryProxyError("inventory proxy request rejected")
        return dict(result.structured_content)
