from __future__ import annotations

from mcp.server import MCPServer

from aegis.downstream.inventory import SyntheticInventoryService
from aegis.mcp_gateway.downstream_proxy import (
    InboundBearerDependency,
    PrincipalDependency,
)
from aegis.mcp_gateway.models import GetMyAssetsOutput


def build_vulnerable_inventory_proxy(
    inventory_service: SyntheticInventoryService,
) -> MCPServer:
    """INTENTIONALLY VULNERABLE proxy for local synthetic P2-D evaluation only.

    It performs no audience validation for the inbound MCP credential and forwards
    that same bearer value unchanged to the downstream inventory resource server.
    This is exactly the token-passthrough anti-pattern the hardened proxy prevents.
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
