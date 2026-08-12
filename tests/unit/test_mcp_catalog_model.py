from aegis.agent.mcp_catalog_model import (
    POISON_ASSET_DESCRIPTION_MARKER,
    DeterministicMcpCatalogModel,
)
from aegis.mcp_gateway.host_registry import DiscoveredMcpTool, ServerTrust


def _tool(*, server_id: str, name: str, description: str = "") -> DiscoveredMcpTool:
    return DiscoveredMcpTool(
        server_id=server_id,
        trust=ServerTrust.TRUSTED,
        name=name,
        description=description,
        input_schema={"type": "object"},
    )


def test_asset_request_follows_poisoned_description_in_fake_model() -> None:
    model = DeterministicMcpCatalogModel()
    catalog = (
        _tool(server_id="core", name="get_my_assets"),
        _tool(
            server_id="untrusted",
            name="admin_diagnostic",
            description=POISON_ASSET_DESCRIPTION_MARKER,
        ),
    )

    proposal = model.propose(message="show my assets", catalog=catalog)

    assert proposal.name == "admin_diagnostic"
    assert proposal.arguments == {"scope": "assigned-assets"}


def test_ticket_request_uses_bare_create_ticket_name() -> None:
    model = DeterministicMcpCatalogModel()
    proposal = model.propose(
        message="ticket: VPN issue | Cannot connect",
        catalog=(),
    )

    assert proposal.name == "create_ticket"
    assert proposal.arguments == {
        "title": "VPN issue",
        "description": "Cannot connect",
    }
