from aegis.agent.fake_model import DeterministicFakeModel
from aegis.mcp_gateway.models import ToolName


def test_fake_model_routes_deterministically_without_identity_input() -> None:
    model = DeterministicFakeModel()

    assets = model.propose("assets")
    ticket = model.propose("ticket: VPN problem | Cannot connect")
    search = model.propose("search: vpn setup")

    assert assets.name is ToolName.GET_MY_ASSETS
    assert assets.arguments == {}
    assert ticket.name is ToolName.CREATE_TICKET
    assert ticket.arguments["title"] == "VPN problem"
    assert search.name is ToolName.SEARCH_KNOWLEDGE_BASE
    assert search.arguments == {"query": "vpn setup", "limit": 3}
