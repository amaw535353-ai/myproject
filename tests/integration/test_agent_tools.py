from fastapi.testclient import TestClient


DYNAMICS_USER = {"X-Aegis-User": "alice@northstar-dynamics.test"}


def test_agent_search_preserves_tenant_isolation(client: TestClient) -> None:
    response = client.post(
        "/v1/agent/run",
        headers=DYNAMICS_USER,
        json={"message": "search: vpn setup"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["tool"] == "search_knowledge_base"
    assert body["tool_calls"] == 1
    assert "AEGIS-NORTH-7Q4M" in response.text
    assert "AEGIS-DIGITAL-9K2X" not in response.text


def test_agent_get_my_assets_is_principal_scoped(client: TestClient) -> None:
    response = client.post(
        "/v1/agent/run",
        headers=DYNAMICS_USER,
        json={"message": "assets"},
    )

    assert response.status_code == 200
    assert "NSD-LAPTOP-001" in response.text
    assert "NSD-PHONE-001" in response.text
    assert "NSDIG-LAPTOP-001" not in response.text


def test_agent_create_ticket_uses_low_impact_tool(client: TestClient) -> None:
    response = client.post(
        "/v1/agent/run",
        headers=DYNAMICS_USER,
        json={"message": "ticket: VPN issue | Synthetic VPN is unavailable"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["tool"] == "create_ticket"
    assert body["tool_calls"] == 1
    assert body["result"]["status"] == "created"
    assert body["result"]["ticket_id"].startswith("TCK-")
