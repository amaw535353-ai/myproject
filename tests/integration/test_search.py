from fastapi.testclient import TestClient


DYNAMICS_USER = {"X-Aegis-User": "alice@northstar-dynamics.test"}


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_authorized_search_returns_same_tenant_document(client: TestClient) -> None:
    response = client.post(
        "/v1/knowledge/search",
        headers=DYNAMICS_USER,
        json={"query": "vpn setup", "limit": 3},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["results"]
    rendered = str(body)
    assert "Northstar Dynamics" in rendered
    assert "AEGIS-DIGITAL-9K2X" not in rendered
