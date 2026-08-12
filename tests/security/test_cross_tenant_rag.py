from fastapi.testclient import TestClient

from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.rag.models import KnowledgeDocument
from aegis.rag.store import KnowledgeStore


DYNAMICS_USER = {"X-Aegis-User": "alice@northstar-dynamics.test"}
DIGITAL_USER = {"X-Aegis-User": "bob@northstar-digital.test"}


def test_store_enforces_principal_tenant_filter() -> None:
    documents = [
        KnowledgeDocument(id=1, tenant_id="tenant_a", title="VPN", text="shared vpn text A-CANARY", canary="A-CANARY"),
        KnowledgeDocument(id=2, tenant_id="tenant_b", title="VPN", text="shared vpn text B-CANARY", canary="B-CANARY"),
    ]
    store = KnowledgeStore(documents)
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None
    principal = principal.model_copy(update={"tenant_id": "tenant_a"})

    results = store.search(principal=principal, query="vpn", limit=5)

    assert results
    assert {result.tenant_id for result in results} == {"tenant_a"}
    assert all("B-CANARY" not in result.text for result in results)


def test_cross_tenant_canaries_never_cross_api_boundary(client: TestClient) -> None:
    dynamics = client.post(
        "/v1/knowledge/search",
        headers=DYNAMICS_USER,
        json={"query": "vpn password reset", "limit": 5},
    )
    digital = client.post(
        "/v1/knowledge/search",
        headers=DIGITAL_USER,
        json={"query": "vpn password reset", "limit": 5},
    )

    assert dynamics.status_code == 200
    assert digital.status_code == 200
    assert "AEGIS-DIGITAL-9K2X" not in dynamics.text
    assert "AEGIS-NORTH-7Q4M" not in digital.text
