from fastapi.testclient import TestClient

from apps.vulnerable_api.main import (
    create_intentionally_vulnerable_lab_app,
    get_vulnerable_knowledge_store,
)


DYNAMICS_USER = {"X-Aegis-User": "alice@northstar-dynamics.test"}
FOREIGN_CANARY = "AEGIS-DIGITAL-9K2X"


def test_vulnerable_unfiltered_retrieval_leaks_cross_tenant_canary() -> None:
    get_vulnerable_knowledge_store.cache_clear()
    try:
        with TestClient(create_intentionally_vulnerable_lab_app()) as client:
            response = client.post(
                "/v1/knowledge/search-unfiltered",
                headers=DYNAMICS_USER,
                json={"query": "vpn password reset", "limit": 5},
            )
        assert response.status_code == 200
        assert FOREIGN_CANARY in response.text
    finally:
        get_vulnerable_knowledge_store.cache_clear()


def test_vulnerable_client_tenant_substitution_leaks_foreign_canary() -> None:
    get_vulnerable_knowledge_store.cache_clear()
    try:
        with TestClient(create_intentionally_vulnerable_lab_app()) as client:
            response = client.post(
                "/v1/knowledge/search-client-tenant",
                headers=DYNAMICS_USER,
                json={
                    "query": "vpn",
                    "tenant_id": "tenant_northstar_digital",
                    "limit": 5,
                },
            )
        assert response.status_code == 200
        assert FOREIGN_CANARY in response.text
    finally:
        get_vulnerable_knowledge_store.cache_clear()


def test_hardened_matched_query_never_leaks_foreign_canary(client: TestClient) -> None:
    response = client.post(
        "/v1/knowledge/search",
        headers=DYNAMICS_USER,
        json={"query": "vpn password reset", "limit": 5},
    )

    assert response.status_code == 200
    assert FOREIGN_CANARY not in response.text


def test_hardened_endpoint_rejects_client_tenant_substitution(client: TestClient) -> None:
    response = client.post(
        "/v1/knowledge/search",
        headers=DYNAMICS_USER,
        json={
            "query": "vpn",
            "tenant_id": "tenant_northstar_digital",
            "limit": 5,
        },
    )

    assert response.status_code == 422
    assert FOREIGN_CANARY not in response.text
