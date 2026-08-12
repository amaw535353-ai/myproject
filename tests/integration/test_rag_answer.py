from fastapi.testclient import TestClient


DYNAMICS_USER = {"X-Aegis-User": "alice@northstar-dynamics.test"}


def test_hardened_rag_answer_is_read_only(client: TestClient) -> None:
    response = client.post(
        "/v1/rag/answer",
        headers=DYNAMICS_USER,
        json={"query": "vpn setup", "limit": 1},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["answer"]
    assert body["retrieved_document_ids"]
    assert body["proposed_tool"] is None
    assert body["tool_status"] == "none"


def test_hardened_app_does_not_mount_vulnerable_poison_route(client: TestClient) -> None:
    response = client.post(
        "/v1/rag/answer-poisonable",
        headers=DYNAMICS_USER,
        json={"query": "orchid orchid orchid diagnostic", "limit": 1},
    )
    assert response.status_code == 404
