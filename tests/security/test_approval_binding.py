from fastapi.testclient import TestClient


ALICE = {"X-Aegis-User": "alice@northstar-dynamics.test"}
CAROL = {"X-Aegis-User": "carol.approver@northstar-dynamics.test"}
BOB = {"X-Aegis-User": "bob@northstar-digital.test"}
DAVE = {"X-Aegis-User": "dave.approver@northstar-digital.test"}


def _start_access_request(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/v1/agent/run",
        headers=headers,
        json={"message": "access: finance-read | Security regression test"},
    )
    assert response.status_code == 200
    approval_id = response.json()["approval_id"]
    assert approval_id
    return str(approval_id)


def test_requester_cannot_self_approve(client: TestClient) -> None:
    approval_id = _start_access_request(client, CAROL)

    response = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )

    assert response.status_code == 403


def test_non_approver_cannot_approve(client: TestClient) -> None:
    approval_id = _start_access_request(client, ALICE)

    denied = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=ALICE,
        json={"decision": "approve"},
    )
    assert denied.status_code == 403

    accepted = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )
    assert accepted.status_code == 200


def test_cross_tenant_approver_cannot_approve(client: TestClient) -> None:
    approval_id = _start_access_request(client, ALICE)

    denied = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=DAVE,
        json={"decision": "approve"},
    )
    assert denied.status_code == 403

    accepted = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )
    assert accepted.status_code == 200


def test_consumed_approval_cannot_be_replayed(client: TestClient) -> None:
    approval_id = _start_access_request(client, ALICE)

    first = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )
    second = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )

    assert first.status_code == 200
    assert first.json()["result"]["status"] == "consumed"
    assert second.status_code == 403


def test_other_tenant_request_does_not_make_approval_transferable(
    client: TestClient,
) -> None:
    approval_id = _start_access_request(client, BOB)

    response = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )

    assert response.status_code == 403
