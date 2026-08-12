from fastapi.testclient import TestClient


ALICE = {"X-Aegis-User": "alice@northstar-dynamics.test"}
CAROL = {"X-Aegis-User": "carol.approver@northstar-dynamics.test"}
BOB = {"X-Aegis-User": "bob@northstar-digital.test"}
DAVE = {"X-Aegis-User": "dave.approver@northstar-digital.test"}


def test_access_request_pauses_until_authorized_human_approval(
    client: TestClient,
) -> None:
    requested = client.post(
        "/v1/agent/run",
        headers=ALICE,
        json={
            "message": "access: finance-read | Need quarterly reporting access"
        },
    )

    assert requested.status_code == 200
    body = requested.json()
    assert body["tool"] == "request_access"
    assert body["status"] == "pending_approval"
    assert body["tool_calls"] == 1
    approval_id = body["approval_id"]
    assert approval_id
    assert body["result"]["status"] == "pending"

    reviewed = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )

    assert reviewed.status_code == 200
    reviewed_body = reviewed.json()
    assert reviewed_body["status"] == "approved"
    assert reviewed_body["result"]["status"] == "consumed"
    assert reviewed_body["tool_calls"] == 1


def test_password_reset_request_can_be_rejected_without_resetting_credentials(
    client: TestClient,
) -> None:
    requested = client.post(
        "/v1/agent/run",
        headers=BOB,
        json={"message": "password-reset: I forgot my synthetic password"},
    )
    approval_id = requested.json()["approval_id"]

    reviewed = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=DAVE,
        json={"decision": "reject"},
    )

    assert reviewed.status_code == 200
    body = reviewed.json()
    assert body["tool"] == "request_password_reset"
    assert body["status"] == "rejected"
    assert body["result"]["status"] == "rejected"
