import pytest
from fastapi.testclient import TestClient

from aegis.effects.control_plane_recovery import ControlPlaneConvergenceError
from apps.api.dependencies import get_default_high_impact_stack, get_effect_outbox_store

ALICE = {"X-Aegis-User": "alice@northstar-dynamics.test"}
CAROL = {"X-Aegis-User": "carol.approver@northstar-dynamics.test"}


def _request_access(client: TestClient) -> str:
    response = client.post(
        "/v1/agent/run",
        headers=ALICE,
        json={"message": "access: synthetic-vpn | P3-A default security chain"},
    )
    assert response.status_code == 200
    approval_id = response.json()["approval_id"]
    assert approval_id
    return approval_id


def test_default_api_uses_authenticated_high_impact_chain(client: TestClient) -> None:
    approval_id = _request_access(client)
    reviewed = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["result"]["status"] == "consumed"
    stack = get_default_high_impact_stack()
    assert stack.policy_version == "default-authenticated-high-impact-chain-v1"
    assert stack.checkpoint_fence.current_active_generation() == 1
    assert stack.effect_service.count_effects(approval_id) == 1
    assert get_effect_outbox_store().get(approval_id).status == "completed"


def test_default_api_fails_closed_when_control_plane_is_not_converged(client: TestClient) -> None:
    approval_id = _request_access(client)
    stack = get_default_high_impact_stack()
    stack.generation_store.advance(
        authority_id=stack.local_control_plane.authority_id,
        expected_current=1,
    )
    with pytest.raises(ControlPlaneConvergenceError):
        client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=CAROL,
            json={"decision": "approve"},
        )
    assert stack.effect_service.count_effects(approval_id) == 0
