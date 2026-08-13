from fastapi.testclient import TestClient

from apps.api.dependencies import (
    get_agent_runner,
    get_approval_store,
    get_approval_workflow_store,
    get_approved_effect_pipeline,
    get_effect_outbox_store,
    get_synthetic_effect_service,
    get_tool_gateway,
)


ALICE = {"X-Aegis-User": "alice@northstar-dynamics.test"}
CAROL = {"X-Aegis-User": "carol.approver@northstar-dynamics.test"}


def _restart_stateful_dependencies() -> None:
    get_agent_runner.cache_clear()
    get_approved_effect_pipeline.cache_clear()
    get_synthetic_effect_service.cache_clear()
    get_effect_outbox_store.cache_clear()
    get_tool_gateway.cache_clear()
    get_approval_workflow_store.cache_clear()
    get_approval_store.cache_clear()


def test_http_approval_survives_dependency_restart_and_replay_is_rejected(
    client: TestClient,
) -> None:
    started = client.post(
        "/v1/agent/run",
        headers=ALICE,
        json={"message": "access: finance-read | HTTP restart test"},
    )
    assert started.status_code == 200
    approval_id = str(started.json()["approval_id"])

    _restart_stateful_dependencies()
    resumed = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )
    assert resumed.status_code == 200
    assert resumed.json()["result"]["status"] == "consumed"
    assert get_effect_outbox_store().get(approval_id).status == "completed"
    assert get_synthetic_effect_service().count_effects(approval_id) == 1

    _restart_stateful_dependencies()
    replay = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=CAROL,
        json={"decision": "approve"},
    )
    assert replay.status_code == 403
    assert get_synthetic_effect_service().count_effects(approval_id) == 1
