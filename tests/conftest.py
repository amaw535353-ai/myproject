import pytest
from fastapi.testclient import TestClient

from apps.api.dependencies import (
    get_agent_runner,
    get_approval_store,
    get_approval_workflow_store,
    get_asset_store,
    get_knowledge_store,
    get_rag_answer_runner,
    get_security_event_sink,
    get_security_telemetry_recorder,
    get_ticket_store,
    get_tool_gateway,
)
from apps.api.main import app


_CACHED_DEPENDENCIES = (
    get_rag_answer_runner,
    get_agent_runner,
    get_security_telemetry_recorder,
    get_security_event_sink,
    get_tool_gateway,
    get_approval_workflow_store,
    get_approval_store,
    get_ticket_store,
    get_asset_store,
    get_knowledge_store,
)


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("AEGISDESK_STATE_DB", str(tmp_path / "state.sqlite3"))
    for dependency in _CACHED_DEPENDENCIES:
        dependency.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    for dependency in _CACHED_DEPENDENCIES:
        dependency.cache_clear()
