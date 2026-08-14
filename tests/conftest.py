import pytest
from fastapi.testclient import TestClient

from apps.api.dependencies import (
    get_agent_checkpointer,
    get_agent_runner,
    get_approval_store,
    get_approval_workflow_store,
    get_approved_effect_pipeline,
    get_asset_store,
    get_checkpoint_backup_manager,
    get_checkpoint_key_provider,
    get_checkpoint_trust_provider_factory,
    get_default_high_impact_stack,
    get_effect_outbox_store,
    get_knowledge_store,
    get_memory_context_service,
    get_memory_store,
    get_rag_answer_runner,
    get_security_event_sink,
    get_security_telemetry_recorder,
    get_synthetic_effect_service,
    get_ticket_store,
    get_tool_gateway,
)
from apps.api.main import app


_CACHED_DEPENDENCIES = (
    get_rag_answer_runner,
    get_agent_runner,
    get_checkpoint_backup_manager,
    get_agent_checkpointer,
    get_checkpoint_key_provider,
    get_checkpoint_trust_provider_factory,
    get_memory_context_service,
    get_memory_store,
    get_approved_effect_pipeline,
    get_synthetic_effect_service,
    get_default_high_impact_stack,
    get_effect_outbox_store,
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
    monkeypatch.setenv("AEGISDESK_EFFECT_DB", str(tmp_path / "synthetic-effects.sqlite3"))
    monkeypatch.setenv("AEGISDESK_MEMORY_DB", str(tmp_path / "memory.sqlite3"))
    monkeypatch.setenv(
        "AEGISDESK_AGENT_CHECKPOINT_DB",
        str(tmp_path / "agent-checkpoints.sqlite3"),
    )
    monkeypatch.setenv(
        "AEGISDESK_AGENT_CHECKPOINT_ANCHOR_DB",
        str(tmp_path / "agent-checkpoint-anchor.sqlite3"),
    )
    for dependency in _CACHED_DEPENDENCIES:
        dependency.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    for dependency in _CACHED_DEPENDENCIES:
        dependency.cache_clear()