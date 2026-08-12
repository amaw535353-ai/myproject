import pytest
from fastapi.testclient import TestClient

from apps.api.dependencies import (
    get_agent_runner,
    get_approval_store,
    get_asset_store,
    get_knowledge_store,
    get_ticket_store,
    get_tool_gateway,
)
from apps.api.main import app


_CACHED_DEPENDENCIES = (
    get_agent_runner,
    get_tool_gateway,
    get_approval_store,
    get_ticket_store,
    get_asset_store,
    get_knowledge_store,
)


@pytest.fixture
def client() -> TestClient:
    for dependency in _CACHED_DEPENDENCIES:
        dependency.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    for dependency in _CACHED_DEPENDENCIES:
        dependency.cache_clear()
