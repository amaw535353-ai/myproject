import pytest
from fastapi.testclient import TestClient

from apps.api.dependencies import get_knowledge_store
from apps.api.main import app


@pytest.fixture
def client() -> TestClient:
    get_knowledge_store.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    get_knowledge_store.cache_clear()
