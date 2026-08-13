import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Header, HTTPException, status

from aegis.agent.fake_model import DeterministicFakeModel
from aegis.agent.graph import AgentRunner
from aegis.agent.rag_model import DeterministicRagSecurityModel
from aegis.approvals.durable import DurableApprovalStore, DurableWorkflowStore
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.models import Principal
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.observability.security_events import (
    P2H_SYNTHETIC_KEY_ID,
    InMemorySecurityEventSink,
    SecurityTelemetryRecorder,
    TelemetryPseudonymizer,
)
from aegis.policy.tool_capabilities import READ_ONLY_RAG_POLICY
from aegis.rag.answering import RagAnswerRunner
from aegis.rag.store import KnowledgeStore


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_KNOWLEDGE_PATH = _REPOSITORY_ROOT / "synthetic_data" / "knowledge.json"
_ASSETS_PATH = _REPOSITORY_ROOT / "synthetic_data" / "assets.json"

# Local synthetic lab key only. Production must load telemetry pseudonymization
# material from a secret manager or equivalent protected configuration.
_SYNTHETIC_TELEMETRY_HMAC_KEY = (
    b"aegisdesk-local-synthetic-telemetry-hmac-key-v1-2026"
)


def _state_database_path() -> Path:
    configured = os.getenv("AEGISDESK_STATE_DB")
    if configured:
        return Path(configured)
    return _REPOSITORY_ROOT / ".aegisdesk" / "state.sqlite3"


async def get_current_principal(
    x_aegis_user: Annotated[str | None, Header(alias="X-Aegis-User")] = None,
) -> Principal:
    if not x_aegis_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing synthetic authentication handle",
        )

    principal = resolve_synthetic_principal(x_aegis_user)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown synthetic authentication handle",
        )
    return principal


@lru_cache(maxsize=1)
def get_knowledge_store() -> KnowledgeStore:
    return KnowledgeStore.from_json(_KNOWLEDGE_PATH)


@lru_cache(maxsize=1)
def get_asset_store() -> AssetStore:
    return AssetStore.from_json(_ASSETS_PATH)


@lru_cache(maxsize=1)
def get_ticket_store() -> TicketStore:
    return TicketStore()


@lru_cache(maxsize=1)
def get_approval_store() -> DurableApprovalStore:
    return DurableApprovalStore(_state_database_path())


@lru_cache(maxsize=1)
def get_approval_workflow_store() -> DurableWorkflowStore:
    return DurableWorkflowStore(_state_database_path())


@lru_cache(maxsize=1)
def get_tool_gateway() -> ToolGateway:
    return ToolGateway(
        knowledge_store=get_knowledge_store(),
        asset_store=get_asset_store(),
        ticket_store=get_ticket_store(),
        approval_store=get_approval_store(),
    )


@lru_cache(maxsize=1)
def get_security_event_sink() -> InMemorySecurityEventSink:
    return InMemorySecurityEventSink()


@lru_cache(maxsize=1)
def get_security_telemetry_recorder() -> SecurityTelemetryRecorder:
    return SecurityTelemetryRecorder(
        sink=get_security_event_sink(),
        pseudonymizer=TelemetryPseudonymizer(
            key=_SYNTHETIC_TELEMETRY_HMAC_KEY,
            key_id=P2H_SYNTHETIC_KEY_ID,
        ),
    )


@lru_cache(maxsize=1)
def get_agent_runner() -> AgentRunner:
    return AgentRunner(
        model=DeterministicFakeModel(),
        gateway=get_tool_gateway(),
        approval_store=get_approval_store(),
        telemetry=get_security_telemetry_recorder(),
        workflow_store=get_approval_workflow_store(),
    )


@lru_cache(maxsize=1)
def get_rag_answer_runner() -> RagAnswerRunner:
    return RagAnswerRunner(
        knowledge_store=get_knowledge_store(),
        model=DeterministicRagSecurityModel(),
        gateway=get_tool_gateway(),
        capability_policy=READ_ONLY_RAG_POLICY,
    )
