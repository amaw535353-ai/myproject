import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Header, HTTPException, status

from aegis.agent.default_budgeted_runner import DefaultBudgetedAgentRunner
from aegis.agent.execution_budget import P2G_EXECUTION_LIMITS
from aegis.agent.fake_model import DeterministicFakeModel
from aegis.agent.rag_model import DeterministicRagSecurityModel
from aegis.approvals.durable import DurableApprovalStore, DurableWorkflowStore
from aegis.effects.default_high_impact import (
    DefaultHighImpactPaths,
    DefaultHighImpactSecurityStack,
    build_default_high_impact_security_stack,
)
from aegis.effects.durable import DurableApprovedEffectPipeline
from aegis.effects.revalidation import RevalidatingEffectOutboxStore, SyntheticAuthorizationStateStore
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.models import Principal, Role
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
_EXECUTION_AUTHORIZATION_PATH = _REPOSITORY_ROOT / "synthetic_data" / "p2m_authorization_state.json"
_AUTHORIZATION_VERSION_PATH = _REPOSITORY_ROOT / "synthetic_data" / "p2n_authorization_versions.json"
_AUTHORIZATION_KEY_PATH = _REPOSITORY_ROOT / "synthetic_data" / "p2o_authorization_keys.json"
_CONTROL_PLANE_PATH = _REPOSITORY_ROOT / "synthetic_data" / "p2p_control_plane_anchor.json"
_CHECKPOINT_RECEIPT_PATH = _REPOSITORY_ROOT / "synthetic_data" / "p2s_checkpoint_receipt_fixture.json"

_SYNTHETIC_TELEMETRY_HMAC_KEY = b"aegisdesk-local-synthetic-telemetry-hmac-key-v1-2026"


def _state_database_path() -> Path:
    configured = os.getenv("AEGISDESK_STATE_DB")
    if configured:
        return Path(configured)
    return _REPOSITORY_ROOT / ".aegisdesk" / "state.sqlite3"


def _effect_database_path() -> Path:
    configured = os.getenv("AEGISDESK_EFFECT_DB")
    if configured:
        return Path(configured)
    return _REPOSITORY_ROOT / ".aegisdesk" / "synthetic-effects.sqlite3"


def _security_database_path(env_name: str, default_name: str) -> Path:
    configured = os.getenv(env_name)
    if configured:
        return Path(configured)
    return _effect_database_path().with_name(default_name)


def _control_plane_database_path() -> Path:
    return _security_database_path("AEGISDESK_CONTROL_PLANE_DB", "control-plane.sqlite3")


def _protected_checkpoint_database_path() -> Path:
    return _security_database_path("AEGISDESK_PROTECTED_CHECKPOINT_DB", "protected-checkpoint.sqlite3")


def _receipt_witness_database_path() -> Path:
    return _security_database_path("AEGISDESK_RECEIPT_WITNESS_DB", "checkpoint-receipt-witness.sqlite3")


def _read_fixture(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_default_execution_authorization_state() -> SyntheticAuthorizationStateStore:
    store = SyntheticAuthorizationStateStore(_effect_database_path())
    fixture = _read_fixture(_EXECUTION_AUTHORIZATION_PATH)

    for subject in fixture["subjects"]:
        store.ensure_subject(
            user_id=subject["user_id"],
            tenant_id=subject["tenant_id"],
            active=subject["active"],
            roles=frozenset(Role(role) for role in subject["roles"]),
        )
    for resource in fixture["resources"]:
        required_role = resource["required_role"]
        store.ensure_resource(
            tenant_id=resource["tenant_id"],
            resource=resource["resource"],
            enabled=resource["enabled"],
            owner_user_id=resource["owner_user_id"],
            required_role=None if required_role is None else Role(required_role),
        )
    for policy in fixture["tenant_policies"]:
        store.ensure_password_reset_policy(
            tenant_id=policy["tenant_id"],
            enabled=policy["password_reset_enabled"],
        )
    return store


async def get_current_principal(
    x_aegis_user: Annotated[str | None, Header(alias="X-Aegis-User")] = None,
) -> Principal:
    if not x_aegis_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing synthetic authentication handle")
    principal = resolve_synthetic_principal(x_aegis_user)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown synthetic authentication handle")
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
def get_effect_outbox_store() -> RevalidatingEffectOutboxStore:
    return RevalidatingEffectOutboxStore(_state_database_path())


@lru_cache(maxsize=1)
def get_default_high_impact_stack() -> DefaultHighImpactSecurityStack:
    paths = DefaultHighImpactPaths(
        state_database_path=_state_database_path(),
        execution_database_path=_effect_database_path(),
        control_plane_database_path=_control_plane_database_path(),
        protected_checkpoint_database_path=_protected_checkpoint_database_path(),
        receipt_witness_database_path=_receipt_witness_database_path(),
    )
    return build_default_high_impact_security_stack(
        paths=paths,
        approval_store=get_approval_store(),
        outbox_store=get_effect_outbox_store(),
        authorization_store=_ensure_default_execution_authorization_state(),
        authorization_version_fixture=_read_fixture(_AUTHORIZATION_VERSION_PATH),
        authorization_key_fixture=_read_fixture(_AUTHORIZATION_KEY_PATH),
        control_plane_fixture=_read_fixture(_CONTROL_PLANE_PATH),
        checkpoint_receipt_fixture=_read_fixture(_CHECKPOINT_RECEIPT_PATH),
    )


@lru_cache(maxsize=1)
def get_synthetic_effect_service():
    """Compatibility getter; the default effect node is now the P3-A consolidated service."""
    return get_default_high_impact_stack().effect_service


@lru_cache(maxsize=1)
def get_approved_effect_pipeline() -> DurableApprovedEffectPipeline:
    return get_default_high_impact_stack().pipeline


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
        pseudonymizer=TelemetryPseudonymizer(key=_SYNTHETIC_TELEMETRY_HMAC_KEY, key_id=P2H_SYNTHETIC_KEY_ID),
    )


@lru_cache(maxsize=1)
def get_agent_runner() -> DefaultBudgetedAgentRunner:
    return DefaultBudgetedAgentRunner(
        model=DeterministicFakeModel(),
        gateway=get_tool_gateway(),
        approval_store=get_approval_store(),
        telemetry=get_security_telemetry_recorder(),
        workflow_store=get_approval_workflow_store(),
        approved_effect_pipeline=get_approved_effect_pipeline(),
        limits=P2G_EXECUTION_LIMITS,
    )


@lru_cache(maxsize=1)
def get_rag_answer_runner() -> RagAnswerRunner:
    return RagAnswerRunner(
        knowledge_store=get_knowledge_store(),
        model=DeterministicRagSecurityModel(),
        gateway=get_tool_gateway(),
        capability_policy=READ_ONLY_RAG_POLICY,
    )
