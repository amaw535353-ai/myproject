from __future__ import annotations

import logging
from pathlib import Path

import pytest

from aegis.agent.checkpoint_security import (
    DEFAULT_CHECKPOINT_SERIALIZATION_POLICY,
    P4A_ALLOWED_MSGPACK_TYPES,
    build_strict_checkpoint_serializer,
)
from aegis.agent.fake_model import DeterministicFakeModel
from aegis.agent.graph import AgentRunner
from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.rag.store import KnowledgeStore
from evals.p4a_strict_checkpoint_serialization import build_report


ROOT = Path(__file__).resolve().parents[2]


def _runner() -> AgentRunner:
    return AgentRunner(
        model=DeterministicFakeModel(),
        gateway=ToolGateway(
            knowledge_store=KnowledgeStore.from_json(ROOT / "synthetic_data" / "knowledge.json"),
            asset_store=AssetStore.from_json(ROOT / "synthetic_data" / "assets.json"),
            ticket_store=TicketStore(),
            approval_store=ApprovalStore(),
        ),
        approval_store=ApprovalStore(),
    )


def test_checkpoint_policy_is_exact_and_disables_fallbacks() -> None:
    policy = DEFAULT_CHECKPOINT_SERIALIZATION_POLICY
    assert policy.allowed_msgpack_types == P4A_ALLOWED_MSGPACK_TYPES
    assert policy.pickle_fallback is False
    assert policy.allowed_json_modules is None
    assert set(P4A_ALLOWED_MSGPACK_TYPES) == {
        ("aegis.identity.models", "Role"),
        ("aegis.identity.models", "Principal"),
        ("aegis.mcp_gateway.models", "ToolName"),
        ("aegis.mcp_gateway.models", "ToolCallProposal"),
    }


def test_serializer_uses_strict_application_allowlist() -> None:
    serializer = build_strict_checkpoint_serializer()
    assert serializer.pickle_fallback is False
    assert serializer._allowed_json_modules is None
    assert serializer._allowed_msgpack_modules == set(P4A_ALLOWED_MSGPACK_TYPES)


@pytest.mark.asyncio
async def test_default_agent_checkpoint_roundtrip_has_no_permissive_warning(caplog) -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    runner = _runner()
    with caplog.at_level(logging.WARNING, logger="langgraph.checkpoint.serde.jsonplus"):
        result = await runner.run(principal=alice, message="assets")
    assert {item["asset_id"] for item in result.result["assets"]} == {
        "NSD-LAPTOP-001",
        "NSD-PHONE-001",
    }
    assert "Deserializing unregistered type" not in caplog.text


def test_p4a_evaluation_metrics_are_exact() -> None:
    report = build_report()
    assert report["variants"]["permissive_baseline"]["metrics"]["asr"] == [2, 2]
    strict = report["variants"]["strict_boundary"]["metrics"]
    assert strict == {
        "asr": [0, 2],
        "fpr": [0, 2],
        "safe_task_rate": [2, 2],
    }
    assert report["pickle_fallback_enabled"] is False
    assert report["custom_json_constructor_allowlist"] is False
    assert report["real_external_operations"] is False
    assert report["passed"] is True
