import asyncio
from pathlib import Path

import pytest

from aegis.agent.fake_model import DeterministicFakeModel
from aegis.agent.graph import AgentRunner
from aegis.approvals.durable import DurableApprovalStore, DurableWorkflowStore
from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.approvals.store import ApprovalBindingError, ApprovalStateError
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.rag.store import KnowledgeStore


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_KNOWLEDGE_PATH = _REPOSITORY_ROOT / "synthetic_data" / "knowledge.json"
_ASSETS_PATH = _REPOSITORY_ROOT / "synthetic_data" / "assets.json"


def _runner(database_path: Path) -> AgentRunner:
    approval_store = DurableApprovalStore(database_path)
    workflow_store = DurableWorkflowStore(database_path)
    gateway = ToolGateway(
        knowledge_store=KnowledgeStore.from_json(_KNOWLEDGE_PATH),
        asset_store=AssetStore.from_json(_ASSETS_PATH),
        ticket_store=TicketStore(),
        approval_store=approval_store,
    )
    return AgentRunner(
        model=DeterministicFakeModel(),
        gateway=gateway,
        approval_store=approval_store,
        workflow_store=workflow_store,
    )


def _principals():
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    carol = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    bob = resolve_synthetic_principal("bob@northstar-digital.test")
    assert alice is not None and carol is not None and bob is not None
    return alice, carol, bob


def test_pending_workflow_survives_runner_restart_and_completes_once(tmp_path) -> None:
    alice, carol, _ = _principals()
    database_path = tmp_path / "state.sqlite3"

    first_runner = _runner(database_path)
    pending = asyncio.run(
        first_runner.run(
            principal=alice,
            message="access: finance-read | Restart-safe approval test",
        )
    )
    assert pending.approval_id is not None

    restarted_runner = _runner(database_path)
    resumed = asyncio.run(
        restarted_runner.review_and_resume(
            approval_id=pending.approval_id,
            approver=carol,
            decision=ApprovalDecision.APPROVE,
        )
    )
    assert resumed.result["status"] == ApprovalStatus.CONSUMED.value
    assert DurableWorkflowStore(database_path).get(pending.approval_id).status == "completed"

    second_restart = _runner(database_path)
    with pytest.raises(ApprovalStateError):
        asyncio.run(
            second_restart.review_and_resume(
                approval_id=pending.approval_id,
                approver=carol,
                decision=ApprovalDecision.APPROVE,
            )
        )


def test_restart_after_decision_recovers_without_second_decision(tmp_path) -> None:
    alice, carol, _ = _principals()
    database_path = tmp_path / "state.sqlite3"
    pending = asyncio.run(
        _runner(database_path).run(
            principal=alice,
            message="access: finance-read | Crash after decision",
        )
    )
    assert pending.approval_id is not None

    DurableApprovalStore(database_path).decide(
        approval_id=pending.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )

    recovered = asyncio.run(
        _runner(database_path).review_and_resume(
            approval_id=pending.approval_id,
            approver=carol,
            decision=ApprovalDecision.APPROVE,
        )
    )
    assert recovered.result["status"] == ApprovalStatus.CONSUMED.value


def test_restart_after_consumption_recovers_without_reconsuming(tmp_path) -> None:
    alice, carol, _ = _principals()
    database_path = tmp_path / "state.sqlite3"
    pending = asyncio.run(
        _runner(database_path).run(
            principal=alice,
            message="access: finance-read | Crash after consume",
        )
    )
    assert pending.approval_id is not None

    approval_store = DurableApprovalStore(database_path)
    workflow = DurableWorkflowStore(database_path).require_pending(pending.approval_id)
    approval_store.decide(
        approval_id=pending.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )
    consumed = approval_store.resolve_after_review(
        approval_id=pending.approval_id,
        requester=workflow.requester,
        action=workflow.action,
        arguments=workflow.arguments,
    )
    assert consumed.status is ApprovalStatus.CONSUMED

    recovered = asyncio.run(
        _runner(database_path).review_and_resume(
            approval_id=pending.approval_id,
            approver=carol,
            decision=ApprovalDecision.APPROVE,
        )
    )
    assert recovered.result["status"] == ApprovalStatus.CONSUMED.value
    assert DurableWorkflowStore(database_path).get(pending.approval_id).status == "completed"


def test_restart_does_not_make_approval_binding_transferable(tmp_path) -> None:
    alice, carol, bob = _principals()
    database_path = tmp_path / "state.sqlite3"
    pending = asyncio.run(
        _runner(database_path).run(
            principal=alice,
            message="access: finance-read | Original binding",
        )
    )
    assert pending.approval_id is not None

    approval_store = DurableApprovalStore(database_path)
    approval_store.decide(
        approval_id=pending.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )

    with pytest.raises(ApprovalBindingError):
        DurableApprovalStore(database_path).resolve_after_review(
            approval_id=pending.approval_id,
            requester=bob,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "finance-admin",
                "justification": "Attempted restart rebinding",
            },
        )

    persisted = DurableWorkflowStore(database_path).require_pending(pending.approval_id)
    assert persisted.requester.user_id == alice.user_id
    assert persisted.tenant_id == alice.tenant_id
    assert persisted.arguments["resource"] == "finance-read"
