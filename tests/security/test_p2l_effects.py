from pathlib import Path

import pytest

from aegis.approvals.durable import DurableApprovalStore
from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.approvals.store import ApprovalStateError
from aegis.effects.durable import (
    DurableEffectOutboxStore,
    DurableEffectWorker,
    SyntheticIdempotentEffectService,
    SyntheticWorkerCrash,
    TransactionalEffectCoordinator,
)
from aegis.identity.synthetic_auth import resolve_synthetic_principal


def _approved_case(
    tmp_path: Path,
    *,
    action: ApprovalAction = ApprovalAction.REQUEST_ACCESS,
    arguments: dict[str, str] | None = None,
):
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    approver = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    assert requester is not None and approver is not None
    arguments = arguments or {
        "resource": "synthetic-vpn",
        "justification": "P2-L test",
    }
    state_db = tmp_path / "state.sqlite3"
    effect_db = tmp_path / "effects.sqlite3"
    store = DurableApprovalStore(state_db)
    approval = store.create(
        requester=requester,
        action=action,
        arguments=arguments,
    )
    store.decide(
        approval_id=approval.approval_id,
        approver=approver,
        decision=ApprovalDecision.APPROVE,
    )
    consumed = TransactionalEffectCoordinator(store).resolve_after_review_and_enqueue(
        approval_id=approval.approval_id,
        requester=requester,
        action=action,
        arguments=arguments,
    )
    return (
        approval.approval_id,
        consumed,
        DurableEffectOutboxStore(state_db),
        SyntheticIdempotentEffectService(effect_db),
    )


def test_approved_effect_consumption_creates_bound_pending_outbox(tmp_path: Path) -> None:
    approval_id, consumed, outbox, _service = _approved_case(tmp_path)

    queued = outbox.get(approval_id)
    assert consumed.status is ApprovalStatus.CONSUMED
    assert queued.status == "pending"
    assert queued.approval_id == approval_id
    assert len(queued.idempotency_key) == 64
    assert queued.delivery_attempts == 0


def test_crash_after_effect_retries_without_duplicate(tmp_path: Path) -> None:
    approval_id, _consumed, outbox, service = _approved_case(tmp_path)
    crashing = DurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
        crash_after_effect_once=True,
    )

    with pytest.raises(SyntheticWorkerCrash):
        crashing.deliver(approval_id)

    assert service.count_effects(approval_id) == 1
    assert outbox.get(approval_id).status == "pending"

    retry = DurableEffectWorker(
        outbox_store=DurableEffectOutboxStore(tmp_path / "state.sqlite3"),
        effect_service=SyntheticIdempotentEffectService(tmp_path / "effects.sqlite3"),
    ).deliver(approval_id)

    assert retry.duplicate_suppressed is True
    assert service.count_effects(approval_id) == 1
    assert outbox.get(approval_id).status == "completed"


def test_duplicate_delivery_is_suppressed_by_downstream_ledger(tmp_path: Path) -> None:
    approval_id, _consumed, outbox, service = _approved_case(tmp_path)
    first = DurableEffectWorker(outbox_store=outbox, effect_service=service).deliver(
        approval_id
    )
    second = DurableEffectWorker(outbox_store=outbox, effect_service=service).deliver(
        approval_id
    )

    assert first.duplicate_suppressed is False
    assert second.duplicate_suppressed is True
    assert first.effect_ref == second.effect_ref
    assert service.count_effects(approval_id) == 1
    assert outbox.get(approval_id).delivery_attempts == 2


def test_rejected_approval_never_creates_effect_outbox(tmp_path: Path) -> None:
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    approver = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    assert requester is not None and approver is not None
    arguments = {"resource": "synthetic-vpn", "justification": "P2-L rejection"}
    state_db = tmp_path / "state.sqlite3"
    store = DurableApprovalStore(state_db)
    approval = store.create(
        requester=requester,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )
    store.decide(
        approval_id=approval.approval_id,
        approver=approver,
        decision=ApprovalDecision.REJECT,
    )

    record = TransactionalEffectCoordinator(store).resolve_after_review_and_enqueue(
        approval_id=approval.approval_id,
        requester=requester,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )
    assert record.status is ApprovalStatus.REJECTED
    with pytest.raises(ApprovalStateError):
        DurableEffectOutboxStore(state_db).get(approval.approval_id)
