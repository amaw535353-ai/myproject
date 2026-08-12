from datetime import datetime, timedelta, timezone

import pytest

from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.approvals.store import ApprovalBindingError, ApprovalStateError, ApprovalStore
from aegis.identity.models import Principal, Role
from aegis.identity.synthetic_auth import resolve_synthetic_principal


def _principal(handle: str) -> Principal:
    principal = resolve_synthetic_principal(handle)
    assert principal is not None
    return principal


def test_approved_request_is_consumed_exactly_once() -> None:
    store = ApprovalStore()
    alice = _principal("alice@northstar-dynamics.test")
    carol = _principal("carol.approver@northstar-dynamics.test")
    arguments = {"resource": "finance-read", "justification": "quarterly reports"}

    record = store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )
    store.decide(
        approval_id=record.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )
    consumed = store.consume(
        approval_id=record.approval_id,
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )

    assert consumed.status is ApprovalStatus.CONSUMED
    with pytest.raises(ApprovalStateError):
        store.consume(
            approval_id=record.approval_id,
            requester=alice,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=arguments,
        )


def test_argument_mutation_invalidates_approval_without_consuming_it() -> None:
    store = ApprovalStore()
    alice = _principal("alice@northstar-dynamics.test")
    carol = _principal("carol.approver@northstar-dynamics.test")
    original = {"resource": "finance-read", "justification": "quarterly reports"}

    record = store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=original,
    )
    store.decide(
        approval_id=record.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )

    with pytest.raises(ApprovalBindingError):
        store.consume(
            approval_id=record.approval_id,
            requester=alice,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "finance-admin",
                "justification": "quarterly reports",
            },
        )

    assert store.get(record.approval_id).status is ApprovalStatus.APPROVED


def test_approval_is_nontransferable_to_another_requester() -> None:
    store = ApprovalStore()
    alice = _principal("alice@northstar-dynamics.test")
    carol = _principal("carol.approver@northstar-dynamics.test")
    other_user = Principal(
        user_id="usr_dyn_other",
        tenant_id=alice.tenant_id,
        roles=frozenset({Role.EMPLOYEE}),
    )
    arguments = {"reason": "forgot password"}

    record = store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_PASSWORD_RESET,
        arguments=arguments,
    )
    store.decide(
        approval_id=record.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )

    with pytest.raises(ApprovalBindingError):
        store.consume(
            approval_id=record.approval_id,
            requester=other_user,
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments=arguments,
        )


def test_expired_approval_fails_closed() -> None:
    now = [datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)]
    store = ApprovalStore(
        ttl=timedelta(seconds=30),
        clock=lambda: now[0],
    )
    alice = _principal("alice@northstar-dynamics.test")
    carol = _principal("carol.approver@northstar-dynamics.test")

    record = store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "finance-read", "justification": "test"},
    )
    now[0] += timedelta(seconds=31)

    with pytest.raises(ApprovalStateError):
        store.decide(
            approval_id=record.approval_id,
            approver=carol,
            decision=ApprovalDecision.APPROVE,
        )
    assert store.get(record.approval_id).status is ApprovalStatus.EXPIRED


def test_action_substitution_invalidates_approval() -> None:
    store = ApprovalStore()
    alice = _principal("alice@northstar-dynamics.test")
    carol = _principal("carol.approver@northstar-dynamics.test")
    arguments = {"resource": "finance-read", "justification": "quarterly reports"}

    record = store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )
    store.decide(
        approval_id=record.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )

    with pytest.raises(ApprovalBindingError):
        store.consume(
            approval_id=record.approval_id,
            requester=alice,
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments=arguments,
        )

    assert store.get(record.approval_id).status is ApprovalStatus.APPROVED


def test_approved_record_cannot_be_consumed_after_expiry() -> None:
    now = [datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)]
    store = ApprovalStore(
        ttl=timedelta(seconds=30),
        clock=lambda: now[0],
    )
    alice = _principal("alice@northstar-dynamics.test")
    carol = _principal("carol.approver@northstar-dynamics.test")
    arguments = {"resource": "finance-read", "justification": "test"}

    record = store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )
    store.decide(
        approval_id=record.approval_id,
        approver=carol,
        decision=ApprovalDecision.APPROVE,
    )
    now[0] += timedelta(seconds=31)

    with pytest.raises(ApprovalStateError):
        store.consume(
            approval_id=record.approval_id,
            requester=alice,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=arguments,
        )

    assert store.get(record.approval_id).status is ApprovalStatus.EXPIRED
