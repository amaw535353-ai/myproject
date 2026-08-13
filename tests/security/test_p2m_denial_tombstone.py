from pathlib import Path

import pytest

from aegis.approvals.durable import DurableApprovalStore
from aegis.approvals.models import ApprovalAction, ApprovalDecision
from aegis.effects.durable import TransactionalEffectCoordinator
from aegis.effects.revalidation import (
    ExecutionAuthorizationError,
    ExecutionAuthorizationReason,
    RevalidatingEffectOutboxStore,
    SyntheticAuthorizationStateStore,
    SyntheticRevalidatingEffectService,
)
from aegis.identity.models import Role
from aegis.identity.synthetic_auth import resolve_synthetic_principal


def test_denial_tombstone_survives_missing_outbox_cancellation(tmp_path: Path) -> None:
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    approver = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    assert requester is not None and approver is not None

    state_db = tmp_path / "state.sqlite3"
    effect_db = tmp_path / "effects.sqlite3"
    arguments = {"resource": "synthetic-vpn", "justification": "denial crash window"}
    approvals = DurableApprovalStore(state_db)
    approval = approvals.create(
        requester=requester,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )
    approvals.decide(
        approval_id=approval.approval_id,
        approver=approver,
        decision=ApprovalDecision.APPROVE,
    )
    TransactionalEffectCoordinator(approvals).resolve_after_review_and_enqueue(
        approval_id=approval.approval_id,
        requester=requester,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments=arguments,
    )

    authorization = SyntheticAuthorizationStateStore(effect_db)
    authorization.set_subject(
        user_id=requester.user_id,
        tenant_id=requester.tenant_id,
        active=False,
        roles=requester.roles,
    )
    authorization.set_resource(
        tenant_id=requester.tenant_id,
        resource="synthetic-vpn",
        enabled=True,
        owner_user_id=requester.user_id,
        required_role=Role.EMPLOYEE,
    )
    service = SyntheticRevalidatingEffectService(
        effect_db,
        authorization_store=authorization,
    )
    record = RevalidatingEffectOutboxStore(state_db).get(approval.approval_id)

    # Call the service directly to model a worker dying after the deny transaction but
    # before it can mark the separate outbox database cancelled.
    with pytest.raises(ExecutionAuthorizationError) as first:
        service.execute(record)
    assert first.value.reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE

    authorization.set_subject_active(requester.user_id, True)
    restarted = SyntheticRevalidatingEffectService(
        effect_db,
        authorization_store=SyntheticAuthorizationStateStore(effect_db),
    )
    with pytest.raises(ExecutionAuthorizationError) as retry:
        restarted.execute(record)

    assert retry.value.reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
    assert restarted.count_effects(approval.approval_id) == 0
