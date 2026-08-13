from pathlib import Path

import pytest

from aegis.approvals.durable import DurableApprovalStore
from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.effects.durable import (
    SyntheticWorkerCrash,
    TransactionalEffectCoordinator,
)
from aegis.effects.revalidation import (
    ExecutionAuthorizationError,
    ExecutionAuthorizationReason,
    RevalidatingDurableEffectWorker,
    RevalidatingEffectOutboxStore,
    SyntheticAuthorizationStateStore,
    SyntheticRevalidatingEffectService,
)
from aegis.identity.models import Role
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
        "justification": "P2-M test",
    }

    state_db = tmp_path / "state.sqlite3"
    effect_db = tmp_path / "effects.sqlite3"
    approvals = DurableApprovalStore(state_db)
    approval = approvals.create(
        requester=requester,
        action=action,
        arguments=arguments,
    )
    approvals.decide(
        approval_id=approval.approval_id,
        approver=approver,
        decision=ApprovalDecision.APPROVE,
    )
    consumed = TransactionalEffectCoordinator(approvals).resolve_after_review_and_enqueue(
        approval_id=approval.approval_id,
        requester=requester,
        action=action,
        arguments=arguments,
    )
    assert consumed.status is ApprovalStatus.CONSUMED

    authorization = SyntheticAuthorizationStateStore(effect_db)
    authorization.set_subject(
        user_id=requester.user_id,
        tenant_id=requester.tenant_id,
        active=True,
        roles=requester.roles,
    )
    authorization.set_resource(
        tenant_id=requester.tenant_id,
        resource="synthetic-vpn",
        enabled=True,
        owner_user_id=requester.user_id,
        required_role=Role.EMPLOYEE,
    )
    authorization.set_resource(
        tenant_id=requester.tenant_id,
        resource="synthetic-reports",
        enabled=True,
        owner_user_id=requester.user_id,
        required_role=Role.EMPLOYEE,
    )
    authorization.set_password_reset_enabled(requester.tenant_id, True)

    outbox = RevalidatingEffectOutboxStore(state_db)
    service = SyntheticRevalidatingEffectService(
        effect_db,
        authorization_store=authorization,
    )
    worker = RevalidatingDurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
    )
    return approval.approval_id, requester, authorization, outbox, service, worker


def test_subject_revoked_after_approval_is_blocked_before_first_effect(tmp_path: Path) -> None:
    approval_id, requester, authorization, outbox, service, worker = _approved_case(tmp_path)
    authorization.set_subject_active(requester.user_id, False)

    with pytest.raises(ExecutionAuthorizationError) as exc:
        worker.deliver(approval_id)

    assert exc.value.reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
    assert service.count_effects(approval_id) == 0
    assert outbox.get(approval_id).status == "cancelled"


def test_resource_owner_changed_after_approval_is_blocked(tmp_path: Path) -> None:
    approval_id, _requester, authorization, outbox, service, worker = _approved_case(
        tmp_path,
        arguments={
            "resource": "synthetic-reports",
            "justification": "Ownership test",
        },
    )
    authorization.set_resource_owner(
        "tenant_northstar_dynamics",
        "synthetic-reports",
        "usr_dyn_carol",
    )

    with pytest.raises(ExecutionAuthorizationError) as exc:
        worker.deliver(approval_id)

    assert exc.value.reason is ExecutionAuthorizationReason.RESOURCE_OWNER_MISMATCH
    assert service.count_effects(approval_id) == 0
    assert outbox.get(approval_id).status == "cancelled"


def test_denied_stale_approval_cannot_resurrect_after_authorization_restored(
    tmp_path: Path,
) -> None:
    approval_id, requester, authorization, outbox, service, worker = _approved_case(tmp_path)
    authorization.set_subject_active(requester.user_id, False)
    with pytest.raises(ExecutionAuthorizationError):
        worker.deliver(approval_id)

    authorization.set_subject_active(requester.user_id, True)
    restarted = RevalidatingDurableEffectWorker(
        outbox_store=RevalidatingEffectOutboxStore(tmp_path / "state.sqlite3"),
        effect_service=SyntheticRevalidatingEffectService(
            tmp_path / "effects.sqlite3",
            authorization_store=SyntheticAuthorizationStateStore(
                tmp_path / "effects.sqlite3"
            ),
        ),
    )
    with pytest.raises(ExecutionAuthorizationError) as exc:
        restarted.deliver(approval_id)

    assert exc.value.reason is ExecutionAuthorizationReason.OUTBOX_CANCELLED
    assert service.count_effects(approval_id) == 0
    assert outbox.get(approval_id).status == "cancelled"


def test_unchanged_authorized_access_completes_once(tmp_path: Path) -> None:
    approval_id, _requester, _authorization, outbox, service, worker = _approved_case(
        tmp_path
    )

    execution = worker.deliver(approval_id)

    assert execution.duplicate_suppressed is False
    assert service.count_effects(approval_id) == 1
    assert outbox.get(approval_id).status == "completed"


def test_unchanged_password_reset_policy_completes_once(tmp_path: Path) -> None:
    approval_id, _requester, _authorization, outbox, service, worker = _approved_case(
        tmp_path,
        action=ApprovalAction.REQUEST_PASSWORD_RESET,
        arguments={"reason": "P2-M recovery"},
    )

    execution = worker.deliver(approval_id)

    assert execution.duplicate_suppressed is False
    assert service.count_effects(approval_id) == 1
    assert outbox.get(approval_id).status == "completed"


def test_crash_after_authorized_effect_can_retry_after_later_revocation(
    tmp_path: Path,
) -> None:
    approval_id, requester, authorization, outbox, service, _worker = _approved_case(
        tmp_path
    )
    crashing = RevalidatingDurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
        crash_after_effect_once=True,
    )
    with pytest.raises(SyntheticWorkerCrash):
        crashing.deliver(approval_id)

    assert service.count_effects(approval_id) == 1
    assert outbox.get(approval_id).status == "pending"

    authorization.set_subject_active(requester.user_id, False)
    retry = RevalidatingDurableEffectWorker(
        outbox_store=RevalidatingEffectOutboxStore(tmp_path / "state.sqlite3"),
        effect_service=SyntheticRevalidatingEffectService(
            tmp_path / "effects.sqlite3",
            authorization_store=SyntheticAuthorizationStateStore(
                tmp_path / "effects.sqlite3"
            ),
        ),
    ).deliver(approval_id)

    assert retry.duplicate_suppressed is True
    assert service.count_effects(approval_id) == 1
    assert outbox.get(approval_id).status == "completed"
