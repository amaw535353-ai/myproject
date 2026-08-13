from pathlib import Path

from aegis.approvals.durable import DurableApprovalStore
from aegis.approvals.models import ApprovalAction, ApprovalDecision
from aegis.effects.durable import TransactionalEffectCoordinator
from aegis.effects.revalidation import (
    ExecutionAuthorizationReason,
    RevalidatingEffectOutboxStore,
    SyntheticAuthorizationStateStore,
)
from aegis.identity.models import Role
from aegis.identity.synthetic_auth import resolve_synthetic_principal


def _record(tmp_path: Path, *, action: ApprovalAction, arguments: dict[str, str]):
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    approver = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    assert requester is not None and approver is not None
    state_db = tmp_path / "state.sqlite3"
    approvals = DurableApprovalStore(state_db)
    approval = approvals.create(requester=requester, action=action, arguments=arguments)
    approvals.decide(
        approval_id=approval.approval_id,
        approver=approver,
        decision=ApprovalDecision.APPROVE,
    )
    TransactionalEffectCoordinator(approvals).resolve_after_review_and_enqueue(
        approval_id=approval.approval_id,
        requester=requester,
        action=action,
        arguments=arguments,
    )

    authorization = SyntheticAuthorizationStateStore(tmp_path / "effects.sqlite3")
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
    authorization.set_password_reset_enabled(requester.tenant_id, True)
    return (
        requester,
        authorization,
        RevalidatingEffectOutboxStore(state_db).get(approval.approval_id),
    )


def test_tenant_membership_drift_is_denied(tmp_path: Path) -> None:
    requester, authorization, record = _record(
        tmp_path,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "synthetic-vpn", "justification": "unit"},
    )
    authorization.set_subject_tenant(requester.user_id, "tenant_northstar_digital")

    assert (
        authorization.evaluate(record)
        is ExecutionAuthorizationReason.TENANT_MEMBERSHIP_CHANGED
    )


def test_missing_current_role_is_denied(tmp_path: Path) -> None:
    requester, authorization, record = _record(
        tmp_path,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "synthetic-vpn", "justification": "unit"},
    )
    authorization.set_subject_roles(requester.user_id, frozenset())

    assert (
        authorization.evaluate(record)
        is ExecutionAuthorizationReason.REQUIRED_ROLE_MISSING
    )


def test_disabled_resource_is_denied(tmp_path: Path) -> None:
    _requester, authorization, record = _record(
        tmp_path,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "synthetic-vpn", "justification": "unit"},
    )
    authorization.set_resource_enabled(
        "tenant_northstar_dynamics",
        "synthetic-vpn",
        False,
    )

    assert authorization.evaluate(record) is ExecutionAuthorizationReason.RESOURCE_DISABLED


def test_disabled_password_reset_policy_is_denied(tmp_path: Path) -> None:
    _requester, authorization, record = _record(
        tmp_path,
        action=ApprovalAction.REQUEST_PASSWORD_RESET,
        arguments={"reason": "unit"},
    )
    authorization.set_password_reset_enabled("tenant_northstar_dynamics", False)

    assert (
        authorization.evaluate(record)
        is ExecutionAuthorizationReason.PASSWORD_RESET_DISABLED
    )
