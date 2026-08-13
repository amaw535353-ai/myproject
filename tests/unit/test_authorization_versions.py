from datetime import datetime, timezone

import pytest

from aegis.approvals.models import ApprovalAction
from aegis.effects.durable import EffectOutboxRecord
from aegis.effects.revalidation import ExecutionAuthorizationReason, SyntheticAuthorizationStateStore
from aegis.effects.versioned_revalidation import (
    AuthorizationVersionStore,
    CachedAuthorizationReplica,
    VersionedAuthorizationController,
    authorization_record_binding,
)
from aegis.identity.models import Role


TENANT = "tenant_northstar_dynamics"
USER = "usr_dyn_alice"


def test_authorization_versions_are_monotonic(tmp_path) -> None:
    store = AuthorizationVersionStore(tmp_path / "versions.sqlite3")
    store.set_version(tenant_id=TENANT, policy_version=1, revocation_epoch=1)
    advanced = store.advance_revocation_epoch(TENANT)
    assert advanced.revocation_epoch == 2
    assert advanced.policy_version == 1

    with pytest.raises(ValueError, match="monotonic"):
        store.set_version(tenant_id=TENANT, policy_version=1, revocation_epoch=1)


def test_authoritative_mutations_advance_the_correct_fence(tmp_path) -> None:
    database = tmp_path / "authorization.sqlite3"
    authorization = SyntheticAuthorizationStateStore(database)
    authorization.set_subject(
        user_id=USER,
        tenant_id=TENANT,
        active=True,
        roles=frozenset({Role.EMPLOYEE}),
    )
    authorization.set_password_reset_enabled(TENANT, True)
    versions = AuthorizationVersionStore(database)
    versions.set_version(tenant_id=TENANT, policy_version=1, revocation_epoch=1)
    controller = VersionedAuthorizationController(
        authorization_store=authorization,
        version_store=versions,
    )

    revoked = controller.set_subject_active(USER, False)
    assert revoked.policy_version == 1
    assert revoked.revocation_epoch == 2

    policy_changed = controller.set_password_reset_enabled(TENANT, False)
    assert policy_changed.policy_version == 2
    assert policy_changed.revocation_epoch == 2


def test_cached_decision_is_bound_to_the_exact_outbox_record(tmp_path) -> None:
    database = tmp_path / "replica.sqlite3"
    authorization = SyntheticAuthorizationStateStore(database)
    authorization.set_subject(
        user_id=USER,
        tenant_id=TENANT,
        active=True,
        roles=frozenset({Role.EMPLOYEE}),
    )
    authorization.set_resource(
        tenant_id=TENANT,
        resource="synthetic-vpn",
        enabled=True,
        owner_user_id=USER,
        required_role=Role.EMPLOYEE,
    )
    versions = AuthorizationVersionStore(database)
    versions.set_version(tenant_id=TENANT, policy_version=3, revocation_epoch=7)
    replica = CachedAuthorizationReplica(
        authorization_store=authorization,
        version_store=versions,
    )
    record = EffectOutboxRecord(
        approval_id="apr_synthetic",
        idempotency_key="idem_synthetic",
        requester_user_id=USER,
        tenant_id=TENANT,
        action=ApprovalAction.REQUEST_ACCESS,
        normalized_arguments_json='{"justification":"unit","resource":"synthetic-vpn"}',
        status="pending",
        delivery_attempts=0,
        created_at=datetime.now(timezone.utc),
    )

    decision = replica.evaluate(record)
    assert decision.reason is ExecutionAuthorizationReason.ALLOWED
    assert decision.policy_version == 3
    assert decision.revocation_epoch == 7
    assert decision.record_binding_hash == authorization_record_binding(record)
