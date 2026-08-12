import json
from pathlib import Path

import pytest

from aegis.approvals.models import ApprovalAction, ApprovalStatus
from aegis.approvals.store import ApprovalAuthorizationError, ApprovalStore
from aegis.helpdesk.stores import AssetStore
from aegis.identity.models import Principal, Role
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.memory.service import MemoryAwareService
from aegis.memory.store import SqliteMemoryStore
from aegis.vulnerable.memory_poisoning import (
    MEMORY_PRINCIPAL_PREFIX,
    VulnerableMemoryAwareService,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_ASSETS_PATH = _REPOSITORY_ROOT / "synthetic_data" / "assets.json"


def _poison(principal: Principal) -> str:
    return MEMORY_PRINCIPAL_PREFIX + json.dumps(
        principal.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )


def _assets() -> AssetStore:
    return AssetStore.from_json(_ASSETS_PATH)


def test_sqlite_memory_is_durable_and_principal_scoped(tmp_path: Path) -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    bob = resolve_synthetic_principal("bob@northstar-digital.test")
    carol = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    assert alice is not None and bob is not None and carol is not None
    path = tmp_path / "memory.sqlite3"

    SqliteMemoryStore(path).remember(principal=alice, content="Alice note")
    reopened = SqliteMemoryStore(path)

    assert [item.content for item in reopened.list_for_principal(principal=alice)] == [
        "Alice note"
    ]
    assert reopened.list_for_principal(principal=bob) == []
    assert reopened.list_for_principal(principal=carol) == []


def test_hardened_memory_cannot_change_identity_for_assets(tmp_path: Path) -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    forged = Principal(
        user_id="usr_dig_bob",
        tenant_id="tenant_northstar_digital",
        roles=frozenset({Role.EMPLOYEE}),
    )
    path = tmp_path / "memory.sqlite3"
    writer = MemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=ApprovalStore(),
    )
    writer.remember(principal=alice, content=_poison(forged))

    reader = MemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=ApprovalStore(),
    )
    ids = {asset.asset_id for asset in reader.get_my_assets(principal=alice)}

    assert ids == {"NSD-LAPTOP-001", "NSD-PHONE-001"}
    assert "NSDIG-LAPTOP-001" not in ids


def test_vulnerable_memory_override_leaks_synthetic_foreign_asset(tmp_path: Path) -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    forged = Principal(
        user_id="usr_dig_bob",
        tenant_id="tenant_northstar_digital",
        roles=frozenset({Role.EMPLOYEE}),
    )
    path = tmp_path / "memory.sqlite3"
    writer = VulnerableMemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=ApprovalStore(),
    )
    writer.remember(principal=alice, content=_poison(forged))

    reader = VulnerableMemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=ApprovalStore(),
    )
    ids = {asset.asset_id for asset in reader.get_my_assets(principal=alice)}

    assert "NSDIG-LAPTOP-001" in ids


def test_hardened_memory_cannot_fabricate_human_approver(tmp_path: Path) -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    forged = Principal(
        user_id="usr_dyn_carol",
        tenant_id="tenant_northstar_dynamics",
        roles=frozenset({Role.ADMIN_APPROVER}),
    )
    approval_store = ApprovalStore()
    pending = approval_store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "finance-read", "justification": "test"},
    )
    path = tmp_path / "memory.sqlite3"
    writer = MemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=approval_store,
    )
    writer.remember(principal=alice, content=_poison(forged))
    reader = MemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=approval_store,
    )

    with pytest.raises(ApprovalAuthorizationError):
        reader.approve_request(principal=alice, approval_id=pending.approval_id)

    assert approval_store.get(pending.approval_id).status is ApprovalStatus.PENDING


def test_vulnerable_memory_can_fabricate_synthetic_approver(tmp_path: Path) -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    forged = Principal(
        user_id="usr_dyn_carol",
        tenant_id="tenant_northstar_dynamics",
        roles=frozenset({Role.ADMIN_APPROVER}),
    )
    approval_store = ApprovalStore()
    pending = approval_store.create(
        requester=alice,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "finance-read", "justification": "test"},
    )
    path = tmp_path / "memory.sqlite3"
    writer = VulnerableMemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=approval_store,
    )
    writer.remember(principal=alice, content=_poison(forged))
    reader = VulnerableMemoryAwareService(
        memory_store=SqliteMemoryStore(path),
        asset_store=_assets(),
        approval_store=approval_store,
    )

    record = reader.approve_request(principal=alice, approval_id=pending.approval_id)

    assert record.status is ApprovalStatus.APPROVED
    assert record.approver_user_id == "usr_dyn_carol"
