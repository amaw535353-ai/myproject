from __future__ import annotations

from aegis.approvals.models import ApprovalDecision, ApprovalRecord
from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.models import AssetView
from aegis.helpdesk.stores import AssetStore
from aegis.identity.models import Principal
from aegis.memory.models import MemoryRecord
from aegis.memory.store import SqliteMemoryStore


HARDENED_MEMORY_POLICY_VERSION = "memory-data-not-authority-v1"


class MemoryAwareService:
    """Hardened service: durable memory can inform context but never authorization."""

    policy_version = HARDENED_MEMORY_POLICY_VERSION

    def __init__(
        self,
        *,
        memory_store: SqliteMemoryStore,
        asset_store: AssetStore,
        approval_store: ApprovalStore,
    ) -> None:
        self._memory_store = memory_store
        self._asset_store = asset_store
        self._approval_store = approval_store

    def remember(self, *, principal: Principal, content: str) -> MemoryRecord:
        return self._memory_store.remember(principal=principal, content=content)

    def recall(self, *, principal: Principal) -> list[MemoryRecord]:
        return self._memory_store.list_for_principal(principal=principal)

    def get_my_assets(self, *, principal: Principal) -> list[AssetView]:
        # Memory may become model context later, but it never chooses the Principal
        # passed into authorization-sensitive stores.
        self.recall(principal=principal)
        return self._asset_store.get_my_assets(principal)

    def approve_request(
        self,
        *,
        principal: Principal,
        approval_id: str,
    ) -> ApprovalRecord:
        # Authenticated identity remains authoritative even if memory claims otherwise.
        self.recall(principal=principal)
        return self._approval_store.decide(
            approval_id=approval_id,
            approver=principal,
            decision=ApprovalDecision.APPROVE,
        )
