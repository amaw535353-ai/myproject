from __future__ import annotations

import json

from pydantic import ValidationError

from aegis.approvals.models import ApprovalDecision, ApprovalRecord
from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.models import AssetView
from aegis.helpdesk.stores import AssetStore
from aegis.identity.models import Principal
from aegis.memory.models import MemoryRecord
from aegis.memory.store import SqliteMemoryStore


MEMORY_PRINCIPAL_PREFIX = "AEGIS_MEMORY_PRINCIPAL="
VULNERABLE_MEMORY_POLICY_VERSION = "memory-content-overrides-principal-v1"


def _memory_selected_principal(
    *,
    authenticated_principal: Principal,
    records: list[MemoryRecord],
) -> Principal:
    """INTENTIONALLY VULNERABLE: interpret persisted user text as trusted identity."""

    for record in reversed(records):
        for line in record.content.splitlines():
            stripped = line.strip()
            if not stripped.startswith(MEMORY_PRINCIPAL_PREFIX):
                continue
            payload = stripped[len(MEMORY_PRINCIPAL_PREFIX) :]
            try:
                candidate = json.loads(payload)
                return Principal.model_validate(candidate)
            except (json.JSONDecodeError, ValidationError):
                continue
    return authenticated_principal


class VulnerableMemoryAwareService:
    """Lab-only durable-memory confused deputy.

    The bug is not SQLite. The bug is promoting stored untrusted content into the
    authoritative Principal used by downstream authorization-sensitive services.
    """

    policy_version = VULNERABLE_MEMORY_POLICY_VERSION

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

    def _effective_principal(self, principal: Principal) -> Principal:
        return _memory_selected_principal(
            authenticated_principal=principal,
            records=self.recall(principal=principal),
        )

    def get_my_assets(self, *, principal: Principal) -> list[AssetView]:
        return self._asset_store.get_my_assets(self._effective_principal(principal))

    def approve_request(
        self,
        *,
        principal: Principal,
        approval_id: str,
    ) -> ApprovalRecord:
        return self._approval_store.decide(
            approval_id=approval_id,
            approver=self._effective_principal(principal),
            decision=ApprovalDecision.APPROVE,
        )
