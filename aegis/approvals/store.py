import hashlib
import hmac
import json
import secrets
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any

from aegis.approvals.models import (
    ApprovalAction,
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStatus,
)
from aegis.identity.models import Principal, Role


class ApprovalError(RuntimeError):
    pass


class ApprovalNotFoundError(ApprovalError):
    pass


class ApprovalAuthorizationError(ApprovalError):
    pass


class ApprovalBindingError(ApprovalError):
    pass


class ApprovalStateError(ApprovalError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonicalize(arguments: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(arguments),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _binding_hash(
    *,
    nonce: str,
    requester_user_id: str,
    tenant_id: str,
    action: ApprovalAction,
    normalized_arguments_json: str,
) -> str:
    material = "\x1f".join(
        (
            nonce,
            requester_user_id,
            tenant_id,
            action.value,
            normalized_arguments_json,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ApprovalStore:
    """In-memory P1-C approval store with strict identity/action/argument binding."""

    def __init__(
        self,
        *,
        ttl: timedelta = timedelta(minutes=10),
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("approval TTL must be positive")
        self._ttl = ttl
        self._clock = clock
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = RLock()

    def create(
        self,
        *,
        requester: Principal,
        action: ApprovalAction,
        arguments: Mapping[str, Any],
    ) -> ApprovalRecord:
        now = self._clock()
        approval_id = f"apr_{secrets.token_urlsafe(18)}"
        nonce = secrets.token_urlsafe(24)
        normalized = _canonicalize(arguments)
        record = ApprovalRecord(
            approval_id=approval_id,
            nonce=nonce,
            requester_user_id=requester.user_id,
            tenant_id=requester.tenant_id,
            action=action,
            normalized_arguments_json=normalized,
            binding_hash=_binding_hash(
                nonce=nonce,
                requester_user_id=requester.user_id,
                tenant_id=requester.tenant_id,
                action=action,
                normalized_arguments_json=normalized,
            ),
            created_at=now,
            expires_at=now + self._ttl,
            status=ApprovalStatus.PENDING,
        )
        with self._lock:
            self._records[approval_id] = record
        return record

    def get(self, approval_id: str) -> ApprovalRecord:
        with self._lock:
            record = self._require_record(approval_id)
            return self._expire_if_needed(record)

    def decide(
        self,
        *,
        approval_id: str,
        approver: Principal,
        decision: ApprovalDecision,
    ) -> ApprovalRecord:
        with self._lock:
            record = self._expire_if_needed(self._require_record(approval_id))
            if Role.ADMIN_APPROVER not in approver.roles:
                raise ApprovalAuthorizationError("principal is not an approver")
            if approver.tenant_id != record.tenant_id:
                raise ApprovalAuthorizationError("cross-tenant approval is forbidden")
            if approver.user_id == record.requester_user_id:
                raise ApprovalAuthorizationError("self-approval is forbidden")
            if record.status is not ApprovalStatus.PENDING:
                raise ApprovalStateError("approval is not pending")

            now = self._clock()
            status = (
                ApprovalStatus.APPROVED
                if decision is ApprovalDecision.APPROVE
                else ApprovalStatus.REJECTED
            )
            updated = record.model_copy(
                update={
                    "status": status,
                    "approver_user_id": approver.user_id,
                    "decided_at": now,
                }
            )
            self._records[approval_id] = updated
            return updated

    def resolve_after_review(
        self,
        *,
        approval_id: str,
        requester: Principal,
        action: ApprovalAction,
        arguments: Mapping[str, Any],
    ) -> ApprovalRecord:
        with self._lock:
            record = self._expire_if_needed(self._require_record(approval_id))
            if record.status is ApprovalStatus.REJECTED:
                self._verify_binding(
                    record=record,
                    requester=requester,
                    action=action,
                    arguments=arguments,
                )
                return record
            if record.status is not ApprovalStatus.APPROVED:
                raise ApprovalStateError("approval is not ready for consumption")
            return self._consume_locked(
                record=record,
                requester=requester,
                action=action,
                arguments=arguments,
            )

    def consume(
        self,
        *,
        approval_id: str,
        requester: Principal,
        action: ApprovalAction,
        arguments: Mapping[str, Any],
    ) -> ApprovalRecord:
        with self._lock:
            record = self._expire_if_needed(self._require_record(approval_id))
            if record.status is not ApprovalStatus.APPROVED:
                raise ApprovalStateError("approval is not approved")
            return self._consume_locked(
                record=record,
                requester=requester,
                action=action,
                arguments=arguments,
            )

    def _consume_locked(
        self,
        *,
        record: ApprovalRecord,
        requester: Principal,
        action: ApprovalAction,
        arguments: Mapping[str, Any],
    ) -> ApprovalRecord:
        self._verify_binding(
            record=record,
            requester=requester,
            action=action,
            arguments=arguments,
        )
        updated = record.model_copy(
            update={
                "status": ApprovalStatus.CONSUMED,
                "consumed_at": self._clock(),
            }
        )
        self._records[record.approval_id] = updated
        return updated

    def _verify_binding(
        self,
        *,
        record: ApprovalRecord,
        requester: Principal,
        action: ApprovalAction,
        arguments: Mapping[str, Any],
    ) -> None:
        normalized = _canonicalize(arguments)
        candidate = _binding_hash(
            nonce=record.nonce,
            requester_user_id=requester.user_id,
            tenant_id=requester.tenant_id,
            action=action,
            normalized_arguments_json=normalized,
        )
        if not hmac.compare_digest(candidate, record.binding_hash):
            raise ApprovalBindingError("approval binding mismatch")

    def _require_record(self, approval_id: str) -> ApprovalRecord:
        record = self._records.get(approval_id)
        if record is None:
            raise ApprovalNotFoundError("approval not found")
        return record

    def _expire_if_needed(self, record: ApprovalRecord) -> ApprovalRecord:
        if record.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            if self._clock() >= record.expires_at:
                expired = record.model_copy(update={"status": ApprovalStatus.EXPIRED})
                self._records[record.approval_id] = expired
                return expired
        return record
