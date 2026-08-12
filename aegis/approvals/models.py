from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ApprovalAction(StrEnum):
    REQUEST_ACCESS = "request_access"
    REQUEST_PASSWORD_RESET = "request_password_reset"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ApprovalRecord(BaseModel):
    """Server-owned approval state. Never expose nonce or binding_hash to the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str
    nonce: str
    requester_user_id: str
    tenant_id: str
    action: ApprovalAction
    normalized_arguments_json: str
    binding_hash: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    approver_user_id: str | None = None
    decided_at: datetime | None = None
    consumed_at: datetime | None = None


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ApprovalDecision
