from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Role(StrEnum):
    EMPLOYEE = "employee"
    SUPPORT_ANALYST = "support_analyst"
    ADMIN_APPROVER = "admin_approver"
    ATTACKER = "attacker"


class Principal(BaseModel):
    """Trusted server-side identity presented to authorization-sensitive services."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: str
    tenant_id: str
    roles: frozenset[Role]
