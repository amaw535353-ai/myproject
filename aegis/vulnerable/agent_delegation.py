from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableDelegationDecision:
    accepted: bool
    denied_count: int
    escalation_count: int


class VulnerableDeclaredDelegationAuthorization:
    """Intentionally weak baseline trusting caller-owned delegation authorization summaries."""

    def evaluate(
        self,
        *,
        declared_delegation_authorized: bool,
        declared_identity_continuity: bool,
        declared_tenant_continuity: bool,
        declared_denied_count: int,
        declared_escalation_count: int,
    ) -> VulnerableDelegationDecision:
        return VulnerableDelegationDecision(
            accepted=bool(
                declared_delegation_authorized
                and declared_identity_continuity
                and declared_tenant_continuity
                and declared_denied_count == 0
                and declared_escalation_count == 0
            ),
            denied_count=declared_denied_count,
            escalation_count=declared_escalation_count,
        )
