from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableHumanApprovalDecision:
    accepted: bool
    approved_count: int
    denied_count: int


class VulnerableDeclaredHumanApprovalSafety:
    """Intentionally weak baseline trusting caller-owned human-approval summaries."""

    def evaluate(self, *, declared_approval_present: bool, declared_approval_fresh: bool, declared_action_unchanged: bool, declared_approved_count: int, declared_denied_count: int) -> VulnerableHumanApprovalDecision:
        return VulnerableHumanApprovalDecision(
            accepted=bool(declared_approval_present and declared_approval_fresh and declared_action_unchanged and declared_approved_count > 0 and declared_denied_count == 0),
            approved_count=declared_approved_count,
            denied_count=declared_denied_count,
        )
