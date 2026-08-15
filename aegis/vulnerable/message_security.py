from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableMessageDecision:
    accepted: bool
    denied_count: int


class VulnerableDeclaredMessageSafety:
    """Intentionally weak baseline trusting caller-owned message safety summaries."""

    def evaluate(
        self,
        *,
        declared_authenticated: bool,
        declared_channel_authorized: bool,
        declared_replay_free: bool,
        declared_denied_count: int,
    ) -> VulnerableMessageDecision:
        return VulnerableMessageDecision(
            accepted=bool(
                declared_authenticated
                and declared_channel_authorized
                and declared_replay_free
                and declared_denied_count == 0
            ),
            denied_count=declared_denied_count,
        )
