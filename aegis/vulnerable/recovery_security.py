from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableDeclaredRecoverySafety:
    checkpoint_trusted: bool = True
    persistence_safe: bool = True
    recovery_authorized: bool = True
    quarantined_item_count: int = 0
    revoked_item_count: int = 0
    denied_recovery_count: int = 0

    def accepts(self) -> bool:
        return self.checkpoint_trusted and self.persistence_safe and self.recovery_authorized and self.denied_recovery_count == 0
