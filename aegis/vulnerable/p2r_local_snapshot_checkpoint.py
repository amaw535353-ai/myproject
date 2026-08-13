from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from aegis.effects.control_plane_recovery import CrashSafeControlPlaneCoordinator


class LocalSnapshotGenerationFence:
    policy_version = "p2q-local-generation-only-v1"

    def __init__(self, coordinator: CrashSafeControlPlaneCoordinator) -> None:
        self.coordinator = coordinator

    @contextmanager
    def locked_active_generation(self) -> Iterator[int]:
        with self.coordinator.locked_active_generation() as generation:
            yield generation

    def current_active_generation(self) -> int:
        return self.coordinator.current_active_generation()
