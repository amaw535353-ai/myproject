from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


P4H_CHECKPOINT_RUNTIME_PROVIDER_POLICY_VERSION = (
    "checkpoint-runtime-operation-provider-seam-v1"
)


@dataclass(frozen=True)
class CheckpointAnchorHead:
    generation: int
    checkpoint_id: str
    checkpoint_digest: str

    def __getitem__(self, key: str) -> object:
        return getattr(self, key)


@dataclass(frozen=True)
class CheckpointWriteHead:
    write_count: int
    aggregate_digest: str

    def __getitem__(self, key: str) -> object:
        return getattr(self, key)


@dataclass(frozen=True)
class RecoveryAuthorizationRequest:
    request_id: str
    operator_id: str
    backup_authenticated: bool
    monotonic_anchor_verified: bool


@runtime_checkable
class CheckpointIntegrityOperationProvider(Protocol):
    provider_id: str
    external_key_custody: bool
    synthetic_in_process: bool
    operationally_external: bool

    def authenticate(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, authenticator: str) -> bool: ...


@runtime_checkable
class CheckpointAnchorOperationProvider(Protocol):
    provider_id: str
    synthetic_in_process: bool
    operationally_external: bool

    def current_head(self, scope: str) -> CheckpointAnchorHead | None: ...

    def advance(
        self,
        scope: str,
        *,
        generation: int,
        checkpoint_id: str,
        checkpoint_digest: str,
        expected_generation: int | None,
    ) -> CheckpointAnchorHead: ...

    def current_write_head(
        self,
        scope: str,
        checkpoint_id: str,
    ) -> CheckpointWriteHead | None: ...

    def set_write_head(
        self,
        scope: str,
        *,
        checkpoint_id: str,
        write_count: int,
        aggregate_digest: str,
    ) -> CheckpointWriteHead: ...

    def delete_thread(self, thread_id: str) -> None: ...


@runtime_checkable
class SnapshotCapableCheckpointAnchorProvider(
    CheckpointAnchorOperationProvider,
    Protocol,
):
    database_path: Path

    def snapshot_to(self, destination: Path) -> None: ...

    def export_heads(self) -> tuple[dict[str, object], ...]: ...


@runtime_checkable
class CheckpointBackupAuthenticationOperationProvider(Protocol):
    provider_id: str
    external_key_custody: bool
    synthetic_in_process: bool
    operationally_external: bool

    def authenticate(self, payload: bytes) -> str: ...

    def verify_or_raise(self, payload: bytes, authenticator: str) -> None: ...


@runtime_checkable
class CheckpointRecoveryAuthorityOperationProvider(Protocol):
    provider_id: str
    synthetic_in_process: bool
    operationally_external: bool

    def authorize_restore(self, request: RecoveryAuthorizationRequest) -> None: ...
