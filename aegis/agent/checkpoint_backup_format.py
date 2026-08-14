from __future__ import annotations

import hashlib
import hmac
import json
from enum import StrEnum
from typing import Any

from aegis.agent.checkpoint_runtime_contracts import (
    CheckpointBackupAuthenticationOperationProvider,
)


P4E_CHECKPOINT_BACKUP_POLICY_VERSION = "authenticated-checkpoint-backup-restore-v1"
P4E_BACKUP_SCHEMA = "aegis.agent-checkpoint-backup.v1"
P4E_LOCAL_BACKUP_KEY_ID = "local-synthetic-agent-checkpoint-backup-hmac-v1"
P4E_LOCAL_BACKUP_KEY = hashlib.sha256(
    b"aegisdesk-local-checkpoint-backup-key-v1-2026"
).digest()
P4E_MAX_PACKAGE_BYTES = 64 * 1024 * 1024


class CheckpointBackupReason(StrEnum):
    PACKAGE_INVALID = "checkpoint_backup_package_invalid"
    AUTHENTICATION_FAILED = "checkpoint_backup_authentication_failed"
    ACTIVE_KEY_MISMATCH = "checkpoint_backup_active_key_mismatch"
    NON_ACTIVE_CIPHERTEXT = "checkpoint_backup_non_active_ciphertext"
    ROLLBACK_DETECTED = "checkpoint_backup_rollback_detected"
    FORK_DETECTED = "checkpoint_backup_fork_detected"
    RECOVERY_AUTHORIZATION_DENIED = "checkpoint_backup_recovery_authorization_denied"
    VALIDATION_FAILED = "checkpoint_backup_validation_failed"


class CheckpointBackupError(RuntimeError):
    def __init__(self, reason: CheckpointBackupReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sign_package(
    body: dict[str, Any],
    *,
    key: bytes | None = None,
    provider: CheckpointBackupAuthenticationOperationProvider | None = None,
) -> bytes:
    payload = canonical_json(body)
    if provider is not None:
        tag = provider.authenticate(payload)
    elif key is not None:
        tag = hmac.new(bytes(key), payload, hashlib.sha256).hexdigest()
    else:
        raise ValueError("checkpoint backup authentication provider or key is required")
    package = canonical_json({**body, "authentication_tag": tag})
    if len(package) > P4E_MAX_PACKAGE_BYTES:
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID)
    return package


def open_package(
    package: bytes,
    *,
    key: bytes | None = None,
    provider: CheckpointBackupAuthenticationOperationProvider | None = None,
) -> dict[str, Any]:
    if len(package) > P4E_MAX_PACKAGE_BYTES:
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID)
    try:
        parsed = json.loads(package)
    except Exception as exc:
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID) from exc
    if not isinstance(parsed, dict):
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID)
    observed = parsed.pop("authentication_tag", None)
    payload = canonical_json(parsed)
    if not isinstance(observed, str):
        raise CheckpointBackupError(CheckpointBackupReason.AUTHENTICATION_FAILED)
    if provider is not None:
        try:
            provider.verify_or_raise(payload, observed)
        except Exception as exc:
            raise CheckpointBackupError(
                CheckpointBackupReason.AUTHENTICATION_FAILED
            ) from exc
    elif key is not None:
        expected = hmac.new(bytes(key), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(observed, expected):
            raise CheckpointBackupError(CheckpointBackupReason.AUTHENTICATION_FAILED)
    else:
        raise ValueError("checkpoint backup authentication provider or key is required")
    return parsed
