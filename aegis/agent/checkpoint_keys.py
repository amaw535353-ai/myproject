from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


P4D_CHECKPOINT_KEY_LIFECYCLE_POLICY_VERSION = "checkpoint-key-lifecycle-migration-v1"
CHECKPOINT_CIPHERTEXT_MAGIC = b"AEGIS-P4C-AESGCM-v1\x00"
P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID = "local-synthetic-agent-checkpoint-aesgcm-v1"
P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID = "local-synthetic-agent-checkpoint-aesgcm-v2"
P4D_LOCAL_SYNTHETIC_LEGACY_KEY = hashlib.sha256(
    b"aegisdesk-local-synthetic-agent-checkpoint-aead-key-v1-2026"
).digest()
P4D_LOCAL_SYNTHETIC_ACTIVE_KEY = hashlib.sha256(
    b"aegisdesk-local-synthetic-agent-checkpoint-aead-key-v2-2026"
).digest()
_NONCE_BYTES = 12


class CheckpointConfidentialityReason(StrEnum):
    CIPHERTEXT_ENVELOPE_INVALID = "checkpoint_ciphertext_envelope_invalid"
    ENCRYPTION_KEY_MISMATCH = "checkpoint_encryption_key_mismatch"
    UNKNOWN_ENCRYPTION_KEY = "checkpoint_unknown_encryption_key"
    REVOKED_ENCRYPTION_KEY = "checkpoint_revoked_encryption_key"
    DECRYPTION_FAILED = "checkpoint_decryption_failed"
    SENSITIVE_METADATA_REJECTED = "checkpoint_sensitive_metadata_rejected"


class CheckpointConfidentialityError(RuntimeError):
    def __init__(self, reason: CheckpointConfidentialityReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class CheckpointKeyState(StrEnum):
    ACTIVE = "active"
    DECRYPT_ONLY = "decrypt_only"
    REVOKED = "revoked"


@dataclass(frozen=True)
class LocalSyntheticCheckpointKey:
    key_id: str
    key: bytes
    state: CheckpointKeyState


@dataclass(frozen=True)
class CheckpointKeyMigrationReport:
    active_key_id: str
    checkpoints_reencrypted: int
    writes_reencrypted: int
    checkpoints_examined: int
    writes_examined: int


@runtime_checkable
class CheckpointEncryptionKeyProvider(Protocol):
    active_key_id: str
    provider_id: str
    external_key_custody: bool

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes: ...

    def decrypt(self, envelope: bytes, *, aad: bytes) -> bytes: ...

    def envelope_key_id(self, envelope: bytes) -> str: ...

    def key_state(self, key_id: str) -> CheckpointKeyState | None: ...


class LocalSyntheticCheckpointKeyProvider:
    """Versioned local AES-256-GCM key provider for deterministic lab use only."""

    provider_id = "local-synthetic-checkpoint-keyring"
    external_key_custody = False

    def __init__(
        self,
        *,
        active_key_id: str,
        keys: Mapping[str, LocalSyntheticCheckpointKey],
    ) -> None:
        copied = dict(keys)
        if active_key_id not in copied:
            raise ValueError("active checkpoint encryption key is missing")
        active = copied[active_key_id]
        if active.state is not CheckpointKeyState.ACTIVE:
            raise ValueError("active checkpoint encryption key must be ACTIVE")
        for key_id, material in copied.items():
            if key_id != material.key_id:
                raise ValueError("checkpoint encryption key id mapping mismatch")
            if len(material.key) != 32:
                raise ValueError("checkpoint AES-GCM keys must be exactly 32 bytes")
            if key_id != active_key_id and material.state is CheckpointKeyState.ACTIVE:
                raise ValueError("checkpoint keyring may contain only one ACTIVE key")
            encoded = key_id.encode("utf-8", "strict")
            if not encoded or len(encoded) > 65535:
                raise ValueError("checkpoint encryption key id length is invalid")
        self.active_key_id = active_key_id
        self._keys = copied

    def key_state(self, key_id: str) -> CheckpointKeyState | None:
        material = self._keys.get(str(key_id))
        return None if material is None else material.state

    @staticmethod
    def _parse_envelope(envelope: bytes) -> tuple[str, bytes, bytes]:
        raw = bytes(envelope)
        if not raw.startswith(CHECKPOINT_CIPHERTEXT_MAGIC):
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID
            )
        offset = len(CHECKPOINT_CIPHERTEXT_MAGIC)
        if len(raw) < offset + 2:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID
            )
        key_id_length = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        minimum_length = offset + key_id_length + _NONCE_BYTES + 16
        if key_id_length <= 0 or len(raw) < minimum_length:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID
            )
        try:
            key_id = raw[offset : offset + key_id_length].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID
            ) from exc
        offset += key_id_length
        nonce = raw[offset : offset + _NONCE_BYTES]
        ciphertext = raw[offset + _NONCE_BYTES :]
        return key_id, nonce, ciphertext

    def envelope_key_id(self, envelope: bytes) -> str:
        key_id, _, _ = self._parse_envelope(envelope)
        return key_id

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        material = self._keys[self.active_key_id]
        key_id_bytes = material.key_id.encode("utf-8", "strict")
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(material.key).encrypt(nonce, bytes(plaintext), aad)
        return (
            CHECKPOINT_CIPHERTEXT_MAGIC
            + len(key_id_bytes).to_bytes(2, "big")
            + key_id_bytes
            + nonce
            + ciphertext
        )

    def decrypt(self, envelope: bytes, *, aad: bytes) -> bytes:
        key_id, nonce, ciphertext = self._parse_envelope(envelope)
        material = self._keys.get(key_id)
        if material is None:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.UNKNOWN_ENCRYPTION_KEY
            )
        if material.state is CheckpointKeyState.REVOKED:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.REVOKED_ENCRYPTION_KEY
            )
        try:
            return AESGCM(material.key).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.DECRYPTION_FAILED
            ) from exc


def build_legacy_single_key_provider(
    *,
    key: bytes = P4D_LOCAL_SYNTHETIC_LEGACY_KEY,
    key_id: str = P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID,
) -> LocalSyntheticCheckpointKeyProvider:
    return LocalSyntheticCheckpointKeyProvider(
        active_key_id=key_id,
        keys={
            key_id: LocalSyntheticCheckpointKey(
                key_id=key_id,
                key=bytes(key),
                state=CheckpointKeyState.ACTIVE,
            )
        },
    )


def build_default_local_synthetic_checkpoint_key_provider() -> LocalSyntheticCheckpointKeyProvider:
    return LocalSyntheticCheckpointKeyProvider(
        active_key_id=P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
        keys={
            P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID: LocalSyntheticCheckpointKey(
                key_id=P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
                key=P4D_LOCAL_SYNTHETIC_ACTIVE_KEY,
                state=CheckpointKeyState.ACTIVE,
            ),
            P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID: LocalSyntheticCheckpointKey(
                key_id=P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID,
                key=P4D_LOCAL_SYNTHETIC_LEGACY_KEY,
                state=CheckpointKeyState.DECRYPT_ONLY,
            ),
        },
    )
