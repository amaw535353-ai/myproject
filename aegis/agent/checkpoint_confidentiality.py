from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    get_checkpoint_metadata,
)

from aegis.agent.checkpoint_durability import (
    P4B_LOCAL_SYNTHETIC_HMAC_KEY,
    P4B_LOCAL_SYNTHETIC_KEY_ID,
    CheckpointIntegrityError,
    CheckpointIntegrityReason,
    DurableIntegrityCheckpointer,
)


P4C_CHECKPOINT_CONFIDENTIALITY_POLICY_VERSION = (
    "durable-checkpoint-aead-secret-minimization-v1"
)
P4C_LOCAL_SYNTHETIC_ENCRYPTION_KEY_ID = "local-synthetic-agent-checkpoint-aesgcm-v1"
P4C_LOCAL_SYNTHETIC_AESGCM_KEY = hashlib.sha256(
    b"aegisdesk-local-synthetic-agent-checkpoint-aead-key-v1-2026"
).digest()
P4C_CIPHERTEXT_MAGIC = b"AEGIS-P4C-AESGCM-v1\x00"
_P4C_NONCE_BYTES = 12
_P4C_TYPED_AAD_PREFIX = b"aegisdesk-agent-checkpoint-serde-v1:"
_P4C_RAW_AAD = b"aegisdesk-agent-checkpoint-serde-v1:raw"
_SENSITIVE_METADATA_KEY_FRAGMENTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
    "prompt",
    "message",
    "content",
    "arguments",
    "tool_result",
)


class CheckpointConfidentialityReason(StrEnum):
    CIPHERTEXT_ENVELOPE_INVALID = "checkpoint_ciphertext_envelope_invalid"
    ENCRYPTION_KEY_MISMATCH = "checkpoint_encryption_key_mismatch"
    DECRYPTION_FAILED = "checkpoint_decryption_failed"
    SENSITIVE_METADATA_REJECTED = "checkpoint_sensitive_metadata_rejected"


class CheckpointConfidentialityError(RuntimeError):
    def __init__(self, reason: CheckpointConfidentialityReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def _typed_aad(type_tag: str) -> bytes:
    return _P4C_TYPED_AAD_PREFIX + type_tag.encode("utf-8", "strict")


def _assert_metadata_minimized(value: object) -> None:
    """Reject metadata key names that should stay inside encrypted graph state.

    This is a structural minimization guard, not a general-purpose DLP scanner.
    LangGraph control metadata remains plaintext for indexing and diagnostics,
    while content-bearing application state must stay in encrypted checkpoint or
    pending-write payloads.
    """

    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).casefold()
            if any(fragment in key for fragment in _SENSITIVE_METADATA_KEY_FRAGMENTS):
                raise CheckpointConfidentialityError(
                    CheckpointConfidentialityReason.SENSITIVE_METADATA_REJECTED
                )
            _assert_metadata_minimized(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_metadata_minimized(child)


class LocalSyntheticCheckpointCipher:
    """Local AES-256-GCM provider used only by the synthetic/default lab runtime."""

    def __init__(
        self,
        *,
        key: bytes = P4C_LOCAL_SYNTHETIC_AESGCM_KEY,
        key_id: str = P4C_LOCAL_SYNTHETIC_ENCRYPTION_KEY_ID,
    ) -> None:
        if len(key) != 32:
            raise ValueError("checkpoint AES-GCM key must be exactly 32 bytes")
        key_id_bytes = key_id.encode("utf-8", "strict")
        if not key_id_bytes or len(key_id_bytes) > 65535:
            raise ValueError("checkpoint encryption key id length is invalid")
        self._aead = AESGCM(bytes(key))
        self.key_id = key_id
        self._key_id_bytes = key_id_bytes

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        nonce = os.urandom(_P4C_NONCE_BYTES)
        ciphertext = self._aead.encrypt(nonce, bytes(plaintext), aad)
        return (
            P4C_CIPHERTEXT_MAGIC
            + len(self._key_id_bytes).to_bytes(2, "big")
            + self._key_id_bytes
            + nonce
            + ciphertext
        )

    def decrypt(self, envelope: bytes, *, aad: bytes) -> bytes:
        raw = bytes(envelope)
        if not raw.startswith(P4C_CIPHERTEXT_MAGIC):
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID
            )
        offset = len(P4C_CIPHERTEXT_MAGIC)
        if len(raw) < offset + 2:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID
            )
        key_id_length = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        minimum_length = offset + key_id_length + _P4C_NONCE_BYTES + 16
        if key_id_length <= 0 or len(raw) < minimum_length:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID
            )
        observed_key_id = raw[offset : offset + key_id_length]
        offset += key_id_length
        if not hmac.compare_digest(observed_key_id, self._key_id_bytes):
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.ENCRYPTION_KEY_MISMATCH
            )
        nonce = raw[offset : offset + _P4C_NONCE_BYTES]
        ciphertext = raw[offset + _P4C_NONCE_BYTES :]
        try:
            return self._aead.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise CheckpointConfidentialityError(
                CheckpointConfidentialityReason.DECRYPTION_FAILED
            ) from exc


class _AeadCheckpointSerializer:
    def __init__(self, *, inner: Any, cipher: LocalSyntheticCheckpointCipher) -> None:
        self._inner = inner
        self._cipher = cipher

    def dumps_typed(self, obj: Any) -> tuple[str, bytes]:
        type_tag, blob = self._inner.dumps_typed(obj)
        resolved_type = str(type_tag)
        return resolved_type, self._cipher.encrypt(
            bytes(blob),
            aad=_typed_aad(resolved_type),
        )

    def loads_typed(self, data: tuple[str, bytes]) -> Any:
        type_tag, envelope = data
        resolved_type = str(type_tag)
        plaintext = self._cipher.decrypt(
            bytes(envelope),
            aad=_typed_aad(resolved_type),
        )
        return self._inner.loads_typed((resolved_type, plaintext))

    def dumps(self, obj: Any) -> bytes:
        return self._cipher.encrypt(bytes(self._inner.dumps(obj)), aad=_P4C_RAW_AAD)

    def loads(self, data: bytes) -> Any:
        return self._inner.loads(self._cipher.decrypt(bytes(data), aad=_P4C_RAW_AAD))


class ConfidentialDurableIntegrityCheckpointer(DurableIntegrityCheckpointer):
    """P4-A/P4-B saver with encrypted payloads and metadata minimization.

    Dynamic checkpoint state and pending writes are AES-256-GCM encrypted before
    they reach SQLite. P4-B then authenticates the ciphertext and monotonic chain,
    so tampering and rollback checks remain intact. Structural SQLite columns and
    LangGraph control metadata remain plaintext by design. Existing plaintext P4-B
    rows are never silently accepted as P4-C ciphertext.

    The default key is local synthetic material embedded for deterministic $0 CI.
    This is not external KMS/HSM custody and is not a production confidentiality
    claim.
    """

    policy_version = P4C_CHECKPOINT_CONFIDENTIALITY_POLICY_VERSION

    def __init__(
        self,
        *,
        database_path: Path,
        anchor_database_path: Path,
        hmac_key: bytes = P4B_LOCAL_SYNTHETIC_HMAC_KEY,
        key_id: str = P4B_LOCAL_SYNTHETIC_KEY_ID,
        encryption_key: bytes = P4C_LOCAL_SYNTHETIC_AESGCM_KEY,
        encryption_key_id: str = P4C_LOCAL_SYNTHETIC_ENCRYPTION_KEY_ID,
    ) -> None:
        self._cipher = LocalSyntheticCheckpointCipher(
            key=encryption_key,
            key_id=encryption_key_id,
        )
        self.encryption_key_id = encryption_key_id
        super().__init__(
            database_path=database_path,
            anchor_database_path=anchor_database_path,
            hmac_key=hmac_key,
            key_id=key_id,
        )
        self._plaintext_serde = self.serde
        self.serde = _AeadCheckpointSerializer(
            inner=self._plaintext_serde,
            cipher=self._cipher,
        )

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        _assert_metadata_minimized(metadata)
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        checkpoint_id = str(checkpoint["id"])
        parent_checkpoint_id = config["configurable"].get("checkpoint_id")
        if parent_checkpoint_id is not None:
            parent_checkpoint_id = str(parent_checkpoint_id)

        new_type_tag, new_plaintext_blob = self._plaintext_serde.dumps_typed(checkpoint)
        metadata_blob = json.dumps(
            get_checkpoint_metadata(config, metadata),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "ignore")

        with self._lock:
            with self._connect(self.database_path) as connection:
                existing = self._checkpoint_row(
                    connection,
                    thread_id=thread_id,
                    checkpoint_ns=checkpoint_ns,
                    checkpoint_id=checkpoint_id,
                )
            if existing is not None:
                self._verify_checkpoint_row(existing)
                existing_type = str(existing["type"])
                same_type = existing_type == str(new_type_tag)
                existing_plaintext = (
                    self._cipher.decrypt(
                        bytes(existing["checkpoint"]),
                        aad=_typed_aad(existing_type),
                    )
                    if same_type
                    else b""
                )
                existing_parent = (
                    None
                    if existing["parent_checkpoint_id"] is None
                    else str(existing["parent_checkpoint_id"])
                )
                if (
                    same_type
                    and existing_plaintext == bytes(new_plaintext_blob)
                    and bytes(existing["metadata"]) == metadata_blob
                    and existing_parent == parent_checkpoint_id
                ):
                    return {
                        "configurable": {
                            "thread_id": thread_id,
                            "checkpoint_ns": checkpoint_ns,
                            "checkpoint_id": checkpoint_id,
                        }
                    }
                raise CheckpointIntegrityError(
                    CheckpointIntegrityReason.CHECKPOINT_CONFLICT
                )

            return super().put(config, checkpoint, metadata, new_versions)
