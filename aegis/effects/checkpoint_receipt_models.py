"""Defensive P2-S checkpoint receipt models for the local synthetic lab.

This module contains typed receipt data, canonical hashing, and interfaces only.
It performs no network access and contains no signing secrets or private-key
material. The production-facing security property is fail-closed verification
of checkpoint provenance and history before synthetic authorization effects.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator


CHECKPOINT_RECEIPT_SCHEMA = "aegis.protected-checkpoint-receipt.v1"
CHECKPOINT_RECEIPT_POLICY_VERSION = "signed-predecessor-linked-checkpoint-history-v1"
GENESIS_RECEIPT_PREDECESSOR = "0" * 64


class CheckpointReceiptPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.protected-checkpoint-receipt.v1"] = CHECKPOINT_RECEIPT_SCHEMA
    authority_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    key_id: str = Field(min_length=1, max_length=128)
    key_epoch: int = Field(ge=1)
    generation: int = Field(ge=1)
    journal_head_sha256: str = Field(min_length=64, max_length=64)
    previous_receipt_sha256: str = Field(min_length=64, max_length=64)

    @field_validator("journal_head_sha256", "previous_receipt_sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("checkpoint receipt hashes must be lowercase SHA-256 hex") from exc
        if len(decoded) != 32 or value != value.lower():
            raise ValueError("checkpoint receipt hashes must be lowercase SHA-256 hex")
        return value


class AuthenticatedCheckpointReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: CheckpointReceiptPayload
    signature_hex: str = Field(min_length=128, max_length=128)

    @field_validator("signature_hex")
    @classmethod
    def _validate_signature(cls, value: str) -> str:
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("checkpoint signature must be lowercase Ed25519 hex") from exc
        if len(decoded) != 64 or value != value.lower():
            raise ValueError("checkpoint signature must be lowercase Ed25519 hex")
        return value


class TrustedCheckpointReceiptKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    key_id: str = Field(min_length=1, max_length=128)
    key_epoch: int = Field(ge=1)
    public_key_hex: str = Field(min_length=64, max_length=64)

    @field_validator("public_key_hex")
    @classmethod
    def _validate_public_key(cls, value: str) -> str:
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("checkpoint public key must be lowercase Ed25519 hex") from exc
        if len(decoded) != 32 or value != value.lower():
            raise ValueError("checkpoint public key must be lowercase Ed25519 hex")
        return value


def canonical_checkpoint_payload(payload: CheckpointReceiptPayload) -> bytes:
    return json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def checkpoint_receipt_sha256(receipt: AuthenticatedCheckpointReceipt) -> str:
    serialized = json.dumps(
        {
            "payload": receipt.payload.model_dump(mode="json"),
            "signature_hex": receipt.signature_hex,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class CheckpointReceiptObserver(Protocol):
    policy_version: str

    def observe(self, receipt: AuthenticatedCheckpointReceipt) -> CheckpointReceiptPayload: ...


class CheckpointReceiptSource(Protocol):
    def current(self) -> AuthenticatedCheckpointReceipt: ...


class SyntheticCheckpointReceiptSource:
    """Deterministic in-memory stand-in for a protected receipt endpoint."""

    def __init__(self, receipt: AuthenticatedCheckpointReceipt) -> None:
        self._receipt = receipt

    def set_current(self, receipt: AuthenticatedCheckpointReceipt) -> None:
        self._receipt = receipt

    def current(self) -> AuthenticatedCheckpointReceipt:
        return self._receipt
