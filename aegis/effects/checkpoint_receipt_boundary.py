"""Defensive P2-S checkpoint receipt validation for the local synthetic lab.

Only public verification material is used here. The boundary verifies a signed
checkpoint receipt, pins the accepted predecessor-linked history in a separate
local witness, and then binds that receipt to the current P2-Q generation and
canonical journal head before any synthetic authorization effect can proceed.
"""

from __future__ import annotations

from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis.effects.checkpoint_receipt_models import (
    CHECKPOINT_RECEIPT_POLICY_VERSION,
    AuthenticatedCheckpointReceipt,
    CheckpointReceiptObserver,
    CheckpointReceiptPayload,
    CheckpointReceiptSource,
    TrustedCheckpointReceiptKey,
    canonical_checkpoint_payload,
)
from aegis.effects.control_plane_recovery import (
    ControlPlaneConvergenceError,
    CrashSafeControlPlaneCoordinator,
)
from aegis.effects.durable import SyntheticEffectExecution, SyntheticWorkerCrash
from aegis.effects.protected_checkpoint import (
    CheckpointBoundAuthorizationReplica,
    CheckpointBoundSyntheticEffectService,
    ProtectedCheckpointError,
    active_journal_heads,
)
from aegis.effects.receipt_witness import ReceiptWitness, ReceiptWitnessError
from aegis.effects.revalidation import RevalidatingEffectOutboxStore
from aegis.effects.rollback_anchor import RollbackAnchorError, RollbackAnchorReason
from aegis.effects.signed_authorization import AuthorizationProvenanceError


class CheckpointReceiptReason(StrEnum):
    AUTHORITY_MISMATCH = "checkpoint_receipt_authority_mismatch"
    AUDIENCE_MISMATCH = "checkpoint_receipt_audience_mismatch"
    KEY_MISMATCH = "checkpoint_receipt_key_mismatch"
    SIGNATURE_INVALID = "checkpoint_receipt_signature_invalid"
    HISTORY_INVALID = "checkpoint_receipt_history_invalid"
    EQUIVOCATION_DETECTED = "checkpoint_receipt_equivocation_detected"
    LOCAL_GENERATION_MISMATCH = "checkpoint_receipt_local_generation_mismatch"
    LOCAL_JOURNAL_HEAD_MISMATCH = "checkpoint_receipt_local_journal_head_mismatch"


class CheckpointReceiptError(RuntimeError):
    def __init__(self, reason: CheckpointReceiptReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class Ed25519CheckpointReceiptObserver:
    """Authenticates receipts with a configured public key and pins their history."""

    policy_version = CHECKPOINT_RECEIPT_POLICY_VERSION

    def __init__(
        self,
        *,
        trusted_key: TrustedCheckpointReceiptKey,
        witness_database_path: Path,
    ) -> None:
        self.trusted_key = trusted_key
        self._public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_key.public_key_hex))
        self._witness = ReceiptWitness(witness_database_path)

    def observe(self, receipt: AuthenticatedCheckpointReceipt) -> CheckpointReceiptPayload:
        payload = receipt.payload
        if payload.authority_id != self.trusted_key.authority_id:
            raise CheckpointReceiptError(CheckpointReceiptReason.AUTHORITY_MISMATCH)
        if payload.audience != self.trusted_key.audience:
            raise CheckpointReceiptError(CheckpointReceiptReason.AUDIENCE_MISMATCH)
        if payload.key_id != self.trusted_key.key_id or payload.key_epoch != self.trusted_key.key_epoch:
            raise CheckpointReceiptError(CheckpointReceiptReason.KEY_MISMATCH)
        authentic = True
        try:
            self._public_key.verify(
                bytes.fromhex(receipt.signature_hex),
                canonical_checkpoint_payload(payload),
            )
        except InvalidSignature:
            authentic = False
        try:
            self._witness.observe(receipt, authentic=authentic)
        except ReceiptWitnessError as exc:
            if str(exc) == "receipt_authentication_failed":
                raise CheckpointReceiptError(CheckpointReceiptReason.SIGNATURE_INVALID) from exc
            if str(exc) == "receipt_equivocation_detected":
                raise CheckpointReceiptError(CheckpointReceiptReason.EQUIVOCATION_DETECTED) from exc
            raise CheckpointReceiptError(CheckpointReceiptReason.HISTORY_INVALID) from exc
        return payload


class CheckpointReceiptGenerationFence:
    """Requires verified receipt state to equal the local active control-plane state."""

    policy_version = CHECKPOINT_RECEIPT_POLICY_VERSION

    def __init__(
        self,
        *,
        local_coordinator: CrashSafeControlPlaneCoordinator,
        receipt_source: CheckpointReceiptSource,
        receipt_observer: CheckpointReceiptObserver,
    ) -> None:
        self.local_coordinator = local_coordinator
        self.receipt_source = receipt_source
        self.receipt_observer = receipt_observer
        self.authority_id = local_coordinator.authority_id

    @contextmanager
    def locked_active_generation(self) -> Iterator[int]:
        with self.local_coordinator.locked_active_generation() as local_generation:
            heads = active_journal_heads(
                generation_store=self.local_coordinator.generation_store,
                authority_id=self.authority_id,
                current_generation=local_generation,
            )
            payload = self.receipt_observer.observe(self.receipt_source.current())
            if payload.generation != local_generation:
                raise CheckpointReceiptError(CheckpointReceiptReason.LOCAL_GENERATION_MISMATCH)
            if payload.journal_head_sha256 != heads[local_generation]:
                raise CheckpointReceiptError(CheckpointReceiptReason.LOCAL_JOURNAL_HEAD_MISMATCH)
            yield local_generation

    def current_active_generation(self) -> int:
        with self.locked_active_generation() as generation:
            return generation


class AuthenticatedCheckpointDurableEffectWorker:
    """At-least-once worker with terminal handling for invalid checkpoint receipts."""

    def __init__(
        self,
        *,
        outbox_store: RevalidatingEffectOutboxStore,
        effect_service: CheckpointBoundSyntheticEffectService,
        authorization_replica: CheckpointBoundAuthorizationReplica,
        crash_after_effect_once: bool = False,
    ) -> None:
        self._outbox_store = outbox_store
        self._effect_service = effect_service
        self._authorization_replica = authorization_replica
        self._crash_after_effect_once = crash_after_effect_once

    def deliver(self, approval_id: str) -> SyntheticEffectExecution:
        current = self._outbox_store.get(approval_id)
        if current.status == "cancelled":
            raise RollbackAnchorError(RollbackAnchorReason.OUTBOX_CANCELLED)
        record = self._outbox_store.begin_delivery(approval_id)
        try:
            envelope = self._authorization_replica.evaluate(record)
            execution = self._effect_service.execute_with_anchored_decision(record, envelope)
        except (ControlPlaneConvergenceError, ProtectedCheckpointError):
            raise
        except CheckpointReceiptError:
            self._outbox_store.cancel(
                approval_id=approval_id,
                idempotency_key=record.idempotency_key,
            )
            raise
        except (RollbackAnchorError, AuthorizationProvenanceError):
            self._outbox_store.cancel(
                approval_id=approval_id,
                idempotency_key=record.idempotency_key,
            )
            raise
        if self._crash_after_effect_once:
            self._crash_after_effect_once = False
            raise SyntheticWorkerCrash("synthetic crash after effect before outbox acknowledgement")
        self._outbox_store.complete(
            approval_id=approval_id,
            idempotency_key=record.idempotency_key,
        )
        return execution
