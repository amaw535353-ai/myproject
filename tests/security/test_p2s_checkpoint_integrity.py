"""Defensive P2-S integrity checks for synthetic checkpoint receipts."""

from pathlib import Path

import pytest

from aegis.effects.checkpoint_receipt_boundary import CheckpointReceiptError, CheckpointReceiptReason, Ed25519CheckpointReceiptObserver
from aegis.effects.checkpoint_receipt_models import GENESIS_RECEIPT_PREDECESSOR, checkpoint_receipt_sha256
from evals.p2s_checkpoint_authenticity import _SyntheticCheckpointSigner


def _observer(tmp_path: Path, signer: _SyntheticCheckpointSigner) -> Ed25519CheckpointReceiptObserver:
    return Ed25519CheckpointReceiptObserver(trusted_key=signer.trusted_key(), witness_database_path=tmp_path / "receipt-witness.sqlite3")


def test_valid_receipt_chain_is_accepted_idempotently(tmp_path: Path) -> None:
    signer = _SyntheticCheckpointSigner()
    observer = _observer(tmp_path, signer)
    first = signer.issue(generation=1, journal_head_sha256="1" * 64, previous_receipt_sha256=GENESIS_RECEIPT_PREDECESSOR)
    assert observer.observe(first).generation == 1
    assert observer.observe(first).generation == 1
    second = signer.issue(generation=2, journal_head_sha256="2" * 64, previous_receipt_sha256=checkpoint_receipt_sha256(first))
    assert observer.observe(second).generation == 2


def test_receipt_with_invalid_authentication_is_rejected(tmp_path: Path) -> None:
    signer = _SyntheticCheckpointSigner()
    observer = _observer(tmp_path, signer)
    receipt = signer.issue(generation=1, journal_head_sha256="1" * 64, previous_receipt_sha256=GENESIS_RECEIPT_PREDECESSOR).model_copy(update={"signature_hex": "00" * 64})
    with pytest.raises(CheckpointReceiptError) as exc_info:
        observer.observe(receipt)
    assert exc_info.value.reason is CheckpointReceiptReason.SIGNATURE_INVALID


def test_second_distinct_receipt_for_pinned_generation_is_rejected(tmp_path: Path) -> None:
    signer = _SyntheticCheckpointSigner()
    observer = _observer(tmp_path, signer)
    first = signer.issue(generation=1, journal_head_sha256="1" * 64, previous_receipt_sha256=GENESIS_RECEIPT_PREDECESSOR)
    observer.observe(first)
    predecessor = checkpoint_receipt_sha256(first)
    branch_one = signer.issue(generation=2, journal_head_sha256="2" * 64, previous_receipt_sha256=predecessor)
    branch_two = signer.issue(generation=2, journal_head_sha256="3" * 64, previous_receipt_sha256=predecessor)
    observer.observe(branch_one)
    with pytest.raises(CheckpointReceiptError) as exc_info:
        observer.observe(branch_two)
    assert exc_info.value.reason is CheckpointReceiptReason.EQUIVOCATION_DETECTED


def test_receipt_chain_requires_exact_predecessor(tmp_path: Path) -> None:
    signer = _SyntheticCheckpointSigner()
    observer = _observer(tmp_path, signer)
    first = signer.issue(generation=1, journal_head_sha256="1" * 64, previous_receipt_sha256=GENESIS_RECEIPT_PREDECESSOR)
    observer.observe(first)
    second = signer.issue(generation=2, journal_head_sha256="2" * 64, previous_receipt_sha256="f" * 64)
    with pytest.raises(CheckpointReceiptError) as exc_info:
        observer.observe(second)
    assert exc_info.value.reason is CheckpointReceiptReason.HISTORY_INVALID
