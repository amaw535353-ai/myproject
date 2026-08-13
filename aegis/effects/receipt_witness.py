"""Defensive local witness for P2-S synthetic checkpoint receipts.

A trusted verifier callback decides whether a receipt is authentic. This class
then records one accepted receipt hash per generation and rejects conflicting
history. It is a fail-closed integrity primitive for the local test lab only.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from aegis.effects.checkpoint_receipt_models import (
    GENESIS_RECEIPT_PREDECESSOR,
    AuthenticatedCheckpointReceipt,
    checkpoint_receipt_sha256,
)


class ReceiptWitnessError(RuntimeError):
    pass


class ReceiptWitness:
    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS receipt_witness (
                    generation INTEGER PRIMARY KEY,
                    receipt_sha256 TEXT NOT NULL
                )
                """
            )

    def observe(self, receipt: AuthenticatedCheckpointReceipt, *, authentic: bool) -> str:
        if not authentic:
            raise ReceiptWitnessError("receipt_authentication_failed")
        receipt_hash = checkpoint_receipt_sha256(receipt)
        generation = receipt.payload.generation
        with sqlite3.connect(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            same = connection.execute(
                "SELECT receipt_sha256 FROM receipt_witness WHERE generation = ?",
                (generation,),
            ).fetchone()
            if same is not None:
                if str(same[0]) != receipt_hash:
                    raise ReceiptWitnessError("receipt_equivocation_detected")
                return receipt_hash
            previous = connection.execute(
                "SELECT generation, receipt_sha256 FROM receipt_witness ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            if previous is None:
                if generation != 1 or receipt.payload.previous_receipt_sha256 != GENESIS_RECEIPT_PREDECESSOR:
                    raise ReceiptWitnessError("receipt_history_invalid")
            else:
                if generation != int(previous[0]) + 1:
                    raise ReceiptWitnessError("receipt_history_invalid")
                if receipt.payload.previous_receipt_sha256 != str(previous[1]):
                    raise ReceiptWitnessError("receipt_history_invalid")
            connection.execute(
                "INSERT INTO receipt_witness (generation, receipt_sha256) VALUES (?, ?)",
                (generation, receipt_hash),
            )
        return receipt_hash
