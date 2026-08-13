from __future__ import annotations

import hmac
import sqlite3
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_backup_format import (
    CheckpointBackupError,
    CheckpointBackupReason,
)
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer


def snapshot_sqlite(source: Path, destination: Path) -> None:
    source_connection = sqlite3.connect(source, timeout=5.0)
    destination_connection = sqlite3.connect(destination, timeout=5.0)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


def read_heads(anchor_path: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(anchor_path, timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT thread_id, checkpoint_ns, generation, checkpoint_id, "
            "checkpoint_digest FROM checkpoint_heads ORDER BY thread_id, checkpoint_ns"
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED) from exc
    finally:
        connection.close()
    return [dict(row) for row in rows]


def validate_heads(saver: KeyLifecycleConfidentialCheckpointer) -> list[dict[str, Any]]:
    heads = read_heads(saver.anchor_database_path)
    for head in heads:
        item = saver.get_tuple(
            {
                "configurable": {
                    "thread_id": head["thread_id"],
                    "checkpoint_ns": head["checkpoint_ns"],
                }
            }
        )
        if item is None or str(item.config["configurable"]["checkpoint_id"]) != str(
            head["checkpoint_id"]
        ):
            raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED)
    return heads


def require_active_ciphertext(saver: KeyLifecycleConfidentialCheckpointer) -> None:
    active_key_id = saver.key_provider.active_key_id
    connection = sqlite3.connect(saver.database_path, timeout=5.0)
    try:
        checkpoint_blobs = [
            bytes(row[0]) for row in connection.execute("SELECT checkpoint FROM checkpoints")
        ]
        write_blobs = [bytes(row[0]) for row in connection.execute("SELECT value FROM writes")]
    except sqlite3.DatabaseError as exc:
        raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED) from exc
    finally:
        connection.close()
    try:
        for blob in checkpoint_blobs + write_blobs:
            if saver.key_provider.envelope_key_id(blob) != active_key_id:
                raise CheckpointBackupError(CheckpointBackupReason.NON_ACTIVE_CIPHERTEXT)
    except CheckpointBackupError:
        raise
    except Exception as exc:
        raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED) from exc


def row_counts(database_path: Path) -> tuple[int, int]:
    connection = sqlite3.connect(database_path, timeout=5.0)
    try:
        checkpoints = int(connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0])
        writes = int(connection.execute("SELECT COUNT(*) FROM writes").fetchone()[0])
    except sqlite3.DatabaseError as exc:
        raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED) from exc
    finally:
        connection.close()
    return checkpoints, writes


def check_restore_boundary(
    saver: KeyLifecycleConfidentialCheckpointer,
    *,
    backup_database_path: Path,
    backup_heads: list[dict[str, Any]],
) -> None:
    candidates = {
        (str(head["thread_id"]), str(head["checkpoint_ns"])): head
        for head in backup_heads
    }
    connection = sqlite3.connect(backup_database_path, timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        for current in read_heads(saver.anchor_database_path):
            namespace = (str(current["thread_id"]), str(current["checkpoint_ns"]))
            candidate = candidates.get(namespace)
            if candidate is None or int(candidate["generation"]) < int(current["generation"]):
                raise CheckpointBackupError(CheckpointBackupReason.ROLLBACK_DETECTED)
            row = connection.execute(
                "SELECT integrity_digest FROM checkpoints "
                "WHERE thread_id=? AND checkpoint_ns=? AND generation=?",
                (
                    current["thread_id"],
                    current["checkpoint_ns"],
                    int(current["generation"]),
                ),
            ).fetchone()
            if row is None or not hmac.compare_digest(
                str(row["integrity_digest"]), str(current["checkpoint_digest"])
            ):
                raise CheckpointBackupError(CheckpointBackupReason.FORK_DETECTED)
    finally:
        connection.close()


def apply_restore(
    saver: KeyLifecycleConfidentialCheckpointer,
    *,
    backup_database_path: Path,
    backup_anchor_path: Path,
) -> None:
    connection = saver._connect(saver.database_path)
    try:
        connection.execute(
            "ATTACH DATABASE ? AS target_anchor", (str(saver.anchor_database_path),)
        )
        connection.execute("ATTACH DATABASE ? AS source_db", (str(backup_database_path),))
        connection.execute(
            "ATTACH DATABASE ? AS source_anchor", (str(backup_anchor_path),)
        )
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM writes")
        connection.execute("DELETE FROM checkpoints")
        connection.execute("DELETE FROM target_anchor.write_heads")
        connection.execute("DELETE FROM target_anchor.checkpoint_heads")
        connection.execute("INSERT INTO checkpoints SELECT * FROM source_db.checkpoints")
        connection.execute("INSERT INTO writes SELECT * FROM source_db.writes")
        connection.execute(
            "INSERT INTO target_anchor.checkpoint_heads "
            "SELECT * FROM source_anchor.checkpoint_heads"
        )
        connection.execute(
            "INSERT INTO target_anchor.write_heads SELECT * FROM source_anchor.write_heads"
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
