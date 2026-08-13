from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer


def saver(root: Path) -> KeyLifecycleConfidentialCheckpointer:
    return KeyLifecycleConfidentialCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "anchors.sqlite3",
    )


def checkpoint(checkpoint_id: str, marker: str) -> dict[str, Any]:
    return {
        "v": 4,
        "ts": "2026-08-13T00:00:00+00:00",
        "id": checkpoint_id,
        "channel_values": {"marker": marker},
        "channel_versions": {},
        "versions_seen": {},
        "updated_channels": ["marker"],
    }


def config(thread_id: str, checkpoint_id: str | None = None) -> dict[str, Any]:
    configurable: dict[str, Any] = {"thread_id": thread_id, "checkpoint_ns": ""}
    if checkpoint_id is not None:
        configurable["checkpoint_id"] = checkpoint_id
    return {"configurable": configurable}


def put(
    checkpointer: KeyLifecycleConfidentialCheckpointer,
    *,
    thread_id: str,
    checkpoint_id: str,
    marker: str,
    parent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return checkpointer.put(
        config(thread_id) if parent is None else parent,
        checkpoint(checkpoint_id, marker),
        {"source": "input"},
        {},
    )


def marker(checkpointer: KeyLifecycleConfidentialCheckpointer, thread_id: str) -> str | None:
    item = checkpointer.get_tuple(config(thread_id))
    if item is None:
        return None
    return str(item.checkpoint["channel_values"].get("marker"))
