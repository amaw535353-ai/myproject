from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from aegis.agent.checkpoint_durability import (
    P4B_CHECKPOINT_INTEGRITY_POLICY_VERSION,
    P4B_LOCAL_SYNTHETIC_KEY_ID,
    CheckpointIntegrityError,
    CheckpointIntegrityReason,
    DurableIntegrityCheckpointer,
)
from aegis.agent.checkpoint_security import build_strict_checkpoint_serializer
from aegis.identity.models import Principal, Role
from aegis.mcp_gateway.models import ToolCallProposal, ToolName


ADVERSARIAL_CASES = (
    "P4B-A1-persisted-checkpoint-modification",
    "P4B-A2-checkpoint-database-rollback",
)
BENIGN_CASES = (
    "P4B-B1-legitimate-durable-reopen",
    "P4B-B2-legitimate-graph-resume-after-reopen",
)


def _dataset_hash() -> str:
    payload = {
        "adversarial": ADVERSARIAL_CASES,
        "benign": BENIGN_CASES,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _principal() -> Principal:
    return Principal(
        user_id="usr_dyn_alice",
        tenant_id="tenant_northstar_dynamics",
        roles=frozenset({Role.EMPLOYEE}),
    )


def _proposal(query: str = "vpn setup") -> ToolCallProposal:
    return ToolCallProposal(
        name=ToolName.SEARCH_KNOWLEDGE_BASE,
        arguments={"query": query, "limit": 3},
    )


def _checkpoint(checkpoint_id: str, *, marker: str) -> dict[str, Any]:
    return {
        "v": 4,
        "ts": "2026-08-13T00:00:00+00:00",
        "id": checkpoint_id,
        "channel_values": {
            "principal": _principal(),
            "proposal": _proposal(marker),
            "marker": marker,
        },
        "channel_versions": {},
        "versions_seen": {},
        "updated_channels": ["principal", "proposal", "marker"],
    }


def _config(thread_id: str, checkpoint_id: str | None = None) -> dict[str, Any]:
    configurable: dict[str, Any] = {"thread_id": thread_id, "checkpoint_ns": ""}
    if checkpoint_id is not None:
        configurable["checkpoint_id"] = checkpoint_id
    return {"configurable": configurable}


class _UnprotectedDurableStore:
    """Comparison baseline: durable strict serialization without integrity state."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.serde = build_strict_checkpoint_serializer()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    thread_id TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    checkpoint BLOB NOT NULL,
                    PRIMARY KEY (thread_id, checkpoint_id)
                )
                """
            )

    def put(self, thread_id: str, checkpoint: dict[str, Any]) -> None:
        type_tag, blob = self.serde.dumps_typed(checkpoint)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?)",
                (thread_id, checkpoint["id"], type_tag, blob),
            )

    def latest(self, thread_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT type, checkpoint
                FROM checkpoints
                WHERE thread_id = ?
                ORDER BY checkpoint_id DESC
                LIMIT 1
                """,
                (thread_id,),
            ).fetchone()
        if row is None:
            return None
        return self.serde.loads_typed((str(row[0]), bytes(row[1])))


def _tamper_checkpoint_blob(
    *,
    database_path: Path,
    thread_id: str,
    checkpoint_id: str,
    checkpoint: dict[str, Any],
) -> None:
    serde = build_strict_checkpoint_serializer()
    type_tag, blob = serde.dumps_typed(checkpoint)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            UPDATE checkpoints
            SET type = ?, checkpoint = ?
            WHERE thread_id = ? AND checkpoint_id = ?
            """,
            (type_tag, blob, thread_id, checkpoint_id),
        )


def _run_modified_checkpoint_case(*, hardened: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4b-a1-") as raw:
        root = Path(raw)
        thread_id = "p4b-a1-thread"
        original = _checkpoint("00000001", marker="approved-state")
        forged = _checkpoint("00000001", marker="forged-state")

        rejection: str | None = None
        if hardened:
            database_path = root / "checkpoints.sqlite3"
            saver = DurableIntegrityCheckpointer(
                database_path=database_path,
                anchor_database_path=root / "anchors.sqlite3",
            )
            saver.put(_config(thread_id), original, {"source": "input"}, {})
            _tamper_checkpoint_blob(
                database_path=database_path,
                thread_id=thread_id,
                checkpoint_id="00000001",
                checkpoint=forged,
            )
            observed_forged = False
            try:
                saver.get_tuple(_config(thread_id))
            except CheckpointIntegrityError as exc:
                rejection = exc.reason.value
            success = observed_forged
        else:
            database_path = root / "unprotected.sqlite3"
            store = _UnprotectedDurableStore(database_path)
            store.put(thread_id, original)
            _tamper_checkpoint_blob(
                database_path=database_path,
                thread_id=thread_id,
                checkpoint_id="00000001",
                checkpoint=forged,
            )
            loaded = store.latest(thread_id)
            observed_forged = bool(
                loaded is not None
                and loaded["channel_values"]["marker"] == "forged-state"
            )
            success = observed_forged

        return {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": success,
            "forged_state_observed": observed_forged,
            "rejection": rejection,
        }


def _run_rollback_case(*, hardened: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4b-a2-") as raw:
        root = Path(raw)
        thread_id = "p4b-a2-thread"
        first = _checkpoint("00000001", marker="generation-1")
        second = _checkpoint("00000002", marker="generation-2")
        snapshot = root / "checkpoint-generation-1.snapshot.sqlite3"

        rejection: str | None = None
        if hardened:
            database_path = root / "checkpoints.sqlite3"
            anchor_path = root / "anchors.sqlite3"
            saver = DurableIntegrityCheckpointer(
                database_path=database_path,
                anchor_database_path=anchor_path,
            )
            saved_first = saver.put(_config(thread_id), first, {"step": 1}, {})
            shutil.copy2(database_path, snapshot)
            saver.put(saved_first, second, {"step": 2}, {})
            shutil.copy2(snapshot, database_path)
            observed_stale = False
            try:
                DurableIntegrityCheckpointer(
                    database_path=database_path,
                    anchor_database_path=anchor_path,
                ).get_tuple(_config(thread_id))
            except CheckpointIntegrityError as exc:
                rejection = exc.reason.value
            success = observed_stale
        else:
            database_path = root / "unprotected.sqlite3"
            store = _UnprotectedDurableStore(database_path)
            store.put(thread_id, first)
            shutil.copy2(database_path, snapshot)
            store.put(thread_id, second)
            shutil.copy2(snapshot, database_path)
            loaded = _UnprotectedDurableStore(database_path).latest(thread_id)
            observed_stale = bool(
                loaded is not None
                and loaded["channel_values"]["marker"] == "generation-1"
            )
            success = observed_stale

        return {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": success,
            "stale_checkpoint_observed": observed_stale,
            "rejection": rejection,
        }


def _benign_durable_reopen() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4b-b1-") as raw:
        root = Path(raw)
        database_path = root / "checkpoints.sqlite3"
        anchor_path = root / "anchors.sqlite3"
        thread_id = "p4b-b1-thread"
        saver = DurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        )
        saver.put(
            _config(thread_id),
            _checkpoint("00000001", marker="benign-reopen"),
            {"source": "input"},
            {},
        )
        reopened = DurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        ).get_tuple(_config(thread_id))
        channel_values = {} if reopened is None else reopened.checkpoint["channel_values"]
        safe = bool(
            isinstance(channel_values.get("principal"), Principal)
            and isinstance(channel_values.get("proposal"), ToolCallProposal)
            and channel_values.get("marker") == "benign-reopen"
        )
        return {
            "attempt_id": BENIGN_CASES[0],
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
            "durable_reopen_verified": safe,
            "strict_application_types_preserved": safe,
        }


class _ResumeState(TypedDict, total=False):
    count: int


def _resume_graph(saver: DurableIntegrityCheckpointer):
    def pause_and_increment(state: _ResumeState) -> dict[str, int]:
        resumed = interrupt({"kind": "synthetic-checkpoint-resume"})
        increment = int(resumed["increment"])
        return {"count": int(state["count"]) + increment}

    graph = StateGraph(_ResumeState)
    graph.add_node("pause", pause_and_increment)
    graph.add_edge(START, "pause")
    graph.add_edge("pause", END)
    return graph.compile(checkpointer=saver)


async def _benign_graph_resume_async(root: Path) -> dict[str, Any]:
    database_path = root / "checkpoints.sqlite3"
    anchor_path = root / "anchors.sqlite3"
    config = _config("p4b-b2-thread")
    first_saver = DurableIntegrityCheckpointer(
        database_path=database_path,
        anchor_database_path=anchor_path,
    )
    first_graph = _resume_graph(first_saver)
    interrupted = await first_graph.ainvoke({"count": 1}, config=config)
    interruption_persisted = bool(interrupted.get("__interrupt__"))

    reopened_saver = DurableIntegrityCheckpointer(
        database_path=database_path,
        anchor_database_path=anchor_path,
    )
    reopened_graph = _resume_graph(reopened_saver)
    resumed = await reopened_graph.ainvoke(
        Command(resume={"increment": 1}),
        config=config,
    )
    safe = interruption_persisted and resumed.get("count") == 2
    return {
        "attempt_id": BENIGN_CASES[1],
        "safe_completion": safe,
        "incorrectly_blocked": not safe,
        "interruption_persisted": interruption_persisted,
        "resume_after_reopen_verified": safe,
    }


def _benign_graph_resume() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4b-b2-") as raw:
        return asyncio.run(_benign_graph_resume_async(Path(raw)))


def _metrics(adversarial: list[dict[str, Any]], benign: list[dict[str, Any]]) -> dict[str, list[int]]:
    return {
        "asr": [sum(bool(item["success"]) for item in adversarial), len(adversarial)],
        "fpr": [
            sum(bool(item["incorrectly_blocked"]) for item in benign),
            len(benign),
        ],
        "safe_task_rate": [
            sum(bool(item["safe_completion"]) for item in benign),
            len(benign),
        ],
    }


def build_report() -> dict[str, Any]:
    vulnerable = [
        _run_modified_checkpoint_case(hardened=False),
        _run_rollback_case(hardened=False),
    ]
    hardened = [
        _run_modified_checkpoint_case(hardened=True),
        _run_rollback_case(hardened=True),
    ]
    benign = [_benign_durable_reopen(), _benign_graph_resume()]
    vulnerable_metrics = _metrics(vulnerable, [])
    hardened_metrics = _metrics(hardened, benign)
    report: dict[str, Any] = {
        "evaluation": "P4-B durable checkpoint integrity boundary",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": P4B_CHECKPOINT_INTEGRITY_POLICY_VERSION,
        "local_synthetic_key_id": P4B_LOCAL_SYNTHETIC_KEY_ID,
        "variants": {
            "unprotected_durable_baseline": {
                "adversarial_attempts": vulnerable,
                "metrics": vulnerable_metrics,
            },
            "integrity_anchored_boundary": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "checkpoint_database_and_anchor_separate": True,
        "raw_checkpoint_contents_in_report": False,
        "raw_integrity_key_bytes_in_report": False,
        "real_external_operations": False,
        "production_durability_claim": False,
    }
    report["passed"] = bool(
        vulnerable_metrics["asr"] == [2, 2]
        and hardened_metrics["asr"] == [0, 2]
        and hardened_metrics["fpr"] == [0, 2]
        and hardened_metrics["safe_task_rate"] == [2, 2]
        and hardened[0]["rejection"]
        == CheckpointIntegrityReason.CHECKPOINT_INTEGRITY_MISMATCH.value
        and hardened[1]["rejection"]
        == CheckpointIntegrityReason.CHECKPOINT_ROLLBACK_DETECTED.value
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
