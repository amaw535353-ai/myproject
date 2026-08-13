from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from aegis.agent.checkpoint_confidentiality import (
    P4C_CHECKPOINT_CONFIDENTIALITY_POLICY_VERSION,
    P4C_CIPHERTEXT_MAGIC,
    P4C_LOCAL_SYNTHETIC_ENCRYPTION_KEY_ID,
    CheckpointConfidentialityError,
    CheckpointConfidentialityReason,
    ConfidentialDurableIntegrityCheckpointer,
)
from aegis.agent.checkpoint_durability import DurableIntegrityCheckpointer
from aegis.identity.models import Principal, Role
from aegis.mcp_gateway.models import ToolCallProposal, ToolName


ADVERSARIAL_CASES = (
    "P4C-A1-checkpoint-file-plaintext-disclosure",
    "P4C-A2-pending-write-plaintext-disclosure",
    "P4C-A3-sensitive-metadata-smuggling",
)
BENIGN_CASES = (
    "P4C-B1-legitimate-encrypted-durable-reopen",
    "P4C-B2-legitimate-encrypted-graph-resume",
)


def _dataset_hash() -> str:
    payload = {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _principal() -> Principal:
    return Principal(
        user_id="usr_dyn_alice",
        tenant_id="tenant_northstar_dynamics",
        roles=frozenset({Role.EMPLOYEE}),
    )


def _proposal(marker: str) -> ToolCallProposal:
    return ToolCallProposal(
        name=ToolName.SEARCH_KNOWLEDGE_BASE,
        arguments={"query": marker, "limit": 3},
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


def _contains(path: Path, marker: bytes) -> bool:
    return marker in path.read_bytes()


def _checkpoint_disclosure_case(*, hardened: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4c-a1-") as raw:
        root = Path(raw)
        database_path = root / "checkpoints.sqlite3"
        marker = b"P4C-SYNTHETIC-USER-MESSAGE-ALPHA-7391"
        saver_cls = (
            ConfidentialDurableIntegrityCheckpointer
            if hardened
            else DurableIntegrityCheckpointer
        )
        saver = saver_cls(
            database_path=database_path,
            anchor_database_path=root / "anchors.sqlite3",
        )
        saver.put(
            _config("p4c-a1-thread"),
            _checkpoint("00000001", marker=marker.decode()),
            {"source": "input"},
            {},
        )
        disclosed = _contains(database_path, marker)
        ciphertext_envelope_present = _contains(database_path, P4C_CIPHERTEXT_MAGIC)
        return {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": disclosed,
            "plaintext_disclosed": disclosed,
            "ciphertext_envelope_present": ciphertext_envelope_present,
        }


def _pending_write_disclosure_case(*, hardened: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4c-a2-") as raw:
        root = Path(raw)
        database_path = root / "checkpoints.sqlite3"
        marker = b"P4C-SYNTHETIC-PENDING-WRITE-BRAVO-2844"
        saver_cls = (
            ConfidentialDurableIntegrityCheckpointer
            if hardened
            else DurableIntegrityCheckpointer
        )
        saver = saver_cls(
            database_path=database_path,
            anchor_database_path=root / "anchors.sqlite3",
        )
        saved = saver.put(
            _config("p4c-a2-thread"),
            _checkpoint("00000001", marker="ordinary-state"),
            {"source": "input"},
            {},
        )
        saver.put_writes(
            saved,
            [("synthetic_pending", {"synthetic_value": marker.decode()})],
            task_id="p4c-a2-task",
        )
        disclosed = _contains(database_path, marker)
        return {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": disclosed,
            "plaintext_disclosed": disclosed,
        }


def _metadata_smuggling_case(*, hardened: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4c-a3-") as raw:
        root = Path(raw)
        database_path = root / "checkpoints.sqlite3"
        marker = b"P4C-SYNTHETIC-METADATA-CHARLIE-9912"
        saver_cls = (
            ConfidentialDurableIntegrityCheckpointer
            if hardened
            else DurableIntegrityCheckpointer
        )
        saver = saver_cls(
            database_path=database_path,
            anchor_database_path=root / "anchors.sqlite3",
        )
        rejection: str | None = None
        try:
            saver.put(
                _config("p4c-a3-thread"),
                _checkpoint("00000001", marker="ordinary-state"),
                {"message": marker.decode()},
                {},
            )
        except CheckpointConfidentialityError as exc:
            rejection = exc.reason.value
        disclosed = _contains(database_path, marker)
        success = disclosed
        return {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": success,
            "plaintext_disclosed": disclosed,
            "rejection": rejection,
        }


def _benign_durable_reopen() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4c-b1-") as raw:
        root = Path(raw)
        database_path = root / "checkpoints.sqlite3"
        anchor_path = root / "anchors.sqlite3"
        saver = ConfidentialDurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        )
        saver.put(
            _config("p4c-b1-thread"),
            _checkpoint("00000001", marker="benign-encrypted-reopen"),
            {"source": "input", "step": 1},
            {},
        )
        reopened = ConfidentialDurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        ).get_tuple(_config("p4c-b1-thread"))
        values = {} if reopened is None else reopened.checkpoint["channel_values"]
        safe = bool(
            isinstance(values.get("principal"), Principal)
            and isinstance(values.get("proposal"), ToolCallProposal)
            and values.get("marker") == "benign-encrypted-reopen"
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


def _resume_graph(saver: ConfidentialDurableIntegrityCheckpointer):
    def pause_and_increment(state: _ResumeState) -> dict[str, int]:
        resumed = interrupt({"kind": "synthetic-encrypted-checkpoint-resume"})
        return {"count": int(state["count"]) + int(resumed["increment"])}

    graph = StateGraph(_ResumeState)
    graph.add_node("pause", pause_and_increment)
    graph.add_edge(START, "pause")
    graph.add_edge("pause", END)
    return graph.compile(checkpointer=saver)


async def _benign_graph_resume_async(root: Path) -> dict[str, Any]:
    database_path = root / "checkpoints.sqlite3"
    anchor_path = root / "anchors.sqlite3"
    config = _config("p4c-b2-thread")
    first_graph = _resume_graph(
        ConfidentialDurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        )
    )
    interrupted = await first_graph.ainvoke({"count": 1}, config=config)
    interruption_persisted = bool(interrupted.get("__interrupt__"))

    reopened_graph = _resume_graph(
        ConfidentialDurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        )
    )
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
    with tempfile.TemporaryDirectory(prefix="aegis-p4c-b2-") as raw:
        return asyncio.run(_benign_graph_resume_async(Path(raw)))


def _wrong_key_fail_closed() -> tuple[bool, str | None]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4c-key-") as raw:
        root = Path(raw)
        database_path = root / "checkpoints.sqlite3"
        anchor_path = root / "anchors.sqlite3"
        saver = ConfidentialDurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        )
        saver.put(
            _config("p4c-key-thread"),
            _checkpoint("00000001", marker="key-bound-state"),
            {"source": "input"},
            {},
        )
        rejection: str | None = None
        try:
            ConfidentialDurableIntegrityCheckpointer(
                database_path=database_path,
                anchor_database_path=anchor_path,
                encryption_key=b"x" * 32,
            ).get_tuple(_config("p4c-key-thread"))
        except CheckpointConfidentialityError as exc:
            rejection = exc.reason.value
        return rejection == CheckpointConfidentialityReason.DECRYPTION_FAILED.value, rejection


def _legacy_plaintext_fail_closed() -> tuple[bool, str | None]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4c-legacy-") as raw:
        root = Path(raw)
        database_path = root / "checkpoints.sqlite3"
        anchor_path = root / "anchors.sqlite3"
        DurableIntegrityCheckpointer(
            database_path=database_path,
            anchor_database_path=anchor_path,
        ).put(
            _config("p4c-legacy-thread"),
            _checkpoint("00000001", marker="legacy-plaintext-state"),
            {"source": "input"},
            {},
        )
        rejection: str | None = None
        try:
            ConfidentialDurableIntegrityCheckpointer(
                database_path=database_path,
                anchor_database_path=anchor_path,
            ).get_tuple(_config("p4c-legacy-thread"))
        except CheckpointConfidentialityError as exc:
            rejection = exc.reason.value
        return (
            rejection
            == CheckpointConfidentialityReason.CIPHERTEXT_ENVELOPE_INVALID.value,
            rejection,
        )


def _metrics(adversarial: list[dict[str, Any]], benign: list[dict[str, Any]]) -> dict[str, list[int]]:
    return {
        "asr": [sum(bool(item["success"]) for item in adversarial), len(adversarial)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }


def build_report() -> dict[str, Any]:
    vulnerable = [
        _checkpoint_disclosure_case(hardened=False),
        _pending_write_disclosure_case(hardened=False),
        _metadata_smuggling_case(hardened=False),
    ]
    hardened = [
        _checkpoint_disclosure_case(hardened=True),
        _pending_write_disclosure_case(hardened=True),
        _metadata_smuggling_case(hardened=True),
    ]
    benign = [_benign_durable_reopen(), _benign_graph_resume()]
    wrong_key_closed, wrong_key_rejection = _wrong_key_fail_closed()
    legacy_closed, legacy_rejection = _legacy_plaintext_fail_closed()
    vulnerable_metrics = _metrics(vulnerable, [])
    hardened_metrics = _metrics(hardened, benign)

    report: dict[str, Any] = {
        "evaluation": "P4-C durable checkpoint confidentiality and secret minimization",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": P4C_CHECKPOINT_CONFIDENTIALITY_POLICY_VERSION,
        "local_synthetic_encryption_key_id": P4C_LOCAL_SYNTHETIC_ENCRYPTION_KEY_ID,
        "variants": {
            "integrity_only_plaintext_baseline": {
                "adversarial_attempts": vulnerable,
                "metrics": vulnerable_metrics,
            },
            "encrypted_minimized_boundary": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "wrong_key_fail_closed": wrong_key_closed,
        "wrong_key_rejection": wrong_key_rejection,
        "legacy_plaintext_fail_closed": legacy_closed,
        "legacy_plaintext_rejection": legacy_rejection,
        "structural_sqlite_metadata_remains_plaintext": True,
        "external_key_custody": False,
        "raw_sensitive_values_in_report": False,
        "raw_encryption_key_bytes_in_report": False,
        "real_external_operations": False,
        "production_confidentiality_claim": False,
    }
    report["passed"] = bool(
        vulnerable_metrics["asr"] == [3, 3]
        and hardened_metrics["asr"] == [0, 3]
        and hardened_metrics["fpr"] == [0, 2]
        and hardened_metrics["safe_task_rate"] == [2, 2]
        and hardened[0]["ciphertext_envelope_present"] is True
        and hardened[2]["rejection"]
        == CheckpointConfidentialityReason.SENSITIVE_METADATA_REJECTED.value
        and wrong_key_closed
        and legacy_closed
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
