from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_confidentiality import ConfidentialDurableIntegrityCheckpointer
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_keys import (
    P4D_CHECKPOINT_KEY_LIFECYCLE_POLICY_VERSION,
    P4D_LOCAL_SYNTHETIC_ACTIVE_KEY,
    P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
    P4D_LOCAL_SYNTHETIC_LEGACY_KEY,
    P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID,
    CheckpointConfidentialityError,
    CheckpointConfidentialityReason,
    CheckpointKeyState,
    LocalSyntheticCheckpointKey,
    LocalSyntheticCheckpointKeyProvider,
    build_default_local_synthetic_checkpoint_key_provider,
)


ADVERSARIAL_CASES = (
    "P4D-A1-compromised-retired-key-after-migration",
    "P4D-A2-revoked-key-ciphertext-reuse",
)
BENIGN_CASES = (
    "P4D-B1-staged-decrypt-only-reopen",
    "P4D-B2-safe-reencrypt-and-resume",
)


def _dataset_hash() -> str:
    payload = {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _checkpoint(checkpoint_id: str, marker: str) -> dict[str, Any]:
    return {
        "v": 4,
        "ts": "2026-08-13T00:00:00+00:00",
        "id": checkpoint_id,
        "channel_values": {"marker": marker},
        "channel_versions": {},
        "versions_seen": {},
        "updated_channels": ["marker"],
    }


def _config(thread_id: str, checkpoint_id: str | None = None) -> dict[str, Any]:
    configurable: dict[str, Any] = {"thread_id": thread_id, "checkpoint_ns": ""}
    if checkpoint_id is not None:
        configurable["checkpoint_id"] = checkpoint_id
    return {"configurable": configurable}


def _legacy_saver(root: Path) -> ConfidentialDurableIntegrityCheckpointer:
    return ConfidentialDurableIntegrityCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "anchors.sqlite3",
    )


def _write_legacy_state(root: Path, *, thread_id: str, marker: str, with_write: bool = False) -> None:
    saver = _legacy_saver(root)
    saved = saver.put(
        _config(thread_id),
        _checkpoint("00000001", marker),
        {"source": "input"},
        {},
    )
    if with_write:
        saver.put_writes(
            saved,
            [("synthetic_pending", {"marker": marker + "-pending"})],
            task_id="p4d-task",
        )


def _legacy_reader_can_read(root: Path, thread_id: str) -> bool:
    try:
        item = _legacy_saver(root).get_tuple(_config(thread_id))
    except CheckpointConfidentialityError:
        return False
    return item is not None


def _compromised_retired_key_case() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4d-a1-") as raw:
        root = Path(raw)
        thread_id = "p4d-a1-thread"
        _write_legacy_state(root, thread_id=thread_id, marker="retired-key-state")
        baseline_success = _legacy_reader_can_read(root, thread_id)

        saver = KeyLifecycleConfidentialCheckpointer(
            database_path=root / "checkpoints.sqlite3",
            anchor_database_path=root / "anchors.sqlite3",
            key_provider=build_default_local_synthetic_checkpoint_key_provider(),
        )
        migration = saver.migrate_to_active_encryption_key()
        retired_reader_success = _legacy_reader_can_read(root, thread_id)
        raw_database = (root / "checkpoints.sqlite3").read_bytes()
        hardened_success = retired_reader_success

        return (
            {
                "attempt_id": ADVERSARIAL_CASES[0],
                "success": baseline_success,
                "retired_key_reader_succeeded": baseline_success,
            },
            {
                "attempt_id": ADVERSARIAL_CASES[0],
                "success": hardened_success,
                "retired_key_reader_succeeded": retired_reader_success,
                "legacy_key_id_remains_in_ciphertext": (
                    P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID.encode() in raw_database
                ),
                "active_key_id_present_in_ciphertext": (
                    P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID.encode() in raw_database
                ),
                "checkpoints_reencrypted": migration.checkpoints_reencrypted,
            },
        )


def _revoked_key_case() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4d-a2-") as raw:
        root = Path(raw)
        thread_id = "p4d-a2-thread"
        _write_legacy_state(root, thread_id=thread_id, marker="revoked-key-state")
        baseline_success = _legacy_reader_can_read(root, thread_id)
        provider = LocalSyntheticCheckpointKeyProvider(
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
                    state=CheckpointKeyState.REVOKED,
                ),
            },
        )
        rejection: str | None = None
        try:
            KeyLifecycleConfidentialCheckpointer(
                database_path=root / "checkpoints.sqlite3",
                anchor_database_path=root / "anchors.sqlite3",
                key_provider=provider,
            ).get_tuple(_config(thread_id))
        except CheckpointConfidentialityError as exc:
            rejection = exc.reason.value
        hardened_success = rejection is None
        return (
            {
                "attempt_id": ADVERSARIAL_CASES[1],
                "success": baseline_success,
                "revoked_key_reader_succeeded": baseline_success,
            },
            {
                "attempt_id": ADVERSARIAL_CASES[1],
                "success": hardened_success,
                "revoked_key_reader_succeeded": hardened_success,
                "rejection": rejection,
            },
        )


def _staged_reopen_benign() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4d-b1-") as raw:
        root = Path(raw)
        thread_id = "p4d-b1-thread"
        marker = "staged-legacy-reopen"
        _write_legacy_state(root, thread_id=thread_id, marker=marker)
        saver = KeyLifecycleConfidentialCheckpointer(
            database_path=root / "checkpoints.sqlite3",
            anchor_database_path=root / "anchors.sqlite3",
            key_provider=build_default_local_synthetic_checkpoint_key_provider(),
        )
        item = saver.get_tuple(_config(thread_id))
        safe = bool(item and item.checkpoint["channel_values"].get("marker") == marker)
        return {
            "attempt_id": BENIGN_CASES[0],
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
            "legacy_key_state": saver.key_provider.key_state(
                P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID
            ).value,
        }


def _migration_benign() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4d-b2-") as raw:
        root = Path(raw)
        thread_id = "p4d-b2-thread"
        marker = "migration-preserves-state"
        _write_legacy_state(root, thread_id=thread_id, marker=marker, with_write=True)
        saver = KeyLifecycleConfidentialCheckpointer(
            database_path=root / "checkpoints.sqlite3",
            anchor_database_path=root / "anchors.sqlite3",
            key_provider=build_default_local_synthetic_checkpoint_key_provider(),
        )
        migration = saver.migrate_to_active_encryption_key()
        reopened = KeyLifecycleConfidentialCheckpointer(
            database_path=root / "checkpoints.sqlite3",
            anchor_database_path=root / "anchors.sqlite3",
            key_provider=build_default_local_synthetic_checkpoint_key_provider(),
        ).get_tuple(_config(thread_id))
        pending = [] if reopened is None else list(reopened.pending_writes)
        raw_database = (root / "checkpoints.sqlite3").read_bytes()
        safe = bool(
            reopened
            and reopened.checkpoint["channel_values"].get("marker") == marker
            and pending
            and pending[0][2].get("marker") == marker + "-pending"
            and migration.checkpoints_reencrypted == 1
            and migration.writes_reencrypted == 1
            and P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID.encode() not in raw_database
            and P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID.encode() in raw_database
        )
        return {
            "attempt_id": BENIGN_CASES[1],
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
            "checkpoint_state_preserved": bool(
                reopened and reopened.checkpoint["channel_values"].get("marker") == marker
            ),
            "pending_write_preserved": bool(pending),
            "checkpoints_reencrypted": migration.checkpoints_reencrypted,
            "writes_reencrypted": migration.writes_reencrypted,
        }


def _metrics(adversarial: list[dict[str, Any]], benign: list[dict[str, Any]]) -> dict[str, list[int]]:
    return {
        "asr": [sum(bool(item["success"]) for item in adversarial), len(adversarial)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }


def build_report() -> dict[str, Any]:
    baseline_a1, hardened_a1 = _compromised_retired_key_case()
    baseline_a2, hardened_a2 = _revoked_key_case()
    baseline = [baseline_a1, baseline_a2]
    hardened = [hardened_a1, hardened_a2]
    benign = [_staged_reopen_benign(), _migration_benign()]
    baseline_metrics = _metrics(baseline, [])
    hardened_metrics = _metrics(hardened, benign)

    report: dict[str, Any] = {
        "evaluation": "P4-D checkpoint encryption key lifecycle and migration",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": P4D_CHECKPOINT_KEY_LIFECYCLE_POLICY_VERSION,
        "active_key_id": P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
        "legacy_key_id": P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID,
        "variants": {
            "single_key_no_lifecycle_baseline": {
                "adversarial_attempts": baseline,
                "metrics": baseline_metrics,
            },
            "versioned_key_lifecycle_boundary": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "external_key_custody": False,
        "raw_key_bytes_in_report": False,
        "real_external_operations": False,
        "production_key_management_claim": False,
    }
    report["passed"] = bool(
        baseline_metrics["asr"] == [2, 2]
        and hardened_metrics["asr"] == [0, 2]
        and hardened_metrics["fpr"] == [0, 2]
        and hardened_metrics["safe_task_rate"] == [2, 2]
        and hardened_a1["legacy_key_id_remains_in_ciphertext"] is False
        and hardened_a1["active_key_id_present_in_ciphertext"] is True
        and hardened_a2["rejection"]
        == CheckpointConfidentialityReason.REVOKED_ENCRYPTION_KEY.value
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
