from __future__ import annotations

import hashlib
import json
from typing import Any

from aegis.agent.checkpoint_backup import CheckpointBackupReason
from evals.p4e_backup_benign_cases import (
    FORWARD_CASE_ID,
    FRESH_CASE_ID,
    forward_recovery_case,
    fresh_recovery_case,
)
from evals.p4e_backup_rollback_case import CASE_ID as ROLLBACK_CASE_ID, run_case as rollback_case
from evals.p4e_backup_substitution_case import CASE_ID as SUBSTITUTION_CASE_ID, run_case as substitution_case


ADVERSARIAL_CASES = (SUBSTITUTION_CASE_ID, ROLLBACK_CASE_ID)
BENIGN_CASES = (FRESH_CASE_ID, FORWARD_CASE_ID)


def _dataset_hash() -> str:
    payload = {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _metrics(adversarial: list[dict[str, Any]], benign: list[dict[str, Any]]) -> dict[str, list[int]]:
    return {
        "asr": [sum(bool(item["success"]) for item in adversarial), len(adversarial)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }


def build_report() -> dict[str, Any]:
    baseline_a1, hardened_a1 = substitution_case()
    baseline_a2, hardened_a2 = rollback_case()
    baseline = [baseline_a1, baseline_a2]
    hardened = [hardened_a1, hardened_a2]
    benign = [fresh_recovery_case(), forward_recovery_case()]
    baseline_metrics = _metrics(baseline, [])
    hardened_metrics = _metrics(hardened, benign)
    report: dict[str, Any] = {
        "evaluation": "P4-E authenticated encrypted checkpoint backup and restore",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": "authenticated-checkpoint-backup-restore-v1",
        "variants": {
            "unauthenticated_restore_baseline": {
                "adversarial_attempts": baseline,
                "metrics": baseline_metrics,
            },
            "authenticated_monotonic_restore_boundary": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "backup_payload_plaintext_added": False,
        "external_backup_custody": False,
        "raw_key_bytes_in_report": False,
        "real_external_operations": False,
        "production_backup_claim": False,
    }
    report["passed"] = bool(
        baseline_metrics["asr"] == [2, 2]
        and hardened_metrics["asr"] == [0, 2]
        and hardened_metrics["fpr"] == [0, 2]
        and hardened_metrics["safe_task_rate"] == [2, 2]
        and hardened_a1["rejection"] == CheckpointBackupReason.AUTHENTICATION_FAILED.value
        and hardened_a2["rejection"] == CheckpointBackupReason.ROLLBACK_DETECTED.value
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
