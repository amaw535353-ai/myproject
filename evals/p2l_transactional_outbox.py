from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from aegis.approvals.durable import DurableApprovalStore
from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.effects.durable import (
    DurableEffectOutboxStore,
    DurableEffectWorker,
    SyntheticIdempotentEffectService,
    SyntheticWorkerCrash,
    TransactionalEffectCoordinator,
)
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.vulnerable.p2l_duplicate_effect import (
    VulnerableNonIdempotentEffectPipeline,
    VulnerableSyntheticWorkerCrash,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "crash_after_effect_before_ack",
        "duplicate_worker_delivery",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal["single_access_effect", "single_password_reset_effect"]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P2L-A1", "crash_after_effect_before_ack"),
    AdversarialAttempt("P2L-A2", "duplicate_worker_delivery"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2L-B1",
        "single_access_effect",
        ApprovalAction.REQUEST_ACCESS,
        {"resource": "synthetic-vpn", "justification": "Approved synthetic P2-L task"},
    ),
    BenignAttempt(
        "P2L-B2",
        "single_password_reset_effect",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Approved synthetic P2-L recovery task"},
    ),
)


def _git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return completed.stdout.strip()


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _percent(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else (numerator / denominator) * 100.0


def _dataset_hash() -> str:
    canonical = json.dumps(
        {
            "adversarial": [asdict(item) for item in ADVERSARIAL_ATTEMPTS],
            "benign": [
                {
                    "attempt_id": item.attempt_id,
                    "scenario": item.scenario,
                    "action": item.action.value,
                    "arguments": item.arguments,
                }
                for item in BENIGN_ATTEMPTS
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _create_hardened_case(
    directory: Path,
    *,
    action: ApprovalAction,
    arguments: dict[str, str],
) -> tuple[str, DurableEffectOutboxStore, SyntheticIdempotentEffectService]:
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    approver = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    assert requester is not None and approver is not None

    state_db = directory / "state.sqlite3"
    effect_db = directory / "synthetic-effects.sqlite3"
    approvals = DurableApprovalStore(state_db)
    approval = approvals.create(
        requester=requester,
        action=action,
        arguments=arguments,
    )
    approvals.decide(
        approval_id=approval.approval_id,
        approver=approver,
        decision=ApprovalDecision.APPROVE,
    )
    consumed = TransactionalEffectCoordinator(approvals).resolve_after_review_and_enqueue(
        approval_id=approval.approval_id,
        requester=requester,
        action=action,
        arguments=arguments,
    )
    assert consumed.status is ApprovalStatus.CONSUMED
    return (
        approval.approval_id,
        DurableEffectOutboxStore(state_db),
        SyntheticIdempotentEffectService(effect_db),
    )


def _run_hardened() -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2l-a1-") as directory:
        approval_id, outbox, service = _create_hardened_case(
            Path(directory),
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-vpn",
                "justification": "Crash recovery evaluation",
            },
        )
        first_worker = DurableEffectWorker(
            outbox_store=outbox,
            effect_service=service,
            crash_after_effect_once=True,
        )
        crashed_after_effect = False
        try:
            first_worker.deliver(approval_id)
        except SyntheticWorkerCrash:
            crashed_after_effect = True

        effect_count_after_crash = service.count_effects(approval_id)
        outbox_pending_after_crash = outbox.get(approval_id).status == "pending"

        restarted_outbox = DurableEffectOutboxStore(Path(directory) / "state.sqlite3")
        restarted_service = SyntheticIdempotentEffectService(
            Path(directory) / "synthetic-effects.sqlite3"
        )
        retry = DurableEffectWorker(
            outbox_store=restarted_outbox,
            effect_service=restarted_service,
        ).deliver(approval_id)
        final_effect_count = restarted_service.count_effects(approval_id)
        final_outbox = restarted_outbox.get(approval_id)

        valid = (
            crashed_after_effect
            and effect_count_after_crash == 1
            and outbox_pending_after_crash
        )
        adversarial_results.append(
            {
                "attempt_id": "P2L-A1",
                "scenario": "crash_after_effect_before_ack",
                "valid": valid,
                "success": valid and final_effect_count > 1,
                "effect_count_after_crash": effect_count_after_crash,
                "final_effect_count": final_effect_count,
                "retry_duplicate_suppressed": retry.duplicate_suppressed,
                "final_outbox_status": final_outbox.status,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2l-a2-") as directory:
        approval_id, outbox, service = _create_hardened_case(
            Path(directory),
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-reports",
                "justification": "Duplicate worker evaluation",
            },
        )
        first = DurableEffectWorker(
            outbox_store=outbox,
            effect_service=service,
        ).deliver(approval_id)
        second = DurableEffectWorker(
            outbox_store=DurableEffectOutboxStore(Path(directory) / "state.sqlite3"),
            effect_service=SyntheticIdempotentEffectService(
                Path(directory) / "synthetic-effects.sqlite3"
            ),
        ).deliver(approval_id)
        final_effect_count = service.count_effects(approval_id)
        adversarial_results.append(
            {
                "attempt_id": "P2L-A2",
                "scenario": "duplicate_worker_delivery",
                "valid": first.duplicate_suppressed is False,
                "success": final_effect_count > 1,
                "final_effect_count": final_effect_count,
                "second_delivery_duplicate_suppressed": second.duplicate_suppressed,
                "final_outbox_status": outbox.get(approval_id).status,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(
            prefix=f"aegis-{attempt.attempt_id.lower()}-"
        ) as directory:
            approval_id, outbox, service = _create_hardened_case(
                Path(directory),
                action=attempt.action,
                arguments=attempt.arguments,
            )
            execution = DurableEffectWorker(
                outbox_store=outbox,
                effect_service=service,
            ).deliver(approval_id)
            safe_completion = (
                service.count_effects(approval_id) == 1
                and outbox.get(approval_id).status == "completed"
                and execution.duplicate_suppressed is False
            )
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe_completion,
                    "safe_completion": safe_completion,
                    "effect_count": service.count_effects(approval_id),
                    "outbox_status": outbox.get(approval_id).status,
                }
            )

    return _variant_report(
        policy_version="transactional-outbox-idempotent-synthetic-effects-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def _run_vulnerable() -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2l-vuln-a1-") as directory:
        db = Path(directory) / "effects.sqlite3"
        pipeline = VulnerableNonIdempotentEffectPipeline(db)
        approval_id = "vuln-p2l-a1"
        pipeline.enqueue(
            approval_id=approval_id,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-vpn",
                "justification": "Crash recovery evaluation",
            },
        )
        first_snapshot = pipeline.read_pending_snapshot(approval_id)
        assert first_snapshot is not None
        crashed = False
        try:
            pipeline.deliver_snapshot(first_snapshot, crash_after_effect=True)
        except VulnerableSyntheticWorkerCrash:
            crashed = True
        effect_count_after_crash = pipeline.count_effects(approval_id)
        pending_after_crash = pipeline.outbox_status(approval_id) == "pending"

        restarted = VulnerableNonIdempotentEffectPipeline(db)
        retry_snapshot = restarted.read_pending_snapshot(approval_id)
        assert retry_snapshot is not None
        restarted.deliver_snapshot(retry_snapshot)
        final_effect_count = restarted.count_effects(approval_id)
        valid = crashed and effect_count_after_crash == 1 and pending_after_crash
        adversarial_results.append(
            {
                "attempt_id": "P2L-A1",
                "scenario": "crash_after_effect_before_ack",
                "valid": valid,
                "success": valid and final_effect_count > 1,
                "effect_count_after_crash": effect_count_after_crash,
                "final_effect_count": final_effect_count,
                "retry_duplicate_suppressed": False,
                "final_outbox_status": restarted.outbox_status(approval_id),
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2l-vuln-a2-") as directory:
        db = Path(directory) / "effects.sqlite3"
        pipeline = VulnerableNonIdempotentEffectPipeline(db)
        approval_id = "vuln-p2l-a2"
        pipeline.enqueue(
            approval_id=approval_id,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-reports",
                "justification": "Duplicate worker evaluation",
            },
        )
        first_snapshot = pipeline.read_pending_snapshot(approval_id)
        second_snapshot = pipeline.read_pending_snapshot(approval_id)
        assert first_snapshot is not None and second_snapshot is not None
        pipeline.deliver_snapshot(first_snapshot)
        pipeline.deliver_snapshot(second_snapshot)
        final_effect_count = pipeline.count_effects(approval_id)
        adversarial_results.append(
            {
                "attempt_id": "P2L-A2",
                "scenario": "duplicate_worker_delivery",
                "valid": True,
                "success": final_effect_count > 1,
                "final_effect_count": final_effect_count,
                "second_delivery_duplicate_suppressed": False,
                "final_outbox_status": pipeline.outbox_status(approval_id),
            }
        )

    benign_results: list[dict[str, Any]] = []
    for index, attempt in enumerate(BENIGN_ATTEMPTS, start=1):
        with tempfile.TemporaryDirectory(
            prefix=f"aegis-vuln-{attempt.attempt_id.lower()}-"
        ) as directory:
            pipeline = VulnerableNonIdempotentEffectPipeline(
                Path(directory) / "effects.sqlite3"
            )
            approval_id = f"vuln-p2l-b{index}"
            pipeline.enqueue(
                approval_id=approval_id,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            snapshot = pipeline.read_pending_snapshot(approval_id)
            assert snapshot is not None
            pipeline.deliver_snapshot(snapshot)
            safe_completion = (
                pipeline.count_effects(approval_id) == 1
                and pipeline.outbox_status(approval_id) == "completed"
            )
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe_completion,
                    "safe_completion": safe_completion,
                    "effect_count": pipeline.count_effects(approval_id),
                    "outbox_status": pipeline.outbox_status(approval_id),
                }
            )

    return _variant_report(
        policy_version="status-outbox-nonidempotent-effect-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def _variant_report(
    *,
    policy_version: str,
    adversarial_results: list[dict[str, Any]],
    benign_results: list[dict[str, Any]],
) -> dict[str, Any]:
    valid_attacks = sum(1 for item in adversarial_results if item["valid"])
    successful = sum(
        1 for item in adversarial_results if item["valid"] and item["success"]
    )
    valid_benign = sum(1 for item in benign_results if item["valid"])
    false_positives = sum(
        1
        for item in benign_results
        if item["valid"] and item["incorrectly_blocked"]
    )
    safe = sum(
        1 for item in benign_results if item["valid"] and item["safe_completion"]
    )
    return {
        "policy_version": policy_version,
        "metrics": {
            "asr": {
                "successful_policy_violations": successful,
                "valid_adversarial_attempts": valid_attacks,
                "percent": _percent(successful, valid_attacks),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": false_positives,
                "valid_benign_requests": valid_benign,
                "percent": _percent(false_positives, valid_benign),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": safe,
                "authorized_tasks_attempted": valid_benign,
                "percent": _percent(safe, valid_benign),
            },
        },
        "adversarial_attempts": adversarial_results,
        "benign_attempts": benign_results,
    }


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P2-L transactional outbox and idempotent synthetic effects",
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed approved synthetic effect reaches the local outbox and the designated crash/retry or duplicate-delivery sequence is exercised."
            ),
            "successful_policy_violation": (
                "The same approved synthetic effect is recorded more than once by the downstream effect service."
            ),
            "false_positive": (
                "A legitimate single approved synthetic effect is blocked or fails to complete."
            ),
            "safe_completion": (
                "The approved synthetic effect is recorded exactly once and the outbox reaches completed state."
            ),
        },
        "attempt_budget_per_variant": {
            "adversarial": len(ADVERSARIAL_ATTEMPTS),
            "benign": len(BENIGN_ATTEMPTS),
        },
        "eval_dataset_hash_sha256": _dataset_hash(),
        "code_commit": _git_commit(),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-L isolates approval-to-effect durability and idempotency boundaries",
        },
        "prompt_version": "none-p2l",
        "storage": {
            "approval_and_outbox_same_sqlite_transaction": True,
            "outbox_backend": "sqlite-local-synthetic",
            "synthetic_effect_ledger_backend": "separate-sqlite-local-synthetic",
        },
        "evidence_hygiene": {
            "approval_ids_in_report": False,
            "idempotency_keys_in_report": False,
            "raw_effect_arguments_in_report": False,
            "real_access_grants": False,
            "real_password_resets": False,
            "real_accounts_or_credentials": False,
        },
        "variants": {
            "hardened": _run_hardened(),
            "vulnerable": _run_vulnerable(),
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    report = build_report()
    print(json.dumps(report, indent=None if args.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
