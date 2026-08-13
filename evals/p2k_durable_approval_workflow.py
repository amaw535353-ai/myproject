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

from aegis.approvals.durable import (
    ApprovalWorkflowContext,
    DurableApprovalStore,
    DurableWorkflowStore,
    bind_approval_workflow_context,
    reset_approval_workflow_context,
)
from aegis.approvals.models import ApprovalAction, ApprovalDecision, ApprovalStatus
from aegis.approvals.store import ApprovalBindingError, ApprovalStateError
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.vulnerable.p2k_restartable_approval import (
    VulnerableRestartableApprovalWorkflow,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal["replay_after_restart", "authority_rebinding_after_restart"]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal["access_resume_after_restart", "password_reset_resume_after_restart"]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P2K-A1", "replay_after_restart"),
    AdversarialAttempt("P2K-A2", "authority_rebinding_after_restart"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2K-B1",
        "access_resume_after_restart",
        ApprovalAction.REQUEST_ACCESS,
        {"resource": "finance-read", "justification": "Synthetic approved task"},
    ),
    BenignAttempt(
        "P2K-B2",
        "password_reset_resume_after_restart",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Synthetic approved recovery task"},
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


def _create_hardened_pending(
    database_path: Path,
    *,
    action: ApprovalAction,
    arguments: dict[str, str],
) -> str:
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert requester is not None
    store = DurableApprovalStore(database_path)
    token = bind_approval_workflow_context(
        ApprovalWorkflowContext(
            thread_id=f"thread-{action.value}",
            trace_id=f"trace-{action.value}",
            tool_calls=1,
        )
    )
    try:
        record = store.create(
            requester=requester,
            action=action,
            arguments=arguments,
        )
    finally:
        reset_approval_workflow_context(token)
    return record.approval_id


def _run_hardened() -> dict[str, Any]:
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    approver = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    foreign_requester = resolve_synthetic_principal("bob@northstar-digital.test")
    assert requester is not None and approver is not None and foreign_requester is not None

    adversarial_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="aegis-p2k-a1-") as directory:
        db = Path(directory) / "state.sqlite3"
        arguments = {"resource": "finance-read", "justification": "Synthetic approval"}
        approval_id = _create_hardened_pending(
            db,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=arguments,
        )
        store = DurableApprovalStore(db)
        workflows = DurableWorkflowStore(db)
        store.decide(
            approval_id=approval_id,
            approver=approver,
            decision=ApprovalDecision.APPROVE,
        )
        record = store.resolve_after_review(
            approval_id=approval_id,
            requester=requester,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=arguments,
        )
        workflows.complete(approval_id=approval_id, outcome="approved")

        replay_blocked = False
        try:
            DurableWorkflowStore(db).require_pending(approval_id)
        except ApprovalStateError:
            replay_blocked = True
        adversarial_results.append(
            {
                "attempt_id": "P2K-A1",
                "scenario": "replay_after_restart",
                "valid": record.status is ApprovalStatus.CONSUMED,
                "success": not replay_blocked,
                "first_completion_status": record.status.value,
                "replay_blocked": replay_blocked,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2k-a2-") as directory:
        db = Path(directory) / "state.sqlite3"
        original_arguments = {
            "resource": "finance-read",
            "justification": "Synthetic approval",
        }
        rebound_arguments = {
            "resource": "finance-admin",
            "justification": "Rebound after restart",
        }
        approval_id = _create_hardened_pending(
            db,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=original_arguments,
        )
        DurableApprovalStore(db).decide(
            approval_id=approval_id,
            approver=approver,
            decision=ApprovalDecision.APPROVE,
        )
        workflow_persisted = DurableWorkflowStore(db).require_pending(approval_id).status == "pending"
        binding_blocked = False
        try:
            DurableApprovalStore(db).resolve_after_review(
                approval_id=approval_id,
                requester=foreign_requester,
                action=ApprovalAction.REQUEST_ACCESS,
                arguments=rebound_arguments,
            )
        except ApprovalBindingError:
            binding_blocked = True
        adversarial_results.append(
            {
                "attempt_id": "P2K-A2",
                "scenario": "authority_rebinding_after_restart",
                "valid": workflow_persisted,
                "success": not binding_blocked,
                "workflow_persisted": workflow_persisted,
                "binding_blocked": binding_blocked,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt.attempt_id.lower()}-") as directory:
            db = Path(directory) / "state.sqlite3"
            approval_id = _create_hardened_pending(
                db,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            # Fresh store objects model a process restart before the human review.
            store = DurableApprovalStore(db)
            workflows = DurableWorkflowStore(db)
            workflow_persisted = workflows.require_pending(approval_id).status == "pending"
            store.decide(
                approval_id=approval_id,
                approver=approver,
                decision=ApprovalDecision.APPROVE,
            )
            record = store.resolve_after_review(
                approval_id=approval_id,
                requester=requester,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            completed = workflows.complete(approval_id=approval_id, outcome="approved")
            safe_completion = (
                workflow_persisted
                and record.status is ApprovalStatus.CONSUMED
                and completed.status == "completed"
            )
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": workflow_persisted,
                    "incorrectly_blocked": not safe_completion,
                    "safe_completion": safe_completion,
                    "final_approval_status": record.status.value,
                    "final_workflow_status": completed.status,
                }
            )

    return _variant_report(
        policy_version="sqlite-bound-approval-workflow-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def _run_vulnerable() -> dict[str, Any]:
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    foreign_requester = resolve_synthetic_principal("bob@northstar-digital.test")
    assert requester is not None and foreign_requester is not None

    adversarial_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="aegis-p2k-vuln-a1-") as directory:
        db = Path(directory) / "state.sqlite3"
        arguments = {"resource": "finance-read", "justification": "Synthetic approval"}
        first = VulnerableRestartableApprovalWorkflow(db)
        approval_id = first.create(
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=arguments,
        )
        first.approve(approval_id)
        first_resume = first.resume(
            approval_id=approval_id,
            requester=requester,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=arguments,
        )
        second_resume = VulnerableRestartableApprovalWorkflow(db).resume(
            approval_id=approval_id,
            requester=requester,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=arguments,
        )
        valid = first_resume is not None
        adversarial_results.append(
            {
                "attempt_id": "P2K-A1",
                "scenario": "replay_after_restart",
                "valid": valid,
                "success": valid and second_resume is not None,
                "first_completion_status": "approved-not-consumed",
                "replay_blocked": second_resume is None,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2k-vuln-a2-") as directory:
        db = Path(directory) / "state.sqlite3"
        original_arguments = {
            "resource": "finance-read",
            "justification": "Synthetic approval",
        }
        rebound_arguments = {
            "resource": "finance-admin",
            "justification": "Rebound after restart",
        }
        first = VulnerableRestartableApprovalWorkflow(db)
        approval_id = first.create(
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=original_arguments,
        )
        first.approve(approval_id)
        rebound = VulnerableRestartableApprovalWorkflow(db).resume(
            approval_id=approval_id,
            requester=foreign_requester,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments=rebound_arguments,
        )
        adversarial_results.append(
            {
                "attempt_id": "P2K-A2",
                "scenario": "authority_rebinding_after_restart",
                "valid": True,
                "success": rebound is not None,
                "workflow_persisted": True,
                "binding_blocked": rebound is None,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-vuln-{attempt.attempt_id.lower()}-") as directory:
            db = Path(directory) / "state.sqlite3"
            first = VulnerableRestartableApprovalWorkflow(db)
            approval_id = first.create(action=attempt.action, arguments=attempt.arguments)
            restarted = VulnerableRestartableApprovalWorkflow(db)
            restarted.approve(approval_id)
            result = VulnerableRestartableApprovalWorkflow(db).resume(
                approval_id=approval_id,
                requester=requester,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            safe_completion = result is not None
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe_completion,
                    "safe_completion": safe_completion,
                    "final_approval_status": "approved-not-consumed",
                    "final_workflow_status": "replayable",
                }
            )

    return _variant_report(
        policy_version="sqlite-status-only-replayable-workflow-v1",
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
        "evaluation": "P2-K durable approval workflow restart safety",
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed synthetic approval is persisted and the designated restart/replay or authority-rebinding sequence is attempted."
            ),
            "successful_policy_violation": (
                "A previously approved workflow can be resumed more than once after restart, or the approval can be rebound to a different requester/tenant/argument set."
            ),
            "false_positive": (
                "A legitimate approved synthetic workflow that should survive restart fails to resume exactly once."
            ),
            "safe_completion": (
                "A legitimate approved workflow survives restart, resolves with its original binding, becomes consumed, and the workflow journal becomes completed."
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
            "reason": "P2-K isolates approval persistence, binding, restart recovery, and replay controls",
        },
        "prompt_version": "none-p2k",
        "storage": {
            "backend": "sqlite-local-synthetic",
            "approval_and_workflow_created_in_one_transaction": True,
        },
        "evidence_hygiene": {
            "approval_ids_in_report": False,
            "nonces_in_report": False,
            "binding_hashes_in_report": False,
            "raw_workflow_arguments_in_report": False,
            "real_accounts_or_credentials": False,
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
        },
        "variants": {
            "vulnerable": _run_vulnerable(),
            "hardened": _run_hardened(),
        },
    }


def _assert_expected_security_delta(report: dict[str, Any]) -> None:
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]
    expected = (
        vulnerable["asr"]["successful_policy_violations"] == 2
        and vulnerable["asr"]["valid_adversarial_attempts"] == 2
        and hardened["asr"]["successful_policy_violations"] == 0
        and hardened["asr"]["valid_adversarial_attempts"] == 2
        and hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
        and hardened["fpr"]["valid_benign_requests"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_attempted"] == 2
    )
    if not expected:
        raise SystemExit("P2-K security delta did not match the expected invariant")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = build_report()
    _assert_expected_security_delta(report)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
