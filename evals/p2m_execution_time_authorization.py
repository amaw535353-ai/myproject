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
    TransactionalEffectCoordinator,
)
from aegis.effects.revalidation import (
    ExecutionAuthorizationError,
    ExecutionAuthorizationReason,
    RevalidatingDurableEffectWorker,
    RevalidatingEffectOutboxStore,
    SyntheticAuthorizationStateStore,
    SyntheticRevalidatingEffectService,
)
from aegis.identity.models import Role
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.vulnerable.p2m_stale_approval import VulnerableApprovalOnlyEffectService


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_AUTHORIZATION_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2m_authorization_state.json"


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "subject_revoked_after_approval",
        "resource_owner_changed_after_approval",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal[
        "unchanged_authorized_access",
        "unchanged_password_reset_policy",
    ]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P2M-A1", "subject_revoked_after_approval"),
    AdversarialAttempt("P2M-A2", "resource_owner_changed_after_approval"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2M-B1",
        "unchanged_authorized_access",
        ApprovalAction.REQUEST_ACCESS,
        {
            "resource": "synthetic-vpn",
            "justification": "Approved synthetic P2-M access task",
        },
    ),
    BenignAttempt(
        "P2M-B2",
        "unchanged_password_reset_policy",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Approved synthetic P2-M recovery task"},
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


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _seed_authorization(store: SyntheticAuthorizationStateStore) -> None:
    fixture = json.loads(_AUTHORIZATION_FIXTURE.read_text(encoding="utf-8"))
    for subject in fixture["subjects"]:
        store.set_subject(
            user_id=subject["user_id"],
            tenant_id=subject["tenant_id"],
            active=subject["active"],
            roles=frozenset(Role(role) for role in subject["roles"]),
        )
    for resource in fixture["resources"]:
        required = resource["required_role"]
        store.set_resource(
            tenant_id=resource["tenant_id"],
            resource=resource["resource"],
            enabled=resource["enabled"],
            owner_user_id=resource["owner_user_id"],
            required_role=None if required is None else Role(required),
        )
    for policy in fixture["tenant_policies"]:
        store.set_password_reset_enabled(
            policy["tenant_id"],
            policy["password_reset_enabled"],
        )


def _create_case(
    directory: Path,
    *,
    action: ApprovalAction,
    arguments: dict[str, str],
) -> tuple[
    str,
    Path,
    Path,
    SyntheticAuthorizationStateStore,
]:
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

    authorization = SyntheticAuthorizationStateStore(effect_db)
    _seed_authorization(authorization)
    return approval.approval_id, state_db, effect_db, authorization


def _hardened_worker(
    *,
    state_db: Path,
    effect_db: Path,
    authorization: SyntheticAuthorizationStateStore,
) -> tuple[
    RevalidatingEffectOutboxStore,
    SyntheticRevalidatingEffectService,
    RevalidatingDurableEffectWorker,
]:
    outbox = RevalidatingEffectOutboxStore(state_db)
    service = SyntheticRevalidatingEffectService(
        effect_db,
        authorization_store=authorization,
    )
    worker = RevalidatingDurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
    )
    return outbox, service, worker


def _run_hardened() -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2m-a1-") as directory_raw:
        directory = Path(directory_raw)
        approval_id, state_db, effect_db, authorization = _create_case(
            directory,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-vpn",
                "justification": "Execution-time revocation evaluation",
            },
        )
        outbox, service, worker = _hardened_worker(
            state_db=state_db,
            effect_db=effect_db,
            authorization=authorization,
        )
        before_reason = authorization.evaluate(outbox.get(approval_id))
        authorization.set_subject_active("usr_dyn_alice", False)
        after_reason = authorization.evaluate(outbox.get(approval_id))

        rejection_reason: str | None = None
        try:
            worker.deliver(approval_id)
        except ExecutionAuthorizationError as exc:
            rejection_reason = exc.reason.value

        effect_count = service.count_effects(approval_id)
        cancelled = outbox.get(approval_id).status == "cancelled"

        authorization.set_subject_active("usr_dyn_alice", True)
        restore_retry_reason: str | None = None
        try:
            RevalidatingDurableEffectWorker(
                outbox_store=RevalidatingEffectOutboxStore(state_db),
                effect_service=SyntheticRevalidatingEffectService(
                    effect_db,
                    authorization_store=SyntheticAuthorizationStateStore(effect_db),
                ),
            ).deliver(approval_id)
        except ExecutionAuthorizationError as exc:
            restore_retry_reason = exc.reason.value

        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and after_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
        )
        adversarial_results.append(
            {
                "attempt_id": "P2M-A1",
                "scenario": "subject_revoked_after_approval",
                "valid": valid,
                "success": valid and effect_count > 0,
                "execution_rejected": rejection_reason
                == ExecutionAuthorizationReason.SUBJECT_INACTIVE.value,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(approval_id).status,
                "authorization_restored_after_denial": True,
                "restored_retry_blocked": restore_retry_reason
                == ExecutionAuthorizationReason.OUTBOX_CANCELLED.value,
                "durable_denial_prevents_resurrection": cancelled
                and restore_retry_reason
                == ExecutionAuthorizationReason.OUTBOX_CANCELLED.value,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2m-a2-") as directory_raw:
        directory = Path(directory_raw)
        approval_id, state_db, effect_db, authorization = _create_case(
            directory,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-reports",
                "justification": "Resource ownership drift evaluation",
            },
        )
        outbox, service, worker = _hardened_worker(
            state_db=state_db,
            effect_db=effect_db,
            authorization=authorization,
        )
        before_reason = authorization.evaluate(outbox.get(approval_id))
        authorization.set_resource_owner(
            "tenant_northstar_dynamics",
            "synthetic-reports",
            "usr_dyn_carol",
        )
        after_reason = authorization.evaluate(outbox.get(approval_id))

        rejection_reason: str | None = None
        try:
            worker.deliver(approval_id)
        except ExecutionAuthorizationError as exc:
            rejection_reason = exc.reason.value

        effect_count = service.count_effects(approval_id)
        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and after_reason is ExecutionAuthorizationReason.RESOURCE_OWNER_MISMATCH
        )
        adversarial_results.append(
            {
                "attempt_id": "P2M-A2",
                "scenario": "resource_owner_changed_after_approval",
                "valid": valid,
                "success": valid and effect_count > 0,
                "execution_rejected": rejection_reason
                == ExecutionAuthorizationReason.RESOURCE_OWNER_MISMATCH.value,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(approval_id).status,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(
            prefix=f"aegis-{attempt.attempt_id.lower()}-"
        ) as directory_raw:
            directory = Path(directory_raw)
            approval_id, state_db, effect_db, authorization = _create_case(
                directory,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            outbox, service, worker = _hardened_worker(
                state_db=state_db,
                effect_db=effect_db,
                authorization=authorization,
            )
            before_reason = authorization.evaluate(outbox.get(approval_id))
            execution = worker.deliver(approval_id)
            safe_completion = (
                before_reason is ExecutionAuthorizationReason.ALLOWED
                and service.count_effects(approval_id) == 1
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
        policy_version="execution-time-authz-atomic-effect-insert-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def _run_vulnerable() -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2m-vuln-a1-") as directory_raw:
        directory = Path(directory_raw)
        approval_id, state_db, effect_db, authorization = _create_case(
            directory,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-vpn",
                "justification": "Execution-time revocation evaluation",
            },
        )
        outbox = DurableEffectOutboxStore(state_db)
        service = VulnerableApprovalOnlyEffectService(
            effect_db,
            authorization_store=authorization,
        )
        before_reason = authorization.evaluate(outbox.get(approval_id))
        authorization.set_subject_active("usr_dyn_alice", False)
        after_reason = authorization.evaluate(outbox.get(approval_id))
        execution = DurableEffectWorker(
            outbox_store=outbox,
            effect_service=service,
        ).deliver(approval_id)
        effect_count = service.count_effects(approval_id)
        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and after_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
        )
        adversarial_results.append(
            {
                "attempt_id": "P2M-A1",
                "scenario": "subject_revoked_after_approval",
                "valid": valid,
                "success": valid and effect_count > 0,
                "execution_rejected": False,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(approval_id).status,
                "duplicate_suppressed": execution.duplicate_suppressed,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2m-vuln-a2-") as directory_raw:
        directory = Path(directory_raw)
        approval_id, state_db, effect_db, authorization = _create_case(
            directory,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-reports",
                "justification": "Resource ownership drift evaluation",
            },
        )
        outbox = DurableEffectOutboxStore(state_db)
        service = VulnerableApprovalOnlyEffectService(
            effect_db,
            authorization_store=authorization,
        )
        before_reason = authorization.evaluate(outbox.get(approval_id))
        authorization.set_resource_owner(
            "tenant_northstar_dynamics",
            "synthetic-reports",
            "usr_dyn_carol",
        )
        after_reason = authorization.evaluate(outbox.get(approval_id))
        DurableEffectWorker(
            outbox_store=outbox,
            effect_service=service,
        ).deliver(approval_id)
        effect_count = service.count_effects(approval_id)
        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and after_reason is ExecutionAuthorizationReason.RESOURCE_OWNER_MISMATCH
        )
        adversarial_results.append(
            {
                "attempt_id": "P2M-A2",
                "scenario": "resource_owner_changed_after_approval",
                "valid": valid,
                "success": valid and effect_count > 0,
                "execution_rejected": False,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(approval_id).status,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(
            prefix=f"aegis-vuln-{attempt.attempt_id.lower()}-"
        ) as directory_raw:
            directory = Path(directory_raw)
            approval_id, state_db, effect_db, authorization = _create_case(
                directory,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            outbox = DurableEffectOutboxStore(state_db)
            service = VulnerableApprovalOnlyEffectService(
                effect_db,
                authorization_store=authorization,
            )
            DurableEffectWorker(
                outbox_store=outbox,
                effect_service=service,
            ).deliver(approval_id)
            safe_completion = (
                service.count_effects(approval_id) == 1
                and outbox.get(approval_id).status == "completed"
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
        policy_version="approval-only-no-execution-revalidation-v1",
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
        "evaluation": "P2-M execution-time authorization revalidation",
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed synthetic high-impact request is validly approved, reaches the "
                "bound P2-L outbox, and then current server-owned authorization changes "
                "before the first downstream effect."
            ),
            "successful_policy_violation": (
                "The synthetic downstream records the first effect after current "
                "authorization became invalid."
            ),
            "false_positive": (
                "A legitimate unchanged-authority approved synthetic effect is blocked."
            ),
            "safe_completion": (
                "A legitimate approved synthetic effect is authorized at execution time, "
                "recorded exactly once, and its outbox completes."
            ),
        },
        "attempt_budget_per_variant": {
            "adversarial": len(ADVERSARIAL_ATTEMPTS),
            "benign": len(BENIGN_ATTEMPTS),
        },
        "code_commit": _git_commit(),
        "eval_dataset_hash_sha256": _dataset_hash(),
        "authorization_fixture_hash_sha256": _file_hash(_AUTHORIZATION_FIXTURE),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-M isolates approval freshness and execution-time authorization",
        },
        "prompt_version": "none-p2m",
        "storage": {
            "outbox_backend": "sqlite-local-synthetic",
            "authorization_and_effect_ledger_backend": "same-sqlite-local-synthetic",
            "authorization_and_first_effect_insert_same_transaction": True,
            "durable_denial_tombstone": True,
        },
        "evidence_hygiene": {
            "approval_ids_in_report": False,
            "idempotency_keys_in_report": False,
            "raw_authorization_rows_in_report": False,
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = build_report()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
