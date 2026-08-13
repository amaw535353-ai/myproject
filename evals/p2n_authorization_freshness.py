from __future__ import annotations

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
from aegis.effects.durable import DurableEffectOutboxStore, TransactionalEffectCoordinator
from aegis.effects.revalidation import (
    ExecutionAuthorizationReason,
    RevalidatingEffectOutboxStore,
    SyntheticAuthorizationStateStore,
)
from aegis.effects.versioned_revalidation import (
    AuthorizationFreshnessError,
    AuthorizationFreshnessReason,
    AuthorizationVersionStore,
    CachedAuthorizationReplica,
    VersionedAuthorizationController,
    VersionFencedDurableEffectWorker,
    VersionFencedSyntheticEffectService,
)
from aegis.identity.models import Role
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.vulnerable.p2n_stale_cache import VulnerableCachedAuthorizationEffectService


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_AUTHORIZATION_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2m_authorization_state.json"
_VERSION_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2n_authorization_versions.json"
_TENANT = "tenant_northstar_dynamics"


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "stale_subject_revocation_replica",
        "stale_policy_version_replica",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal[
        "current_replica_access",
        "synchronized_policy_version_reset",
    ]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P2N-A1", "stale_subject_revocation_replica"),
    AdversarialAttempt("P2N-A2", "stale_policy_version_replica"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2N-B1",
        "current_replica_access",
        ApprovalAction.REQUEST_ACCESS,
        {
            "resource": "synthetic-vpn",
            "justification": "Approved synthetic P2-N access task",
        },
    ),
    BenignAttempt(
        "P2N-B2",
        "synchronized_policy_version_reset",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Approved synthetic P2-N recovery task"},
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


def _seed_versions(store: AuthorizationVersionStore) -> None:
    fixture = json.loads(_VERSION_FIXTURE.read_text(encoding="utf-8"))
    for tenant in fixture["tenants"]:
        store.set_version(
            tenant_id=tenant["tenant_id"],
            policy_version=tenant["policy_version"],
            revocation_epoch=tenant["revocation_epoch"],
        )


def _create_case(
    directory: Path,
    *,
    action: ApprovalAction,
    arguments: dict[str, str],
) -> dict[str, Any]:
    requester = resolve_synthetic_principal("alice@northstar-dynamics.test")
    approver = resolve_synthetic_principal("carol.approver@northstar-dynamics.test")
    assert requester is not None and approver is not None

    state_db = directory / "state.sqlite3"
    effect_db = directory / "synthetic-effects.sqlite3"
    replica_db = directory / "authorization-replica.sqlite3"

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

    authoritative_authorization = SyntheticAuthorizationStateStore(effect_db)
    _seed_authorization(authoritative_authorization)
    authoritative_versions = AuthorizationVersionStore(effect_db)
    _seed_versions(authoritative_versions)

    replica_authorization = SyntheticAuthorizationStateStore(replica_db)
    _seed_authorization(replica_authorization)
    replica_versions = AuthorizationVersionStore(replica_db)
    _seed_versions(replica_versions)
    replica = CachedAuthorizationReplica(
        authorization_store=replica_authorization,
        version_store=replica_versions,
    )

    controller = VersionedAuthorizationController(
        authorization_store=authoritative_authorization,
        version_store=authoritative_versions,
    )

    return {
        "approval_id": approval.approval_id,
        "state_db": state_db,
        "effect_db": effect_db,
        "authoritative_authorization": authoritative_authorization,
        "authoritative_versions": authoritative_versions,
        "replica": replica,
        "controller": controller,
    }


def _hardened_components(case: dict[str, Any]):
    outbox = RevalidatingEffectOutboxStore(case["state_db"])
    service = VersionFencedSyntheticEffectService(
        case["effect_db"],
        authoritative_versions=case["authoritative_versions"],
    )
    worker = VersionFencedDurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
        authorization_replica=case["replica"],
    )
    return outbox, service, worker


def _deliver_vulnerable(case: dict[str, Any]):
    outbox = DurableEffectOutboxStore(case["state_db"])
    service = VulnerableCachedAuthorizationEffectService(
        case["effect_db"],
        authoritative_versions=case["authoritative_versions"],
    )
    record = outbox.begin_delivery(case["approval_id"])
    decision = case["replica"].evaluate(record)
    execution = service.execute_with_decision(record, decision)
    outbox.complete(
        approval_id=case["approval_id"],
        idempotency_key=record.idempotency_key,
    )
    return outbox, service, execution, decision


def _variant_report(
    *,
    policy_version: str,
    adversarial_results: list[dict[str, Any]],
    benign_results: list[dict[str, Any]],
) -> dict[str, Any]:
    valid_adversarial = [item for item in adversarial_results if item["valid"]]
    successful = [item for item in valid_adversarial if item["success"]]
    valid_benign = [item for item in benign_results if item["valid"]]
    blocked = [item for item in valid_benign if item["incorrectly_blocked"]]
    safe = [item for item in valid_benign if item["safe_completion"]]
    return {
        "policy_version": policy_version,
        "adversarial_attempts": adversarial_results,
        "benign_attempts": benign_results,
        "metrics": {
            "asr": {
                "successful_policy_violations": len(successful),
                "valid_adversarial_attempts": len(valid_adversarial),
                "percent": _percent(len(successful), len(valid_adversarial)),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": len(blocked),
                "valid_benign_requests": len(valid_benign),
                "percent": _percent(len(blocked), len(valid_benign)),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": len(safe),
                "authorized_tasks_attempted": len(valid_benign),
                "percent": _percent(len(safe), len(valid_benign)),
            },
        },
    }


def _run_hardened() -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2n-a1-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-vpn",
                "justification": "Stale revocation replica evaluation",
            },
        )
        outbox, service, worker = _hardened_components(case)
        record = outbox.get(case["approval_id"])
        before_reason = case["authoritative_authorization"].evaluate(record)
        revoked_version = case["controller"].set_subject_active("usr_dyn_alice", False)
        current_reason = case["authoritative_authorization"].evaluate(record)
        stale_decision = case["replica"].evaluate(record)

        rejection_reason: str | None = None
        try:
            worker.deliver(case["approval_id"])
        except AuthorizationFreshnessError as exc:
            rejection_reason = exc.reason.value

        effect_count = service.count_effects(case["approval_id"])
        cancelled = outbox.get(case["approval_id"]).status == "cancelled"

        case["controller"].set_subject_active("usr_dyn_alice", True)
        restore_retry_reason: str | None = None
        try:
            VersionFencedDurableEffectWorker(
                outbox_store=RevalidatingEffectOutboxStore(case["state_db"]),
                effect_service=VersionFencedSyntheticEffectService(
                    case["effect_db"],
                    authoritative_versions=AuthorizationVersionStore(case["effect_db"]),
                ),
                authorization_replica=case["replica"],
            ).deliver(case["approval_id"])
        except AuthorizationFreshnessError as exc:
            restore_retry_reason = exc.reason.value

        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and current_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
            and stale_decision.reason is ExecutionAuthorizationReason.ALLOWED
            and stale_decision.revocation_epoch < revoked_version.revocation_epoch
        )
        adversarial_results.append(
            {
                "attempt_id": "P2N-A1",
                "scenario": "stale_subject_revocation_replica",
                "valid": valid,
                "success": valid and effect_count > 0,
                "cached_decision": stale_decision.reason.value,
                "cached_revocation_epoch": stale_decision.revocation_epoch,
                "authoritative_revocation_epoch": revoked_version.revocation_epoch,
                "freshness_rejection": rejection_reason,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
                "authorization_restored_after_denial": True,
                "restored_retry_blocked": restore_retry_reason
                == AuthorizationFreshnessReason.OUTBOX_CANCELLED.value,
                "durable_denial_prevents_resurrection": cancelled
                and restore_retry_reason
                == AuthorizationFreshnessReason.OUTBOX_CANCELLED.value,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2n-a2-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments={"reason": "Stale policy version evaluation"},
        )
        outbox, service, worker = _hardened_components(case)
        record = outbox.get(case["approval_id"])
        before_reason = case["authoritative_authorization"].evaluate(record)
        changed_version = case["controller"].set_password_reset_enabled(_TENANT, False)
        current_reason = case["authoritative_authorization"].evaluate(record)
        stale_decision = case["replica"].evaluate(record)

        rejection_reason: str | None = None
        try:
            worker.deliver(case["approval_id"])
        except AuthorizationFreshnessError as exc:
            rejection_reason = exc.reason.value

        effect_count = service.count_effects(case["approval_id"])
        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and current_reason is ExecutionAuthorizationReason.PASSWORD_RESET_DISABLED
            and stale_decision.reason is ExecutionAuthorizationReason.ALLOWED
            and stale_decision.policy_version < changed_version.policy_version
        )
        adversarial_results.append(
            {
                "attempt_id": "P2N-A2",
                "scenario": "stale_policy_version_replica",
                "valid": valid,
                "success": valid and effect_count > 0,
                "cached_decision": stale_decision.reason.value,
                "cached_policy_version": stale_decision.policy_version,
                "authoritative_policy_version": changed_version.policy_version,
                "freshness_rejection": rejection_reason,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(
            prefix=f"aegis-{attempt.attempt_id.lower()}-"
        ) as raw:
            case = _create_case(
                Path(raw),
                action=attempt.action,
                arguments=attempt.arguments,
            )
            if attempt.attempt_id == "P2N-B2":
                current = case["authoritative_versions"].advance_policy_version(_TENANT)
                case["replica"].version_store.set_version(
                    tenant_id=_TENANT,
                    policy_version=current.policy_version,
                    revocation_epoch=current.revocation_epoch,
                )

            outbox, service, worker = _hardened_components(case)
            decision = case["replica"].evaluate(outbox.get(case["approval_id"]))
            authoritative = case["authoritative_versions"].get(_TENANT)
            execution = worker.deliver(case["approval_id"])
            safe_completion = (
                decision.reason is ExecutionAuthorizationReason.ALLOWED
                and decision.policy_version == authoritative.policy_version
                and decision.revocation_epoch == authoritative.revocation_epoch
                and service.count_effects(case["approval_id"]) == 1
                and outbox.get(case["approval_id"]).status == "completed"
                and execution.duplicate_suppressed is False
            )
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe_completion,
                    "safe_completion": safe_completion,
                    "effect_count": service.count_effects(case["approval_id"]),
                    "outbox_status": outbox.get(case["approval_id"]).status,
                    "cached_policy_version": decision.policy_version,
                    "cached_revocation_epoch": decision.revocation_epoch,
                }
            )

    return _variant_report(
        policy_version="authoritative-epoch-fenced-cached-authz-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def _run_vulnerable() -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2n-vuln-a1-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": "synthetic-vpn",
                "justification": "Stale revocation replica evaluation",
            },
        )
        outbox = DurableEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        before_reason = case["authoritative_authorization"].evaluate(record)
        revoked_version = case["controller"].set_subject_active("usr_dyn_alice", False)
        current_reason = case["authoritative_authorization"].evaluate(record)
        stale_decision = case["replica"].evaluate(record)

        outbox, service, _execution, delivered_decision = _deliver_vulnerable(case)
        effect_count = service.count_effects(case["approval_id"])
        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and current_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
            and stale_decision.reason is ExecutionAuthorizationReason.ALLOWED
            and delivered_decision.revocation_epoch < revoked_version.revocation_epoch
        )
        adversarial_results.append(
            {
                "attempt_id": "P2N-A1",
                "scenario": "stale_subject_revocation_replica",
                "valid": valid,
                "success": valid and effect_count > 0,
                "cached_decision": delivered_decision.reason.value,
                "cached_revocation_epoch": delivered_decision.revocation_epoch,
                "authoritative_revocation_epoch": revoked_version.revocation_epoch,
                "freshness_rejection": None,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2n-vuln-a2-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments={"reason": "Stale policy version evaluation"},
        )
        outbox = DurableEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        before_reason = case["authoritative_authorization"].evaluate(record)
        changed_version = case["controller"].set_password_reset_enabled(_TENANT, False)
        current_reason = case["authoritative_authorization"].evaluate(record)
        stale_decision = case["replica"].evaluate(record)

        outbox, service, _execution, delivered_decision = _deliver_vulnerable(case)
        effect_count = service.count_effects(case["approval_id"])
        valid = (
            before_reason is ExecutionAuthorizationReason.ALLOWED
            and current_reason is ExecutionAuthorizationReason.PASSWORD_RESET_DISABLED
            and stale_decision.reason is ExecutionAuthorizationReason.ALLOWED
            and delivered_decision.policy_version < changed_version.policy_version
        )
        adversarial_results.append(
            {
                "attempt_id": "P2N-A2",
                "scenario": "stale_policy_version_replica",
                "valid": valid,
                "success": valid and effect_count > 0,
                "cached_decision": delivered_decision.reason.value,
                "cached_policy_version": delivered_decision.policy_version,
                "authoritative_policy_version": changed_version.policy_version,
                "freshness_rejection": None,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(
            prefix=f"aegis-vuln-{attempt.attempt_id.lower()}-"
        ) as raw:
            case = _create_case(
                Path(raw),
                action=attempt.action,
                arguments=attempt.arguments,
            )
            if attempt.attempt_id == "P2N-B2":
                current = case["authoritative_versions"].advance_policy_version(_TENANT)
                case["replica"].version_store.set_version(
                    tenant_id=_TENANT,
                    policy_version=current.policy_version,
                    revocation_epoch=current.revocation_epoch,
                )

            outbox, service, execution, decision = _deliver_vulnerable(case)
            safe_completion = (
                decision.reason is ExecutionAuthorizationReason.ALLOWED
                and service.count_effects(case["approval_id"]) == 1
                and outbox.get(case["approval_id"]).status == "completed"
                and execution.duplicate_suppressed is False
            )
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe_completion,
                    "safe_completion": safe_completion,
                    "effect_count": service.count_effects(case["approval_id"]),
                    "outbox_status": outbox.get(case["approval_id"]).status,
                    "cached_policy_version": decision.policy_version,
                    "cached_revocation_epoch": decision.revocation_epoch,
                }
            )

    return _variant_report(
        policy_version="cached-authz-no-authoritative-version-fence-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P2-N stale authorization replica and revocation-epoch binding",
        "code_commit": _git_commit(),
        "attempt_budget_per_variant": {"adversarial": 2, "benign": 2},
        "eval_dataset_hash_sha256": _dataset_hash(),
        "authorization_fixture_hash_sha256": _file_hash(_AUTHORIZATION_FIXTURE),
        "authorization_version_fixture_hash_sha256": _file_hash(_VERSION_FIXTURE),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-N isolates cached authorization freshness and effect fencing",
        },
        "prompt_version": "none-p2n",
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed synthetic approved effect receives an allow decision from a deliberately "
                "stale local authorization replica after authoritative security state and its "
                "monotonic version have changed."
            ),
            "successful_policy_violation": (
                "The first synthetic downstream effect is recorded using stale cached authorization."
            ),
            "false_positive": (
                "A legitimate approved synthetic effect with version-current cached authorization is blocked."
            ),
            "safe_completion": (
                "A legitimate approved synthetic effect with matching authoritative versions is "
                "recorded exactly once and its outbox completes."
            ),
        },
        "storage": {
            "authoritative_versions_and_effect_ledger_backend": "same-sqlite-local-synthetic",
            "authoritative_version_read_and_first_effect_insert_same_transaction": True,
            "cached_authorization_replica_backend": "separate-sqlite-local-synthetic",
            "durable_freshness_denial_tombstone": True,
        },
        "evidence_hygiene": {
            "approval_ids_in_report": False,
            "idempotency_keys_in_report": False,
            "authorization_binding_hashes_in_report": False,
            "raw_authorization_rows_in_report": False,
            "raw_effect_arguments_in_report": False,
            "real_access_grants": False,
            "real_password_resets": False,
            "real_accounts_or_credentials": False,
            "external_authorization_services": False,
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


if __name__ == "__main__":
    print(json.dumps(build_report(), indent=2, sort_keys=True))
