from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from aegis.approvals.models import ApprovalAction
from aegis.effects.control_plane_recovery import (
    ControlPlaneChangeStatus,
    ControlPlaneConvergenceError,
    ControlPlaneCrashPoint,
    ControlPlaneMutation,
    ControlPlaneMutationKind,
    CrashSafeControlPlaneCoordinator,
    CrashSafeControlPlaneDurableEffectWorker,
    CrashSafeRollbackResistantSyntheticEffectService,
    RecoverableAnchoredAuthorizationReplica,
    SyntheticControlPlaneCrash,
)
from aegis.effects.revalidation import ExecutionAuthorizationReason, RevalidatingEffectOutboxStore
from aegis.effects.rollback_anchor import (
    AnchoredAuthorizationReplica,
    AnchoredAuthorizationSigner,
    ControlPlaneGenerationStore,
    RollbackResistantDurableEffectWorker,
    RollbackResistantSyntheticEffectService,
)
from aegis.effects.signed_authorization import TrustedAuthorizationKeyStore
from aegis.effects.versioned_revalidation import CachedAuthorizationReplica
from aegis.vulnerable.p2q_partial_control_plane import VulnerableUncoordinatedControlPlane
from evals.p2n_authorization_freshness import _create_case
from evals.p2o_authorization_provenance import _clock, _key_fixture, _signer, _trust_initial


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_RECOVERY_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2q_control_plane_recovery.json"
_KEY_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2o_authorization_keys.json"


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "partial_subject_reactivation_before_generation_activation",
        "partial_signing_key_rotation_before_generation_activation",
    ]
    action: ApprovalAction
    arguments: dict[str, str]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal[
        "recovered_subject_reactivation",
        "recovered_signing_key_rotation",
    ]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt(
        "P2Q-A1",
        "partial_subject_reactivation_before_generation_activation",
        ApprovalAction.REQUEST_ACCESS,
        {
            "resource": "synthetic-vpn",
            "justification": "Synthetic P2-Q partial subject-reactivation crash",
        },
    ),
    AdversarialAttempt(
        "P2Q-A2",
        "partial_signing_key_rotation_before_generation_activation",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Synthetic P2-Q partial signing-key rotation crash"},
    ),
)

BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2Q-B1",
        "recovered_subject_reactivation",
        ApprovalAction.REQUEST_ACCESS,
        {
            "resource": "synthetic-vpn",
            "justification": "Synthetic P2-Q recovered access task",
        },
    ),
    BenignAttempt(
        "P2Q-B2",
        "recovered_signing_key_rotation",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Synthetic P2-Q recovered password-reset task"},
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
            "adversarial": [
                {
                    "attempt_id": item.attempt_id,
                    "scenario": item.scenario,
                    "action": item.action.value,
                    "arguments": item.arguments,
                }
                for item in ADVERSARIAL_ATTEMPTS
            ],
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


def _recovery_fixture() -> dict[str, Any]:
    return json.loads(_RECOVERY_FIXTURE.read_text(encoding="utf-8"))


def _live_authorization_replica(case: dict[str, Any]) -> CachedAuthorizationReplica:
    return CachedAuthorizationReplica(
        authorization_store=case["authoritative_authorization"],
        version_store=case["authoritative_versions"],
    )


def _subject_reactivation_mutation() -> ControlPlaneMutation:
    return ControlPlaneMutation(
        kind=ControlPlaneMutationKind.SUBJECT_ACTIVE,
        tenant_id="tenant_northstar_dynamics",
        user_id="usr_dyn_alice",
        active=True,
    )


def _key_rotation_mutation(key_fixture: dict[str, Any], key2: dict[str, Any]) -> ControlPlaneMutation:
    signer = _signer(key_fixture, key2)
    return ControlPlaneMutation(
        kind=ControlPlaneMutationKind.SIGNING_KEY_ROTATION,
        issuer_id=str(key_fixture["issuer_id"]),
        audience=str(key_fixture["audience"]),
        key_id=str(key2["key_id"]),
        key_epoch=int(key2["key_epoch"]),
        public_key_hex=signer.public_key_bytes().hex(),
    )


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


def _initialize_case(
    *,
    root: Path,
    action: ApprovalAction,
    arguments: dict[str, str],
    subject_starts_inactive: bool,
) -> tuple[
    dict[str, Any],
    TrustedAuthorizationKeyStore,
    ControlPlaneGenerationStore,
    str,
    dict[str, Any],
    dict[str, Any],
]:
    case = _create_case(root, action=action, arguments=arguments)
    key_fixture = _key_fixture()
    key1, key2 = key_fixture["keys"]
    registry = TrustedAuthorizationKeyStore(case["effect_db"])
    _trust_initial(registry, key_fixture, key1)
    if subject_starts_inactive:
        case["controller"].set_subject_active("usr_dyn_alice", False)
    recovery_fixture = _recovery_fixture()
    authority_id = str(recovery_fixture["authority_id"])
    generation_store = ControlPlaneGenerationStore(root / "control-plane-anchor.sqlite3")
    return case, registry, generation_store, authority_id, key1, key2


def _build_delivery_stack(
    *,
    hardened: bool,
    case: dict[str, Any],
    registry: TrustedAuthorizationKeyStore,
    generation_store: ControlPlaneGenerationStore,
    authority_id: str,
    signer_key: dict[str, Any],
    coordinator: CrashSafeControlPlaneCoordinator | None,
):
    key_fixture = _key_fixture()
    live_replica = _live_authorization_replica(case)
    anchored_signer = AnchoredAuthorizationSigner(_signer(key_fixture, signer_key))
    outbox = RevalidatingEffectOutboxStore(case["state_db"])
    if hardened:
        assert coordinator is not None
        replica = RecoverableAnchoredAuthorizationReplica(
            authorization_replica=live_replica,
            signer=anchored_signer,
            coordinator=coordinator,
        )
        service = CrashSafeRollbackResistantSyntheticEffectService(
            case["effect_db"],
            authoritative_versions=case["authoritative_versions"],
            trusted_keys=registry,
            coordinator=coordinator,
            expected_issuer_id=str(key_fixture["issuer_id"]),
            expected_audience=str(key_fixture["audience"]),
            clock=_clock,
        )
        worker = CrashSafeControlPlaneDurableEffectWorker(
            outbox_store=outbox,
            effect_service=service,
            authorization_replica=replica,
        )
        return outbox, service, worker

    replica = AnchoredAuthorizationReplica(
        authorization_replica=live_replica,
        signer=anchored_signer,
        generation_store=generation_store,
        authority_id=authority_id,
    )
    service = RollbackResistantSyntheticEffectService(
        case["effect_db"],
        authoritative_versions=case["authoritative_versions"],
        trusted_keys=registry,
        generation_store=generation_store,
        authority_id=authority_id,
        expected_issuer_id=str(key_fixture["issuer_id"]),
        expected_audience=str(key_fixture["audience"]),
        clock=_clock,
    )
    worker = RollbackResistantDurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
        authorization_replica=replica,
    )
    return outbox, service, worker


def _run_adversarial(*, hardened: bool) -> list[dict[str, Any]]:
    recovery_fixture = _recovery_fixture()
    initial_generation = int(recovery_fixture["initial_generation"])
    key_fixture = _key_fixture()
    results: list[dict[str, Any]] = []

    for attempt in ADVERSARIAL_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt.attempt_id.lower()}-") as raw:
            root = Path(raw)
            is_subject_case = attempt.attempt_id == "P2Q-A1"
            case, registry, generation_store, authority_id, key1, key2 = _initialize_case(
                root=root,
                action=attempt.action,
                arguments=attempt.arguments,
                subject_starts_inactive=is_subject_case,
            )
            outbox_probe = RevalidatingEffectOutboxStore(case["state_db"])
            record = outbox_probe.get(case["approval_id"])
            if is_subject_case:
                before_reason = case["authoritative_authorization"].evaluate(record)
                mutation = _subject_reactivation_mutation()
                signer_key = key1
            else:
                before_reason = case["authoritative_authorization"].evaluate(record)
                mutation = _key_rotation_mutation(key_fixture, key2)
                signer_key = key2

            coordinator: CrashSafeControlPlaneCoordinator | None = None
            if hardened:
                coordinator = CrashSafeControlPlaneCoordinator(
                    execution_database_path=case["effect_db"],
                    generation_store=generation_store,
                    authority_id=authority_id,
                )
                coordinator.initialize(generation=initial_generation)
                control_plane = coordinator
            else:
                generation_store.initialize(
                    authority_id=authority_id,
                    generation=initial_generation,
                )
                control_plane = VulnerableUncoordinatedControlPlane(
                    controller=case["controller"],
                    trusted_keys=registry,
                    generation_store=generation_store,
                    authority_id=authority_id,
                )

            crash_point: str | None = None
            try:
                control_plane.commit(
                    change_id=f"synthetic-{attempt.attempt_id.lower()}-change",
                    mutation=mutation,
                    crash_at=ControlPlaneCrashPoint.AFTER_EXECUTION_APPLY,
                )
            except SyntheticControlPlaneCrash as exc:
                crash_point = exc.point.value

            after_reason = case["authoritative_authorization"].evaluate(record)
            anchor_before_recovery = generation_store.current(authority_id)
            execution_generation_before_recovery: int | None = None
            journal_status_before_recovery: str | None = None
            if coordinator is not None:
                execution_generation_before_recovery = coordinator.execution_state().applied_generation
                pending = coordinator.pending_change()
                journal_status_before_recovery = None if pending is None else pending.status.value

            outbox, service, worker = _build_delivery_stack(
                hardened=hardened,
                case=case,
                registry=registry,
                generation_store=generation_store,
                authority_id=authority_id,
                signer_key=signer_key,
                coordinator=coordinator,
            )
            rejection: str | None = None
            try:
                worker.deliver(case["approval_id"])
            except ControlPlaneConvergenceError as exc:
                rejection = exc.reason.value

            pre_recovery_effect_count = service.count_effects(case["approval_id"])
            pre_recovery_outbox_status = outbox.get(case["approval_id"]).status
            recovered_generation: int | None = None
            post_recovery_effect_count = pre_recovery_effect_count
            post_recovery_outbox_status = pre_recovery_outbox_status
            if coordinator is not None:
                recovered = coordinator.recover()
                recovered_generation = (
                    None if recovered is None else recovered.target_generation
                )
                worker.deliver(case["approval_id"])
                post_recovery_effect_count = service.count_effects(case["approval_id"])
                post_recovery_outbox_status = outbox.get(case["approval_id"]).status

            if is_subject_case:
                mutation_became_locally_authoritative = (
                    before_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
                    and after_reason is ExecutionAuthorizationReason.ALLOWED
                )
                mutation_evidence = {
                    "authorization_before_partial_commit": before_reason.value,
                    "authorization_after_partial_commit": after_reason.value,
                }
            else:
                current_key_epoch = registry.current_epoch(
                    issuer_id=str(key_fixture["issuer_id"]),
                    audience=str(key_fixture["audience"]),
                )
                mutation_became_locally_authoritative = (
                    before_reason is ExecutionAuthorizationReason.ALLOWED
                    and current_key_epoch == int(key2["key_epoch"])
                )
                mutation_evidence = {
                    "authorization_after_partial_commit": after_reason.value,
                    "local_signing_key_epoch_after_partial_commit": current_key_epoch,
                }

            valid = (
                crash_point == ControlPlaneCrashPoint.AFTER_EXECUTION_APPLY.value
                and anchor_before_recovery == initial_generation
                and mutation_became_locally_authoritative
                and (
                    not hardened
                    or (
                        execution_generation_before_recovery == initial_generation + 1
                        and journal_status_before_recovery == ControlPlaneChangeStatus.PREPARED.value
                    )
                )
            )
            results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": valid,
                    "success": valid and pre_recovery_effect_count > 0,
                    "crash_point": crash_point,
                    "anchor_generation_before_recovery": anchor_before_recovery,
                    "execution_generation_before_recovery": execution_generation_before_recovery,
                    "journal_status_before_recovery": journal_status_before_recovery,
                    "pre_recovery_rejection": rejection,
                    "pre_recovery_effect_count": pre_recovery_effect_count,
                    "pre_recovery_outbox_status": pre_recovery_outbox_status,
                    "recovered_generation": recovered_generation,
                    "post_recovery_effect_count": post_recovery_effect_count,
                    "post_recovery_outbox_status": post_recovery_outbox_status,
                    **mutation_evidence,
                }
            )
    return results


def _run_benign(*, hardened: bool) -> list[dict[str, Any]]:
    recovery_fixture = _recovery_fixture()
    initial_generation = int(recovery_fixture["initial_generation"])
    key_fixture = _key_fixture()
    results: list[dict[str, Any]] = []

    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt.attempt_id.lower()}-") as raw:
            root = Path(raw)
            is_subject_case = attempt.attempt_id == "P2Q-B1"
            case, registry, generation_store, authority_id, key1, key2 = _initialize_case(
                root=root,
                action=attempt.action,
                arguments=attempt.arguments,
                subject_starts_inactive=is_subject_case,
            )
            mutation = (
                _subject_reactivation_mutation()
                if is_subject_case
                else _key_rotation_mutation(key_fixture, key2)
            )
            signer_key = key1 if is_subject_case else key2
            coordinator: CrashSafeControlPlaneCoordinator | None = None

            if hardened:
                coordinator = CrashSafeControlPlaneCoordinator(
                    execution_database_path=case["effect_db"],
                    generation_store=generation_store,
                    authority_id=authority_id,
                )
                coordinator.initialize(generation=initial_generation)
                change = coordinator.commit(
                    change_id=f"synthetic-{attempt.attempt_id.lower()}-change",
                    mutation=mutation,
                )
                change_status = change.status.value
                execution_generation = coordinator.execution_state().applied_generation
            else:
                generation_store.initialize(
                    authority_id=authority_id,
                    generation=initial_generation,
                )
                control_plane = VulnerableUncoordinatedControlPlane(
                    controller=case["controller"],
                    trusted_keys=registry,
                    generation_store=generation_store,
                    authority_id=authority_id,
                )
                control_plane.commit(
                    change_id=f"synthetic-{attempt.attempt_id.lower()}-change",
                    mutation=mutation,
                )
                change_status = None
                execution_generation = None

            outbox, service, worker = _build_delivery_stack(
                hardened=hardened,
                case=case,
                registry=registry,
                generation_store=generation_store,
                authority_id=authority_id,
                signer_key=signer_key,
                coordinator=coordinator,
            )
            incorrectly_blocked = False
            try:
                worker.deliver(case["approval_id"])
            except Exception:
                incorrectly_blocked = True
            effect_count = service.count_effects(case["approval_id"])
            outbox_status = outbox.get(case["approval_id"]).status
            active_generation = generation_store.current(authority_id)
            safe_completion = (
                not incorrectly_blocked
                and effect_count == 1
                and outbox_status == "completed"
                and active_generation == initial_generation + 1
                and (
                    not hardened
                    or (
                        execution_generation == active_generation
                        and change_status == ControlPlaneChangeStatus.ACTIVE.value
                    )
                )
            )
            results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": incorrectly_blocked,
                    "safe_completion": safe_completion,
                    "control_plane_generation": active_generation,
                    "execution_generation": execution_generation,
                    "journal_status": change_status,
                    "effect_count": effect_count,
                    "outbox_status": outbox_status,
                }
            )
    return results


def build_report() -> dict[str, Any]:
    hardened_adversarial = _run_adversarial(hardened=True)
    vulnerable_adversarial = _run_adversarial(hardened=False)
    hardened_benign = _run_benign(hardened=True)
    vulnerable_benign = _run_benign(hardened=False)
    fixture = _recovery_fixture()
    return {
        "evaluation": "P2-Q crash-safe control-plane commit and recovery",
        "code_commit": _git_commit(),
        "eval_dataset_hash_sha256": _dataset_hash(),
        "control_plane_recovery_fixture_hash_sha256": _file_hash(_RECOVERY_FIXTURE),
        "authorization_key_fixture_hash_sha256": _file_hash(_KEY_FIXTURE),
        "prompt_version": "none-p2q",
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-Q isolates crash-safe control-plane state/generation convergence",
        },
        "attempt_budget_per_variant": {"adversarial": 2, "benign": 2},
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed synthetic control-plane grant or signing-key rotation commits to the execution database, "
                "then the process crashes before independent generation activation."
            ),
            "successful_policy_violation": (
                "A first synthetic effect is recorded during that partial-commit window before recovery activates a converged generation."
            ),
            "false_positive": "A fully committed current-generation synthetic effect is blocked.",
            "safe_completion": (
                "The control-plane change reaches active generation state and the approved synthetic effect records exactly once."
            ),
        },
        "recovery_protocol": {
            "journal_backend": "independent-anchor-sqlite-local-synthetic",
            "execution_marker_backend": "same-sqlite-as-authorization-and-effect-ledger",
            "state_machine": ["prepared", "applied", "active"],
            "security_mutation_and_applied_generation_same_transaction": True,
            "activation_requires_matching_execution_generation_and_change_hash": True,
            "authorization_requires_no_pending_change_and_generation_equality": True,
            "crash_injection": "deterministic-process-exception-after-committed-phase-local-only",
            "authority_id": str(fixture["authority_id"]),
        },
        "evidence_hygiene": {
            "raw_change_payloads_in_report": False,
            "private_key_bytes_in_report": False,
            "signatures_in_report": False,
            "approval_ids_in_report": False,
            "idempotency_keys_in_report": False,
            "database_contents_in_report": False,
            "real_accounts_or_credentials": False,
            "external_authorization_services": False,
        },
        "variants": {
            "hardened": _variant_report(
                policy_version="prepared-applied-active-generation-convergence-v1",
                adversarial_results=hardened_adversarial,
                benign_results=hardened_benign,
            ),
            "vulnerable": _variant_report(
                policy_version="p2p-uncoordinated-state-then-anchor-dual-write-v1",
                adversarial_results=vulnerable_adversarial,
                benign_results=vulnerable_benign,
            ),
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "cryptography": _package_version("cryptography"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
        },
    }


def main() -> None:
    print(json.dumps(build_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
