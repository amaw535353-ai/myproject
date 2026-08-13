from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from aegis.approvals.models import ApprovalAction
from aegis.effects.control_plane_recovery import (
    ControlPlaneMutation,
    ControlPlaneMutationKind,
    CrashSafeControlPlaneCoordinator,
)
from aegis.effects.protected_checkpoint import (
    PROTECTED_CHECKPOINT_POLICY_VERSION,
    CheckpointBoundAuthorizationReplica,
    CheckpointBoundSyntheticEffectService,
    ExternallyCheckpointedControlPlaneCoordinator,
    ProtectedCheckpointDurableEffectWorker,
    ProtectedCheckpointError,
    SyntheticProtectedCheckpointAuthority,
)
from aegis.effects.revalidation import ExecutionAuthorizationReason, RevalidatingEffectOutboxStore
from aegis.effects.rollback_anchor import AnchoredAuthorizationSigner, ControlPlaneGenerationStore
from aegis.effects.signed_authorization import TrustedAuthorizationKeyStore
from aegis.effects.versioned_revalidation import CachedAuthorizationReplica
from aegis.vulnerable.p2r_local_snapshot_checkpoint import LocalSnapshotGenerationFence
from evals.p2n_authorization_freshness import _create_case
from evals.p2o_authorization_provenance import _clock, _key_fixture, _signer, _trust_initial
from evals.p2p_rollback_resistant_anchor import _restore_sqlite, _snapshot_sqlite


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_CHECKPOINT_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2r_protected_checkpoint.json"
_KEY_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2o_authorization_keys.json"


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "dual_local_subject_revocation_rollback",
        "dual_local_signing_key_rollback",
    ]
    action: ApprovalAction
    arguments: dict[str, str]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal[
        "current_protected_checkpoint_access",
        "advanced_protected_checkpoint_rotated_key_reset",
    ]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt(
        "P2R-A1",
        "dual_local_subject_revocation_rollback",
        ApprovalAction.REQUEST_ACCESS,
        {
            "resource": "synthetic-vpn",
            "justification": "Synthetic P2-R dual-local rollback after subject revocation",
        },
    ),
    AdversarialAttempt(
        "P2R-A2",
        "dual_local_signing_key_rollback",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Synthetic P2-R dual-local rollback after signing-key rotation"},
    ),
)

BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2R-B1",
        "current_protected_checkpoint_access",
        ApprovalAction.REQUEST_ACCESS,
        {
            "resource": "synthetic-vpn",
            "justification": "Synthetic P2-R current protected checkpoint access",
        },
    ),
    BenignAttempt(
        "P2R-B2",
        "advanced_protected_checkpoint_rotated_key_reset",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Synthetic P2-R protected checkpoint after key rotation"},
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
    value = {
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
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _checkpoint_fixture() -> dict[str, Any]:
    return json.loads(_CHECKPOINT_FIXTURE.read_text(encoding="utf-8"))


def _live_replica(case: dict[str, Any]) -> CachedAuthorizationReplica:
    return CachedAuthorizationReplica(
        authorization_store=case["authoritative_authorization"],
        version_store=case["authoritative_versions"],
    )


def _subject_revocation_mutation() -> ControlPlaneMutation:
    return ControlPlaneMutation(
        kind=ControlPlaneMutationKind.SUBJECT_ACTIVE,
        tenant_id="tenant_northstar_dynamics",
        user_id="usr_dyn_alice",
        active=False,
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


def _initialize_stack(*, root: Path, action: ApprovalAction, arguments: dict[str, str]):
    case = _create_case(root, action=action, arguments=arguments)
    key_fixture = _key_fixture()
    key1, key2 = key_fixture["keys"]
    registry = TrustedAuthorizationKeyStore(case["effect_db"])
    _trust_initial(registry, key_fixture, key1)
    fixture = _checkpoint_fixture()
    generation_store = ControlPlaneGenerationStore(root / "control-plane-anchor.sqlite3")
    local = CrashSafeControlPlaneCoordinator(
        execution_database_path=case["effect_db"],
        generation_store=generation_store,
        authority_id=str(fixture["authority_id"]),
    )
    checkpoint_authority = SyntheticProtectedCheckpointAuthority(root / "protected-checkpoint.sqlite3")
    protected = ExternallyCheckpointedControlPlaneCoordinator(
        local_coordinator=local,
        checkpoint_authority=checkpoint_authority,
    )
    protected.initialize(generation=int(fixture["initial_generation"]))
    return case, registry, generation_store, local, checkpoint_authority, protected, key_fixture, key1, key2


def _build_delivery_stack(
    *,
    case: dict[str, Any],
    registry: TrustedAuthorizationKeyStore,
    generation_store: ControlPlaneGenerationStore,
    generation_fence,
    signer_key: dict[str, Any],
):
    key_fixture = _key_fixture()
    replica = CheckpointBoundAuthorizationReplica(
        authorization_replica=_live_replica(case),
        signer=AnchoredAuthorizationSigner(_signer(key_fixture, signer_key)),
        generation_fence=generation_fence,
    )
    service = CheckpointBoundSyntheticEffectService(
        case["effect_db"],
        authoritative_versions=case["authoritative_versions"],
        trusted_keys=registry,
        generation_store=generation_store,
        authority_id=str(_checkpoint_fixture()["authority_id"]),
        generation_fence=generation_fence,
        expected_issuer_id=str(key_fixture["issuer_id"]),
        expected_audience=str(key_fixture["audience"]),
        clock=_clock,
    )
    outbox = RevalidatingEffectOutboxStore(case["state_db"])
    worker = ProtectedCheckpointDurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
        authorization_replica=replica,
    )
    return outbox, service, worker


def _variant_report(*, policy_version: str, adversarial: list[dict[str, Any]], benign: list[dict[str, Any]]) -> dict[str, Any]:
    valid_adversarial = [item for item in adversarial if item["valid"]]
    successful = [item for item in valid_adversarial if item["success"]]
    valid_benign = [item for item in benign if item["valid"]]
    blocked = [item for item in valid_benign if item["incorrectly_blocked"]]
    safe = [item for item in valid_benign if item["safe_completion"]]
    return {
        "policy_version": policy_version,
        "adversarial_attempts": adversarial,
        "benign_attempts": benign,
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


def _run_adversarial(*, hardened: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for attempt in ADVERSARIAL_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt.attempt_id.lower()}-") as raw:
            root = Path(raw)
            case, registry, generation_store, local, checkpoint_authority, protected, key_fixture, key1, key2 = _initialize_stack(
                root=root,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            authority_id = local.authority_id
            execution_snapshot = root / "execution-generation-1.snapshot.sqlite3"
            anchor_snapshot = root / "anchor-generation-1.snapshot.sqlite3"
            _snapshot_sqlite(case["effect_db"], execution_snapshot)
            _snapshot_sqlite(generation_store.database_path, anchor_snapshot)

            record = RevalidatingEffectOutboxStore(case["state_db"]).get(case["approval_id"])
            before_reason = case["authoritative_authorization"].evaluate(record)
            mutation = (
                _subject_revocation_mutation()
                if attempt.attempt_id == "P2R-A1"
                else _key_rotation_mutation(key_fixture, key2)
            )
            protected.commit(
                change_id=f"synthetic-{attempt.attempt_id.lower()}-advance",
                mutation=mutation,
            )
            checkpoint_before_restore = checkpoint_authority.current(authority_id).generation
            local_before_restore = local.current_active_generation()

            if attempt.attempt_id == "P2R-A1":
                after_reason = case["authoritative_authorization"].evaluate(record)
                security_advanced = (
                    before_reason is ExecutionAuthorizationReason.ALLOWED
                    and after_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
                )
                advanced_evidence = {
                    "authorization_before_security_change": before_reason.value,
                    "authorization_after_security_change": after_reason.value,
                }
            else:
                after_reason = case["authoritative_authorization"].evaluate(record)
                epoch = registry.current_epoch(
                    issuer_id=str(key_fixture["issuer_id"]),
                    audience=str(key_fixture["audience"]),
                )
                security_advanced = after_reason is ExecutionAuthorizationReason.ALLOWED and epoch == int(key2["key_epoch"])
                advanced_evidence = {
                    "authorization_after_security_change": after_reason.value,
                    "signing_key_epoch_before_restore": epoch,
                }

            _restore_sqlite(execution_snapshot, case["effect_db"])
            _restore_sqlite(anchor_snapshot, generation_store.database_path)
            registry = TrustedAuthorizationKeyStore(case["effect_db"])
            generation_store = ControlPlaneGenerationStore(generation_store.database_path)
            local = CrashSafeControlPlaneCoordinator(
                execution_database_path=case["effect_db"],
                generation_store=generation_store,
                authority_id=authority_id,
            )
            local_after_restore = local.current_active_generation()
            checkpoint_after_restore = checkpoint_authority.current(authority_id)

            if attempt.attempt_id == "P2R-A1":
                restored_reason = case["authoritative_authorization"].evaluate(record)
                old_authority_restored = restored_reason is ExecutionAuthorizationReason.ALLOWED
                restored_evidence = {"authorization_after_dual_local_restore": restored_reason.value}
            else:
                restored_epoch = registry.current_epoch(
                    issuer_id=str(key_fixture["issuer_id"]),
                    audience=str(key_fixture["audience"]),
                )
                old_authority_restored = restored_epoch == int(key1["key_epoch"])
                restored_evidence = {"signing_key_epoch_after_dual_local_restore": restored_epoch}

            if hardened:
                fence = ExternallyCheckpointedControlPlaneCoordinator(
                    local_coordinator=local,
                    checkpoint_authority=checkpoint_authority,
                )
                policy_version = PROTECTED_CHECKPOINT_POLICY_VERSION
            else:
                fence = LocalSnapshotGenerationFence(local)
                policy_version = fence.policy_version

            outbox, service, worker = _build_delivery_stack(
                case=case,
                registry=registry,
                generation_store=generation_store,
                generation_fence=fence,
                signer_key=key1,
            )
            rejection: str | None = None
            try:
                worker.deliver(case["approval_id"])
            except ProtectedCheckpointError as exc:
                rejection = exc.reason.value

            effect_count = service.count_effects(case["approval_id"])
            outbox_status = outbox.get(case["approval_id"]).status
            valid = (
                checkpoint_before_restore == 2
                and local_before_restore == 2
                and local_after_restore == 1
                and checkpoint_after_restore.generation == 2
                and security_advanced
                and old_authority_restored
            )
            results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": valid,
                    "success": valid and effect_count > 0,
                    "policy_version": policy_version,
                    "checkpoint_generation_before_restore": checkpoint_before_restore,
                    "local_generation_before_restore": local_before_restore,
                    "local_generation_after_dual_restore": local_after_restore,
                    "protected_checkpoint_generation_after_dual_restore": checkpoint_after_restore.generation,
                    "protected_checkpoint_rejection": rejection,
                    "effect_count": effect_count,
                    "outbox_status": outbox_status,
                    **advanced_evidence,
                    **restored_evidence,
                }
            )
    return results


def _run_benign(*, hardened: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt.attempt_id.lower()}-") as raw:
            root = Path(raw)
            case, registry, generation_store, local, checkpoint_authority, protected, key_fixture, key1, key2 = _initialize_stack(
                root=root,
                action=attempt.action,
                arguments=attempt.arguments,
            )
            signer_key = key1
            if attempt.attempt_id == "P2R-B2":
                protected.commit(
                    change_id="synthetic-p2r-b2-key-rotation",
                    mutation=_key_rotation_mutation(key_fixture, key2),
                )
                signer_key = key2

            if hardened:
                fence = protected
                policy_version = PROTECTED_CHECKPOINT_POLICY_VERSION
            else:
                fence = LocalSnapshotGenerationFence(local)
                policy_version = fence.policy_version

            outbox, service, worker = _build_delivery_stack(
                case=case,
                registry=registry,
                generation_store=generation_store,
                generation_fence=fence,
                signer_key=signer_key,
            )
            rejection: str | None = None
            try:
                worker.deliver(case["approval_id"])
            except ProtectedCheckpointError as exc:
                rejection = exc.reason.value
            effect_count = service.count_effects(case["approval_id"])
            outbox_status = outbox.get(case["approval_id"]).status
            local_generation = local.current_active_generation()
            checkpoint_generation = checkpoint_authority.current(local.authority_id).generation
            safe = rejection is None and effect_count == 1 and outbox_status == "completed" and local_generation == checkpoint_generation
            results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe,
                    "safe_completion": safe,
                    "policy_version": policy_version,
                    "local_generation": local_generation,
                    "protected_checkpoint_generation": checkpoint_generation,
                    "effect_count": effect_count,
                    "outbox_status": outbox_status,
                    "rejection": rejection,
                }
            )
    return results


def build_report() -> dict[str, Any]:
    fixture = _checkpoint_fixture()
    vulnerable_adversarial = _run_adversarial(hardened=False)
    hardened_adversarial = _run_adversarial(hardened=True)
    vulnerable_benign = _run_benign(hardened=False)
    hardened_benign = _run_benign(hardened=True)
    return {
        "evaluation": "P2-R externally protected monotonic recovery checkpoint",
        "code_commit": _git_commit(),
        "prompt_version": "none-p2r",
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-R isolates dual-local rollback detection and protected checkpoint fencing",
        },
        "attempt_budget_per_variant": {"adversarial": 2, "benign": 2},
        "definitions": {
            "valid_adversarial_attempt": "A fixed synthetic security change advances both P2-Q local stores and the protected checkpoint to generation 2; only the execution and anchor/journal SQLite databases are then restored to their generation-1 snapshots.",
            "successful_policy_violation": "A first synthetic downstream effect is recorded after both rollback-restorable local control-plane databases were restored to obsolete but internally consistent authority.",
            "false_positive": "A legitimate current protected-checkpoint synthetic effect is blocked.",
            "safe_completion": "The protected checkpoint matches the local active generation and journal head and the approved synthetic effect records exactly once.",
        },
        "eval_dataset_hash_sha256": _dataset_hash(),
        "protected_checkpoint_fixture_hash_sha256": _file_hash(_CHECKPOINT_FIXTURE),
        "authorization_key_fixture_hash_sha256": _file_hash(_KEY_FIXTURE),
        "protected_checkpoint_protocol": {
            "authority_id": str(fixture["authority_id"]),
            "protected_domain_id": str(fixture["protected_domain_id"]),
            "rollback_set": list(fixture["rollback_set"]),
            "checkpoint_backend": "separate-sqlite-local-synthetic-protected-domain",
            "checkpoint_excluded_from_dual_local_snapshot_restore": True,
            "checkpoint_generation_is_monotonic": True,
            "checkpoint_binds_canonical_active_journal_hash_chain": True,
            "authorization_requires_exact_generation_and_journal_head": True,
            "local_activation_before_checkpoint_sync_fails_closed": True,
            "checkpoint_catchup_requires_matching_prior_journal_prefix": True,
        },
        "evidence_hygiene": {
            "approval_ids_in_report": False,
            "database_contents_in_report": False,
            "idempotency_keys_in_report": False,
            "private_key_bytes_in_report": False,
            "raw_change_payloads_in_report": False,
            "raw_effect_arguments_in_report": False,
            "real_accounts_or_credentials": False,
            "signatures_in_report": False,
        },
        "variants": {
            "vulnerable": _variant_report(
                policy_version=LocalSnapshotGenerationFence.policy_version,
                adversarial=vulnerable_adversarial,
                benign=vulnerable_benign,
            ),
            "hardened": _variant_report(
                policy_version=PROTECTED_CHECKPOINT_POLICY_VERSION,
                adversarial=hardened_adversarial,
                benign=hardened_benign,
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
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    hardened = report["variants"]["hardened"]["metrics"]
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    assert vulnerable["asr"]["percent"] == 100.0
    assert hardened["asr"]["percent"] == 0.0
    assert hardened["fpr"]["percent"] == 0.0
    assert hardened["safe_task_rate"]["percent"] == 100.0


if __name__ == "__main__":
    main()
