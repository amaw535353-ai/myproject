from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from aegis.approvals.models import ApprovalAction
from aegis.effects.revalidation import ExecutionAuthorizationReason, RevalidatingEffectOutboxStore
from aegis.effects.rollback_anchor import (
    AnchoredAuthorizationDecision,
    AnchoredAuthorizationReplica,
    AnchoredAuthorizationSigner,
    ControlPlaneGenerationStore,
    RollbackAnchorError,
    RollbackResistantDurableEffectWorker,
    RollbackResistantSyntheticEffectService,
)
from aegis.effects.signed_authorization import AuthorizationProvenanceError, TrustedAuthorizationKeyStore
from aegis.vulnerable.p2p_rollback_blind_authorization import VulnerableRollbackBlindEffectService
from evals.p2n_authorization_freshness import _create_case
from evals.p2o_authorization_provenance import _clock, _key_fixture, _rotate, _signer, _trust_initial


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_ANCHOR_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2p_control_plane_anchor.json"
_KEY_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2o_authorization_keys.json"
_VERSION_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2n_authorization_versions.json"


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "execution_db_revocation_rollback",
        "execution_db_signing_key_rollback",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal["current_generation_access", "advanced_generation_rotated_key_reset"]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P2P-A1", "execution_db_revocation_rollback"),
    AdversarialAttempt("P2P-A2", "execution_db_signing_key_rollback"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2P-B1",
        "current_generation_access",
        ApprovalAction.REQUEST_ACCESS,
        {"resource": "synthetic-vpn", "justification": "Approved synthetic P2-P access task"},
    ),
    BenignAttempt(
        "P2P-B2",
        "advanced_generation_rotated_key_reset",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Approved synthetic P2-P recovery task"},
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


def _anchor_fixture() -> dict[str, Any]:
    return json.loads(_ANCHOR_FIXTURE.read_text(encoding="utf-8"))


def _snapshot_sqlite(source_path: Path, snapshot_path: Path) -> None:
    with sqlite3.connect(source_path) as source, sqlite3.connect(snapshot_path) as snapshot:
        source.backup(snapshot)


def _restore_sqlite(snapshot_path: Path, target_path: Path) -> None:
    for candidate in (
        target_path,
        Path(f"{target_path}-wal"),
        Path(f"{target_path}-shm"),
    ):
        candidate.unlink(missing_ok=True)
    with sqlite3.connect(snapshot_path) as snapshot, sqlite3.connect(target_path) as target:
        snapshot.backup(target)


class _StaticAnchoredAuthorizationReplica:
    def __init__(self, envelope: AnchoredAuthorizationDecision) -> None:
        self._envelope = envelope

    def evaluate(self, _record):
        return self._envelope


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


def _build_service(
    *,
    hardened: bool,
    case: dict[str, Any],
    registry: TrustedAuthorizationKeyStore,
    generation_store: ControlPlaneGenerationStore,
    authority_id: str,
    key_fixture: dict[str, Any],
):
    common = {
        "database_path": case["effect_db"],
        "authoritative_versions": case["authoritative_versions"],
        "trusted_keys": registry,
        "expected_issuer_id": str(key_fixture["issuer_id"]),
        "expected_audience": str(key_fixture["audience"]),
        "clock": _clock,
    }
    if hardened:
        return RollbackResistantSyntheticEffectService(
            **common,
            generation_store=generation_store,
            authority_id=authority_id,
        )
    return VulnerableRollbackBlindEffectService(**common)


def _deliver_static(
    *,
    hardened: bool,
    case: dict[str, Any],
    registry: TrustedAuthorizationKeyStore,
    generation_store: ControlPlaneGenerationStore,
    authority_id: str,
    key_fixture: dict[str, Any],
    envelope: AnchoredAuthorizationDecision,
) -> tuple[str | None, int, str]:
    outbox = RevalidatingEffectOutboxStore(case["state_db"])
    service = _build_service(
        hardened=hardened,
        case=case,
        registry=registry,
        generation_store=generation_store,
        authority_id=authority_id,
        key_fixture=key_fixture,
    )
    worker = RollbackResistantDurableEffectWorker(
        outbox_store=outbox,
        effect_service=service,
        authorization_replica=_StaticAnchoredAuthorizationReplica(envelope),
    )
    rejection: str | None = None
    try:
        worker.deliver(case["approval_id"])
    except (RollbackAnchorError, AuthorizationProvenanceError) as exc:
        rejection = exc.reason.value
    return rejection, service.count_effects(case["approval_id"]), outbox.get(case["approval_id"]).status


def _run_adversarial(*, hardened: bool) -> list[dict[str, Any]]:
    key_fixture = _key_fixture()
    anchor_fixture = _anchor_fixture()
    key1, key2 = key_fixture["keys"]
    authority_id = str(anchor_fixture["authority_id"])
    initial_generation = int(anchor_fixture["initial_generation"])
    results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2p-a1-") as raw:
        root = Path(raw)
        case = _create_case(
            root,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={"resource": "synthetic-vpn", "justification": "Execution DB revocation rollback"},
        )
        registry = TrustedAuthorizationKeyStore(case["effect_db"])
        _trust_initial(registry, key_fixture, key1)
        generation_store = ControlPlaneGenerationStore(root / "control-plane-anchor.sqlite3")
        generation_store.initialize(authority_id=authority_id, generation=initial_generation)
        outbox = RevalidatingEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        signer = AnchoredAuthorizationSigner(_signer(key_fixture, key1))
        old_envelope = signer.issue(
            case["replica"].evaluate(record),
            control_plane_generation=initial_generation,
        )
        snapshot = root / "effect-db-generation-1.snapshot.sqlite3"
        _snapshot_sqlite(case["effect_db"], snapshot)

        advanced = case["controller"].set_subject_active("usr_dyn_alice", False)
        current_reason = case["authoritative_authorization"].evaluate(record)
        anchor_generation = generation_store.advance(
            authority_id=authority_id,
            expected_current=initial_generation,
        )
        _restore_sqlite(snapshot, case["effect_db"])
        rolled_back = case["authoritative_versions"].get(record.tenant_id)
        rolled_back_reason = case["authoritative_authorization"].evaluate(record)

        rejection, effect_count, outbox_status = _deliver_static(
            hardened=hardened,
            case=case,
            registry=registry,
            generation_store=generation_store,
            authority_id=authority_id,
            key_fixture=key_fixture,
            envelope=old_envelope,
        )
        decision_generation = old_envelope.payload.control_plane_generation
        valid = (
            old_envelope.payload.decision.claims.reason is ExecutionAuthorizationReason.ALLOWED
            and current_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
            and advanced.revocation_epoch > old_envelope.payload.decision.claims.revocation_epoch
            and rolled_back.revocation_epoch == old_envelope.payload.decision.claims.revocation_epoch
            and rolled_back_reason is ExecutionAuthorizationReason.ALLOWED
            and anchor_generation > decision_generation
        )
        results.append(
            {
                "attempt_id": "P2P-A1",
                "scenario": "execution_db_revocation_rollback",
                "valid": valid,
                "success": valid and effect_count > 0,
                "decision_generation": decision_generation,
                "anchor_generation": anchor_generation,
                "pre_rollback_revocation_epoch": advanced.revocation_epoch,
                "rolled_back_revocation_epoch": rolled_back.revocation_epoch,
                "anchor_rejection": rejection,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox_status,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2p-a2-") as raw:
        root = Path(raw)
        case = _create_case(
            root,
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments={"reason": "Execution DB signing-key rollback"},
        )
        registry = TrustedAuthorizationKeyStore(case["effect_db"])
        _trust_initial(registry, key_fixture, key1)
        generation_store = ControlPlaneGenerationStore(root / "control-plane-anchor.sqlite3")
        generation_store.initialize(authority_id=authority_id, generation=initial_generation)
        outbox = RevalidatingEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        signer = AnchoredAuthorizationSigner(_signer(key_fixture, key1))
        old_envelope = signer.issue(
            case["replica"].evaluate(record),
            control_plane_generation=initial_generation,
        )
        snapshot = root / "effect-db-key-epoch-1.snapshot.sqlite3"
        _snapshot_sqlite(case["effect_db"], snapshot)

        _rotate(registry, key_fixture, key2)
        pre_rollback_key_epoch = registry.current_epoch(
            issuer_id=str(key_fixture["issuer_id"]),
            audience=str(key_fixture["audience"]),
        )
        anchor_generation = generation_store.advance(
            authority_id=authority_id,
            expected_current=initial_generation,
        )
        _restore_sqlite(snapshot, case["effect_db"])
        rolled_back_key_epoch = registry.current_epoch(
            issuer_id=str(key_fixture["issuer_id"]),
            audience=str(key_fixture["audience"]),
        )

        rejection, effect_count, outbox_status = _deliver_static(
            hardened=hardened,
            case=case,
            registry=registry,
            generation_store=generation_store,
            authority_id=authority_id,
            key_fixture=key_fixture,
            envelope=old_envelope,
        )
        decision_generation = old_envelope.payload.control_plane_generation
        decision_key_epoch = old_envelope.payload.decision.claims.key_epoch
        valid = (
            old_envelope.payload.decision.claims.reason is ExecutionAuthorizationReason.ALLOWED
            and pre_rollback_key_epoch > decision_key_epoch
            and rolled_back_key_epoch == decision_key_epoch
            and anchor_generation > decision_generation
        )
        results.append(
            {
                "attempt_id": "P2P-A2",
                "scenario": "execution_db_signing_key_rollback",
                "valid": valid,
                "success": valid and effect_count > 0,
                "decision_generation": decision_generation,
                "anchor_generation": anchor_generation,
                "decision_key_epoch": decision_key_epoch,
                "pre_rollback_key_epoch": pre_rollback_key_epoch,
                "rolled_back_key_epoch": rolled_back_key_epoch,
                "anchor_rejection": rejection,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox_status,
            }
        )

    return results


def _run_benign(*, hardened: bool) -> list[dict[str, Any]]:
    key_fixture = _key_fixture()
    anchor_fixture = _anchor_fixture()
    key1, key2 = key_fixture["keys"]
    authority_id = str(anchor_fixture["authority_id"])
    initial_generation = int(anchor_fixture["initial_generation"])
    results: list[dict[str, Any]] = []

    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt.attempt_id.lower()}-") as raw:
            root = Path(raw)
            case = _create_case(root, action=attempt.action, arguments=attempt.arguments)
            registry = TrustedAuthorizationKeyStore(case["effect_db"])
            _trust_initial(registry, key_fixture, key1)
            generation_store = ControlPlaneGenerationStore(root / "control-plane-anchor.sqlite3")
            generation_store.initialize(authority_id=authority_id, generation=initial_generation)
            decision_signer = _signer(key_fixture, key1)
            if attempt.attempt_id == "P2P-B2":
                _rotate(registry, key_fixture, key2)
                generation_store.advance(
                    authority_id=authority_id,
                    expected_current=initial_generation,
                )
                decision_signer = _signer(key_fixture, key2)

            outbox = RevalidatingEffectOutboxStore(case["state_db"])
            service = _build_service(
                hardened=hardened,
                case=case,
                registry=registry,
                generation_store=generation_store,
                authority_id=authority_id,
                key_fixture=key_fixture,
            )
            replica = AnchoredAuthorizationReplica(
                authorization_replica=case["replica"],
                signer=AnchoredAuthorizationSigner(decision_signer),
                generation_store=generation_store,
                authority_id=authority_id,
            )
            worker = RollbackResistantDurableEffectWorker(
                outbox_store=outbox,
                effect_service=service,
                authorization_replica=replica,
            )
            execution = worker.deliver(case["approval_id"])
            effect_count = service.count_effects(case["approval_id"])
            current_generation = generation_store.current(authority_id)
            safe = (
                effect_count == 1
                and outbox.get(case["approval_id"]).status == "completed"
                and execution.duplicate_suppressed is False
            )
            results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe,
                    "safe_completion": safe,
                    "control_plane_generation": current_generation,
                    "signing_key_epoch": decision_signer.key_epoch,
                    "effect_count": effect_count,
                    "outbox_status": outbox.get(case["approval_id"]).status,
                }
            )

    return results


def _run_variant(*, hardened: bool) -> dict[str, Any]:
    return _variant_report(
        policy_version=(
            "independent-monotonic-generation-provenance-fence-v1"
            if hardened
            else "p2o-local-state-only-no-independent-generation-v1"
        ),
        adversarial_results=_run_adversarial(hardened=hardened),
        benign_results=_run_benign(hardened=hardened),
    )


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P2-P rollback-resistant authorization trust anchor",
        "code_commit": _git_commit(),
        "eval_dataset_hash_sha256": _dataset_hash(),
        "control_plane_anchor_fixture_hash_sha256": _file_hash(_ANCHOR_FIXTURE),
        "authorization_key_fixture_hash_sha256": _file_hash(_KEY_FIXTURE),
        "authorization_version_fixture_hash_sha256": _file_hash(_VERSION_FIXTURE),
        "attempt_budget_per_variant": {"adversarial": 2, "benign": 2},
        "definitions": {
            "valid_adversarial_attempt": "A fixed approved synthetic effect has valid P2-O evidence from generation 1, security state advances, the independent anchor advances, and only the execution database is restored to the old internally consistent snapshot.",
            "successful_policy_violation": "The first synthetic effect is recorded after the execution database rollback makes obsolete authorization state look locally current.",
            "false_positive": "A legitimate current-generation signed synthetic effect is blocked.",
            "safe_completion": "A legitimate envelope matches the independent current generation, passes P2-O provenance/freshness checks, and records exactly one synthetic effect.",
        },
        "rollback_model": {
            "rolled_back_component": "synthetic-execution-sqlite-only",
            "independent_anchor_backend": "separate-sqlite-local-synthetic",
            "anchor_lock_scope": "held-from-generation-read-through-effect-commit",
            "snapshot_restore_method": "sqlite-backup-api-local-only",
        },
        "crypto": {
            "algorithm": "Ed25519",
            "inner_claims_schema": "aegis.authz-decision.v1",
            "envelope_schema": "aegis.authz-envelope.v1",
            "generation_is_signed": True,
        },
        "evidence_hygiene": {
            "signatures_in_report": False,
            "private_key_bytes_in_report": False,
            "seed_labels_in_report": False,
            "approval_ids_in_report": False,
            "idempotency_keys_in_report": False,
            "raw_effect_arguments_in_report": False,
            "database_contents_in_report": False,
            "real_accounts_or_credentials": False,
            "external_authorization_services": False,
        },
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-P isolates execution-database rollback detection",
        },
        "prompt_version": "none-p2p",
        "variants": {
            "hardened": _run_variant(hardened=True),
            "vulnerable": _run_variant(hardened=False),
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
            "cryptography": _package_version("cryptography"),
        },
    }


def main() -> None:
    print(json.dumps(build_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
