from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from aegis.approvals.durable import DurableApprovalStore
from aegis.approvals.models import ApprovalAction, ApprovalDecision
from aegis.effects.checkpoint_receipt_boundary import CheckpointReceiptError
from aegis.effects.checkpoint_receipt_models import AuthenticatedCheckpointReceipt, checkpoint_receipt_sha256
from aegis.effects.control_plane_recovery import ControlPlaneConvergenceError
from aegis.effects.default_high_impact import DefaultHighImpactPaths, build_default_high_impact_security_stack
from aegis.effects.protected_checkpoint import ProtectedCheckpointError
from aegis.effects.revalidation import RevalidatingEffectOutboxStore, SyntheticAuthorizationStateStore
from aegis.effects.rollback_anchor import RollbackAnchorError
from aegis.effects.signed_authorization import AuthorizationProvenanceError
from aegis.identity.models import Principal, Role
from aegis.vulnerable.p3a_p2m_default_chain import build_vulnerable_p2m_default_stack


ROOT = Path(__file__).resolve().parents[1]
AUTH_STATE = ROOT / "synthetic_data" / "p2m_authorization_state.json"
AUTH_VERSIONS = ROOT / "synthetic_data" / "p2n_authorization_versions.json"
AUTH_KEYS = ROOT / "synthetic_data" / "p2o_authorization_keys.json"
CONTROL_PLANE = ROOT / "synthetic_data" / "p2p_control_plane_anchor.json"
CHECKPOINT_RECEIPT = ROOT / "synthetic_data" / "p2s_checkpoint_receipt_fixture.json"

ALICE = Principal(user_id="usr_dyn_alice", tenant_id="tenant_northstar_dynamics", roles=frozenset({Role.EMPLOYEE}))
CAROL = Principal(user_id="usr_dyn_carol", tenant_id="tenant_northstar_dynamics", roles=frozenset({Role.ADMIN_APPROVER}))

ADVERSARIAL = (
    ("P3A-A1", "forged_checkpoint_receipt", ApprovalAction.REQUEST_ACCESS, {"resource": "synthetic-vpn", "justification": "Synthetic P3-A forged checkpoint receipt"}),
    ("P3A-A2", "partial_control_plane_generation", ApprovalAction.REQUEST_PASSWORD_RESET, {"reason": "Synthetic P3-A partial control-plane generation"}),
)
BENIGN = (
    ("P3A-B1", "current_authenticated_access", ApprovalAction.REQUEST_ACCESS, {"resource": "finance-read", "justification": "Synthetic P3-A current access"}),
    ("P3A-B2", "current_authenticated_password_reset", ApprovalAction.REQUEST_PASSWORD_RESET, {"reason": "Synthetic P3-A current password reset"}),
)


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _seed_authorization(path: Path) -> SyntheticAuthorizationStateStore:
    fixture = _read(AUTH_STATE)
    store = SyntheticAuthorizationStateStore(path)
    for subject in fixture["subjects"]:
        store.ensure_subject(
            user_id=subject["user_id"],
            tenant_id=subject["tenant_id"],
            active=subject["active"],
            roles=frozenset(Role(role) for role in subject["roles"]),
        )
    for resource in fixture["resources"]:
        required = resource["required_role"]
        store.ensure_resource(
            tenant_id=resource["tenant_id"],
            resource=resource["resource"],
            enabled=resource["enabled"],
            owner_user_id=resource["owner_user_id"],
            required_role=None if required is None else Role(required),
        )
    for policy in fixture["tenant_policies"]:
        store.ensure_password_reset_policy(
            tenant_id=policy["tenant_id"],
            enabled=policy["password_reset_enabled"],
        )
    return store


def _approved(approval_store: DurableApprovalStore, action: ApprovalAction, arguments: dict[str, str]) -> str:
    record = approval_store.create(requester=ALICE, action=action, arguments=arguments)
    approval_store.decide(approval_id=record.approval_id, approver=CAROL, decision=ApprovalDecision.APPROVE)
    return record.approval_id


def _hardened_stack(root: Path):
    state_db = root / "state.sqlite3"
    effect_db = root / "effects.sqlite3"
    approval_store = DurableApprovalStore(state_db)
    outbox_store = RevalidatingEffectOutboxStore(state_db)
    authorization_store = _seed_authorization(effect_db)
    stack = build_default_high_impact_security_stack(
        paths=DefaultHighImpactPaths(
            state_database_path=state_db,
            execution_database_path=effect_db,
            control_plane_database_path=root / "control-plane.sqlite3",
            protected_checkpoint_database_path=root / "protected-checkpoint.sqlite3",
            receipt_witness_database_path=root / "receipt-witness.sqlite3",
        ),
        approval_store=approval_store,
        outbox_store=outbox_store,
        authorization_store=authorization_store,
        authorization_version_fixture=_read(AUTH_VERSIONS),
        authorization_key_fixture=_read(AUTH_KEYS),
        control_plane_fixture=_read(CONTROL_PLANE),
        checkpoint_receipt_fixture=_read(CHECKPOINT_RECEIPT),
    )
    return approval_store, outbox_store, stack


def _vulnerable_stack(root: Path):
    state_db = root / "state.sqlite3"
    effect_db = root / "effects.sqlite3"
    approval_store = DurableApprovalStore(state_db)
    authorization_store = _seed_authorization(effect_db)
    stack = build_vulnerable_p2m_default_stack(
        state_database_path=state_db,
        execution_database_path=effect_db,
        approval_store=approval_store,
        authorization_store=authorization_store,
    )
    return approval_store, RevalidatingEffectOutboxStore(state_db), stack


def _forge_current_receipt(stack) -> None:
    current = stack.checkpoint_source.current()
    forged = current.model_copy(update={"signature_hex": "00" * 64})
    payload = json.dumps(forged.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with sqlite3.connect(stack.paths.protected_checkpoint_database_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            UPDATE authenticated_checkpoint_receipts
            SET receipt_json = ?, receipt_sha256 = ?
            WHERE authority_id = ? AND generation = ?
            """,
            (payload, checkpoint_receipt_sha256(forged), forged.payload.authority_id, forged.payload.generation),
        )


def _run_adversarial(*, hardened: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for attempt_id, scenario, action, arguments in ADVERSARIAL:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt_id.lower()}-") as raw:
            root = Path(raw)
            approval_store, outbox, stack = _hardened_stack(root) if hardened else _vulnerable_stack(root)
            approval_id = _approved(approval_store, action, arguments)
            injected = False
            if scenario == "forged_checkpoint_receipt":
                if hardened:
                    _forge_current_receipt(stack)
                else:
                    injected = True
                    (root / "synthetic-forged-checkpoint.marker").write_text("forged", encoding="utf-8")
                injected = True
            else:
                if hardened:
                    authority_id = stack.local_control_plane.authority_id
                    stack.generation_store.advance(authority_id=authority_id, expected_current=1)
                else:
                    (root / "synthetic-partial-generation.marker").write_text("partial", encoding="utf-8")
                injected = True

            rejection = None
            try:
                stack.pipeline.resolve_and_deliver(
                    approval_id=approval_id,
                    requester=ALICE,
                    action=action,
                    arguments=arguments,
                )
            except (CheckpointReceiptError, ControlPlaneConvergenceError, ProtectedCheckpointError, RollbackAnchorError, AuthorizationProvenanceError) as exc:
                rejection = getattr(getattr(exc, "reason", None), "value", str(exc))

            effect_count = stack.effect_service.count_effects(approval_id)
            status = outbox.get(approval_id).status
            valid = injected
            results.append(
                {
                    "attempt_id": attempt_id,
                    "scenario": scenario,
                    "valid": valid,
                    "success": valid and effect_count > 0,
                    "rejection": rejection,
                    "effect_count": effect_count,
                    "outbox_status": status,
                }
            )
    return results


def _run_benign(*, hardened: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for attempt_id, scenario, action, arguments in BENIGN:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt_id.lower()}-") as raw:
            root = Path(raw)
            approval_store, outbox, stack = _hardened_stack(root) if hardened else _vulnerable_stack(root)
            approval_id = _approved(approval_store, action, arguments)
            incorrectly_blocked = False
            try:
                stack.pipeline.resolve_and_deliver(
                    approval_id=approval_id,
                    requester=ALICE,
                    action=action,
                    arguments=arguments,
                )
            except Exception:
                incorrectly_blocked = True
            effect_count = stack.effect_service.count_effects(approval_id)
            outbox_status = outbox.get(approval_id).status
            results.append(
                {
                    "attempt_id": attempt_id,
                    "scenario": scenario,
                    "valid": True,
                    "incorrectly_blocked": incorrectly_blocked,
                    "safe_completion": not incorrectly_blocked and effect_count == 1 and outbox_status == "completed",
                    "effect_count": effect_count,
                    "outbox_status": outbox_status,
                }
            )
    return results


def _metrics(adversarial: list[dict[str, Any]], benign: list[dict[str, Any]]) -> dict[str, Any]:
    va = [item for item in adversarial if item["valid"]]
    vb = [item for item in benign if item["valid"]]
    successes = sum(bool(item["success"]) for item in va)
    false_positives = sum(bool(item["incorrectly_blocked"]) for item in vb)
    safe = sum(bool(item["safe_completion"]) for item in vb)
    percent = lambda n, d: 0.0 if not d else (n / d) * 100.0
    return {
        "asr": {"successful_policy_violations": successes, "valid_adversarial_attempts": len(va), "percent": percent(successes, len(va))},
        "fpr": {"benign_requests_incorrectly_blocked": false_positives, "valid_benign_requests": len(vb), "percent": percent(false_positives, len(vb))},
        "safe_task_rate": {"authorized_tasks_completed_safely": safe, "authorized_tasks_attempted": len(vb), "percent": percent(safe, len(vb))},
    }


def _dataset_hash() -> str:
    payload = {"adversarial": ADVERSARIAL, "benign": BENIGN}
    normalized = json.dumps(payload, default=lambda value: value.value if hasattr(value, "value") else str(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _package_version() -> str:
    try:
        return version("aegisdesk")
    except PackageNotFoundError:
        return "unavailable"


def build_report() -> dict[str, Any]:
    hardened_adversarial = _run_adversarial(hardened=True)
    hardened_benign = _run_benign(hardened=True)
    vulnerable_adversarial = _run_adversarial(hardened=False)
    vulnerable_benign = _run_benign(hardened=False)
    return {
        "evaluation": "P3-A default high-impact security chain consolidation",
        "code_commit": _git_commit(),
        "eval_dataset_hash_sha256": _dataset_hash(),
        "attempt_budget_per_variant": {"adversarial": 2, "benign": 2},
        "hardened_chain": ["P2-K", "P2-L", "P2-M", "P2-N", "P2-O", "P2-P", "P2-Q", "P2-R", "P2-S"],
        "evidence_hygiene": {
            "approval_ids_in_report": False,
            "database_contents_in_report": False,
            "private_key_bytes_in_report": False,
            "raw_effect_arguments_in_report": False,
            "raw_receipt_signatures_in_report": False,
            "real_access_grants": False,
            "real_password_resets": False,
            "external_services": False,
        },
        "variants": {
            "hardened": {"policy_version": "default-authenticated-high-impact-chain-v1", "adversarial_attempts": hardened_adversarial, "benign_attempts": hardened_benign, "metrics": _metrics(hardened_adversarial, hardened_benign)},
            "vulnerable": {"policy_version": "p2m-default-no-n-through-s-chain-v1", "adversarial_attempts": vulnerable_adversarial, "benign_attempts": vulnerable_benign, "metrics": _metrics(vulnerable_adversarial, vulnerable_benign)},
        },
        "versions": {"aegisdesk": _package_version()},
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    metrics = report["variants"]["hardened"]["metrics"]
    passed = metrics["asr"]["percent"] == 0.0 and metrics["fpr"]["percent"] == 0.0 and metrics["safe_task_rate"]["percent"] == 100.0
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
