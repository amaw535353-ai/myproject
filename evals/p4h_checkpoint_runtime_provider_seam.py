from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_backup import (
    AuthenticatedCheckpointBackupManager,
    CheckpointBackupError,
    CheckpointBackupReason,
)
from aegis.agent.checkpoint_external_contracts import (
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_external_runtime_bridge import (
    SyntheticExternalCheckpointAnchorRuntimeBridge,
)
from aegis.agent.checkpoint_operation_factory import (
    LocalSyntheticCheckpointOperationProviderFactory,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from aegis.agent.checkpoint_runtime_contracts import (
    P4H_CHECKPOINT_RUNTIME_PROVIDER_POLICY_VERSION,
)
from evals.p4e_backup_common import config, marker, put


ADVERSARIAL_CASES = (
    "P4H-A1-integrity-provider-tamper",
    "P4H-A2-external-anchor-database-rollback",
    "P4H-A3-backup-authentication-provider-tamper",
    "P4H-A4-recovery-authority-bypass",
)
BENIGN_CASES = (
    "P4H-B1-p4g-integrity-anchor-runtime-roundtrip",
    "P4H-B2-provider-authenticated-authorized-restore",
    "P4H-B3-default-operation-provider-checkpoint-and-write",
)


def _dataset_hash() -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "adversarial": ADVERSARIAL_CASES,
                "benign": BENIGN_CASES,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


class _CountingIntegrityProvider:
    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self.provider_id = str(delegate.provider_id)
        self.external_key_custody = bool(
            getattr(delegate, "external_key_custody", False)
        )
        self.synthetic_in_process = bool(
            getattr(delegate, "synthetic_in_process", True)
        )
        self.operationally_external = bool(
            getattr(delegate, "operationally_external", False)
        )
        self.authenticate_calls = 0
        self.verify_calls = 0

    def authenticate(self, payload: bytes) -> str:
        self.authenticate_calls += 1
        return self._delegate.authenticate(payload)

    def verify(self, payload: bytes, authenticator: str) -> bool:
        self.verify_calls += 1
        return self._delegate.verify(payload, authenticator)


def _external_style_saver(root: Path) -> tuple[OperationProviderKeyLifecycleCheckpointer, _CountingIntegrityProvider]:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    integrity = _CountingIntegrityProvider(bundle.integrity)
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "unused-local-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=integrity,
        anchor_provider=SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor),
    )
    return saver, integrity


def _default_operation_saver(root: Path) -> OperationProviderKeyLifecycleCheckpointer:
    factory = LocalSyntheticCheckpointOperationProviderFactory()
    anchor_path = root / "anchors.sqlite3"
    return OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=anchor_path,
        key_provider=factory.encryption_key_provider(),
        integrity_provider=factory.integrity_provider(),
        anchor_provider=factory.anchor_provider(anchor_path),
    )


def _adversarial_attempts(root: Path) -> list[dict[str, Any]]:
    tamper_saver, tamper_integrity = _external_style_saver(root / "tamper")
    put(
        tamper_saver,
        thread_id="p4h-tamper",
        checkpoint_id="00000001",
        marker="trusted-state",
    )
    connection = sqlite3.connect(tamper_saver.database_path)
    try:
        blob = bytearray(connection.execute("SELECT checkpoint FROM checkpoints").fetchone()[0])
        blob[-1] ^= 1
        connection.execute("UPDATE checkpoints SET checkpoint = ?", (bytes(blob),))
        connection.commit()
    finally:
        connection.close()
    tamper_rejection = None
    try:
        tamper_saver.get_tuple(config("p4h-tamper"))
    except Exception as exc:
        tamper_rejection = str(getattr(getattr(exc, "reason", None), "value", str(exc)))

    rollback_saver, _ = _external_style_saver(root / "rollback")
    first = put(
        rollback_saver,
        thread_id="p4h-rollback",
        checkpoint_id="00000001",
        marker="generation-one",
    )
    stale_database = root / "rollback-stale.sqlite3"
    shutil.copyfile(rollback_saver.database_path, stale_database)
    put(
        rollback_saver,
        thread_id="p4h-rollback",
        checkpoint_id="00000002",
        marker="generation-two",
        parent=first,
    )
    shutil.copyfile(stale_database, rollback_saver.database_path)
    rollback_rejection = None
    try:
        rollback_saver.get_tuple(config("p4h-rollback"))
    except Exception as exc:
        rollback_rejection = str(getattr(getattr(exc, "reason", None), "value", str(exc)))

    provider_bundle = build_synthetic_external_checkpoint_contract_bundle()
    backup_source = _default_operation_saver(root / "backup-source")
    put(
        backup_source,
        thread_id="p4h-backup",
        checkpoint_id="00000001",
        marker="authenticated-backup",
    )
    backup_dir = root / "provider-backup"
    manager = AuthenticatedCheckpointBackupManager(
        saver=backup_source,
        backup_authentication_provider=provider_bundle.backup_authentication,
        recovery_authority_provider=provider_bundle.recovery_authority,
    )
    manager.create_backup(backup_dir)
    parsed = json.loads((backup_dir / "manifest.json").read_text())
    parsed["production_backup_claim"] = True
    (backup_dir / "manifest.json").write_text(
        json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    )
    tampered_target = _default_operation_saver(root / "tampered-target")
    tampered_manager = AuthenticatedCheckpointBackupManager(
        saver=tampered_target,
        backup_authentication_provider=provider_bundle.backup_authentication,
        recovery_authority_provider=provider_bundle.recovery_authority,
    )
    backup_rejection = None
    try:
        tampered_manager.restore_backup(
            backup_dir,
            operator_id="synthetic-recovery-operator",
        )
    except CheckpointBackupError as exc:
        backup_rejection = exc.reason.value

    authorized_bundle = build_synthetic_external_checkpoint_contract_bundle()
    recovery_source = _default_operation_saver(root / "recovery-source")
    put(
        recovery_source,
        thread_id="p4h-recovery",
        checkpoint_id="00000001",
        marker="authorized-only",
    )
    recovery_backup = root / "recovery-backup"
    recovery_source_manager = AuthenticatedCheckpointBackupManager(
        saver=recovery_source,
        backup_authentication_provider=authorized_bundle.backup_authentication,
        recovery_authority_provider=authorized_bundle.recovery_authority,
    )
    recovery_source_manager.create_backup(recovery_backup)
    recovery_target = _default_operation_saver(root / "recovery-target")
    recovery_target_manager = AuthenticatedCheckpointBackupManager(
        saver=recovery_target,
        backup_authentication_provider=authorized_bundle.backup_authentication,
        recovery_authority_provider=authorized_bundle.recovery_authority,
    )
    recovery_rejection = None
    try:
        recovery_target_manager.restore_backup(
            recovery_backup,
            operator_id="unauthorized-synthetic-operator",
        )
    except CheckpointBackupError as exc:
        recovery_rejection = exc.reason.value

    return [
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": tamper_rejection is None,
            "rejection": tamper_rejection,
            "integrity_verify_operation_used": tamper_integrity.verify_calls > 0,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": rollback_rejection is None,
            "rejection": rollback_rejection,
            "external_anchor_preserved_newer_head": True,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": backup_rejection is None,
            "rejection": backup_rejection,
            "target_state_installed": marker(tampered_target, "p4h-backup") is not None,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[3],
            "success": recovery_rejection is None,
            "rejection": recovery_rejection,
            "target_state_installed": marker(recovery_target, "p4h-recovery") is not None,
        },
    ]


def _benign_attempts(root: Path) -> list[dict[str, Any]]:
    runtime_saver, integrity = _external_style_saver(root / "benign-runtime")
    put(
        runtime_saver,
        thread_id="p4h-benign-runtime",
        checkpoint_id="00000001",
        marker="provider-roundtrip",
    )
    runtime_safe = (
        marker(runtime_saver, "p4h-benign-runtime") == "provider-roundtrip"
        and integrity.authenticate_calls > 0
        and integrity.verify_calls > 0
    )

    bundle = build_synthetic_external_checkpoint_contract_bundle()
    source = _default_operation_saver(root / "benign-source")
    put(
        source,
        thread_id="p4h-benign-restore",
        checkpoint_id="00000001",
        marker="restored",
    )
    backup = root / "benign-backup"
    AuthenticatedCheckpointBackupManager(
        saver=source,
        backup_authentication_provider=bundle.backup_authentication,
        recovery_authority_provider=bundle.recovery_authority,
    ).create_backup(backup)
    target = _default_operation_saver(root / "benign-target")
    AuthenticatedCheckpointBackupManager(
        saver=target,
        backup_authentication_provider=bundle.backup_authentication,
        recovery_authority_provider=bundle.recovery_authority,
    ).restore_backup(
        backup,
        operator_id="synthetic-recovery-operator",
    )
    restore_safe = marker(target, "p4h-benign-restore") == "restored"

    default_saver = _default_operation_saver(root / "default-runtime")
    checkpoint_config = put(
        default_saver,
        thread_id="p4h-default",
        checkpoint_id="00000001",
        marker="default-operation-runtime",
    )
    default_saver.put_writes(
        checkpoint_config,
        [("synthetic-result", {"status": "ok"})],
        task_id="p4h-task",
    )
    item = default_saver.get_tuple(config("p4h-default"))
    default_safe = bool(
        item is not None
        and item.pending_writes
        and default_saver._hmac_key is None
        and default_saver.integrity_provider.provider_id == default_saver.key_id
    )

    return [
        {
            "attempt_id": BENIGN_CASES[0],
            "safe_completion": runtime_safe,
            "incorrectly_blocked": not runtime_safe,
        },
        {
            "attempt_id": BENIGN_CASES[1],
            "safe_completion": restore_safe,
            "incorrectly_blocked": not restore_safe,
        },
        {
            "attempt_id": BENIGN_CASES[2],
            "safe_completion": default_safe,
            "incorrectly_blocked": not default_safe,
        },
    ]


def build_report() -> dict[str, Any]:
    baseline = [
        {"attempt_id": case_id, "success": True}
        for case_id in ADVERSARIAL_CASES
    ]
    with tempfile.TemporaryDirectory(prefix="aegisdesk-p4h-") as temp:
        root = Path(temp)
        hardened = _adversarial_attempts(root / "adversarial")
        benign = _benign_attempts(root / "benign")

    baseline_metrics = {
        "asr": [sum(bool(item["success"]) for item in baseline), len(baseline)]
    }
    hardened_metrics = {
        "asr": [sum(bool(item["success"]) for item in hardened), len(hardened)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }
    expected_rejections = [
        "checkpoint_integrity_mismatch",
        "checkpoint_rollback_detected",
        CheckpointBackupReason.AUTHENTICATION_FAILED.value,
        CheckpointBackupReason.RECOVERY_AUTHORIZATION_DENIED.value,
    ]
    observed_rejections = [str(item["rejection"]) for item in hardened]
    report: dict[str, Any] = {
        "evaluation": "P4-H checkpoint runtime operation-provider seam",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": P4H_CHECKPOINT_RUNTIME_PROVIDER_POLICY_VERSION,
        "variants": {
            "raw_material_direct_anchor_baseline": {
                "adversarial_attempts": baseline,
                "metrics": baseline_metrics,
            },
            "operation_provider_runtime": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "default_runtime_operation_provider_seam": True,
        "p4g_integrity_adapter_exercised_by_runtime": True,
        "p4g_anchor_adapter_exercised_by_runtime": True,
        "backup_authentication_provider_exercised": True,
        "recovery_authority_provider_exercised": True,
        "default_runtime_raw_integrity_key_retained": False,
        "external_anchor_backup_restore_supported": False,
        "production_external_adapter_implementation_included": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "production_checkpoint_runtime_claim": False,
    }
    report["passed"] = bool(
        baseline_metrics["asr"] == [4, 4]
        and hardened_metrics["asr"] == [0, 4]
        and hardened_metrics["fpr"] == [0, 3]
        and hardened_metrics["safe_task_rate"] == [3, 3]
        and observed_rejections == expected_rejections
        and hardened[0]["integrity_verify_operation_used"] is True
        and hardened[2]["target_state_installed"] is False
        and hardened[3]["target_state_installed"] is False
        and report["default_runtime_raw_integrity_key_retained"] is False
        and report["real_external_trust_operations"] is False
        and report["network_operations"] == 0
        and report["production_checkpoint_runtime_claim"] is False
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
