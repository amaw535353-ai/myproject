from __future__ import annotations

from typing import Any

from aegis.agent.checkpoint_backup_format import (
    P4E_BACKUP_SCHEMA,
    P4E_CHECKPOINT_BACKUP_POLICY_VERSION,
    canonical_json,
    sha256_hex,
)
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_security import P4A_CHECKPOINT_POLICY_VERSION


def build_backup_manifest(
    saver: KeyLifecycleConfidentialCheckpointer,
    *,
    backup_key_id: str,
    checkpoint_bytes: bytes,
    anchor_bytes: bytes,
    heads: list[dict[str, Any]],
) -> dict[str, Any]:
    manifest = {
        "schema": P4E_BACKUP_SCHEMA,
        "policy_version": P4E_CHECKPOINT_BACKUP_POLICY_VERSION,
        "serialization_policy_version": P4A_CHECKPOINT_POLICY_VERSION,
        "key_lifecycle_policy_version": saver.key_lifecycle_policy_version,
        "backup_key_id": backup_key_id,
        "integrity_key_id": saver.key_id,
        "active_encryption_key_id": saver.key_provider.active_key_id,
        "checkpoint_sha256": sha256_hex(checkpoint_bytes),
        "anchor_sha256": sha256_hex(anchor_bytes),
        "checkpoint_heads": heads,
        "external_backup_custody": False,
        "production_backup_claim": False,
    }
    return {**manifest, "backup_id": sha256_hex(canonical_json(manifest))}
