import pytest

from aegis.agent.checkpoint_confidentiality import ConfidentialDurableIntegrityCheckpointer
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_keys import (
    P4D_CHECKPOINT_KEY_LIFECYCLE_POLICY_VERSION,
    P4D_LOCAL_SYNTHETIC_ACTIVE_KEY,
    P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
    P4D_LOCAL_SYNTHETIC_LEGACY_KEY,
    P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID,
    CheckpointConfidentialityError,
    CheckpointConfidentialityReason,
    CheckpointKeyState,
    LocalSyntheticCheckpointKey,
    LocalSyntheticCheckpointKeyProvider,
    build_default_local_synthetic_checkpoint_key_provider,
)
from apps.api.dependencies import get_agent_checkpointer, get_agent_runner, get_checkpoint_key_provider
from evals.p4d_checkpoint_key_lifecycle import build_report


def _checkpoint(marker: str) -> dict:
    return {
        "v": 4,
        "ts": "2026-08-13T00:00:00+00:00",
        "id": "00000001",
        "channel_values": {"marker": marker},
        "channel_versions": {},
        "versions_seen": {},
        "updated_channels": ["marker"],
    }


def _config(thread_id: str, checkpoint_id: str | None = None) -> dict:
    configurable = {"thread_id": thread_id, "checkpoint_ns": ""}
    if checkpoint_id is not None:
        configurable["checkpoint_id"] = checkpoint_id
    return {"configurable": configurable}


def test_default_api_uses_versioned_checkpoint_key_provider(client) -> None:
    saver = get_agent_checkpointer()
    provider = get_checkpoint_key_provider()
    runner = get_agent_runner()

    assert isinstance(saver, KeyLifecycleConfidentialCheckpointer)
    assert runner.checkpointer is saver
    assert saver.key_provider is provider
    assert saver.key_lifecycle_policy_version == P4D_CHECKPOINT_KEY_LIFECYCLE_POLICY_VERSION
    assert provider.active_key_id == P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID
    assert provider.key_state(P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID) is CheckpointKeyState.ACTIVE
    assert provider.key_state(P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID) is CheckpointKeyState.DECRYPT_ONLY
    assert provider.external_key_custody is False


def test_default_api_persists_new_checkpoint_under_active_key(client) -> None:
    marker = "P4D-DEFAULT-ACTIVE-KEY-9182"
    response = client.post(
        "/v1/agent/run",
        json={"message": f"search: {marker}"},
        headers={"X-Aegis-User": "alice@northstar-dynamics.test"},
    )

    assert response.status_code == 200
    raw_database = get_agent_checkpointer().database_path.read_bytes()
    assert P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID.encode() in raw_database
    assert marker.encode() not in raw_database


def test_migration_reencrypts_legacy_checkpoint_and_pending_write(tmp_path) -> None:
    database_path = tmp_path / "checkpoints.sqlite3"
    anchor_path = tmp_path / "anchors.sqlite3"
    legacy = ConfidentialDurableIntegrityCheckpointer(
        database_path=database_path,
        anchor_database_path=anchor_path,
    )
    saved = legacy.put(
        _config("p4d-migrate"),
        _checkpoint("legacy-state"),
        {"source": "input"},
        {},
    )
    legacy.put_writes(
        saved,
        [("synthetic_pending", {"marker": "legacy-pending"})],
        task_id="p4d-task",
    )

    saver = KeyLifecycleConfidentialCheckpointer(
        database_path=database_path,
        anchor_database_path=anchor_path,
        key_provider=build_default_local_synthetic_checkpoint_key_provider(),
    )
    assert saver.get_tuple(_config("p4d-migrate")) is not None
    migration = saver.migrate_to_active_encryption_key()
    reopened = saver.get_tuple(_config("p4d-migrate"))

    assert migration.checkpoints_reencrypted == 1
    assert migration.writes_reencrypted == 1
    assert reopened is not None
    assert reopened.checkpoint["channel_values"]["marker"] == "legacy-state"
    assert list(reopened.pending_writes)[0][2]["marker"] == "legacy-pending"
    raw_database = database_path.read_bytes()
    assert P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID.encode() not in raw_database
    assert P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID.encode() in raw_database


def test_revoked_legacy_key_fails_closed(tmp_path) -> None:
    database_path = tmp_path / "checkpoints.sqlite3"
    anchor_path = tmp_path / "anchors.sqlite3"
    ConfidentialDurableIntegrityCheckpointer(
        database_path=database_path,
        anchor_database_path=anchor_path,
    ).put(
        _config("p4d-revoked"),
        _checkpoint("revoked-state"),
        {"source": "input"},
        {},
    )
    provider = LocalSyntheticCheckpointKeyProvider(
        active_key_id=P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
        keys={
            P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID: LocalSyntheticCheckpointKey(
                key_id=P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
                key=P4D_LOCAL_SYNTHETIC_ACTIVE_KEY,
                state=CheckpointKeyState.ACTIVE,
            ),
            P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID: LocalSyntheticCheckpointKey(
                key_id=P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID,
                key=P4D_LOCAL_SYNTHETIC_LEGACY_KEY,
                state=CheckpointKeyState.REVOKED,
            ),
        },
    )
    saver = KeyLifecycleConfidentialCheckpointer(
        database_path=database_path,
        anchor_database_path=anchor_path,
        key_provider=provider,
    )

    with pytest.raises(CheckpointConfidentialityError) as raised:
        saver.get_tuple(_config("p4d-revoked"))

    assert raised.value.reason is CheckpointConfidentialityReason.REVOKED_ENCRYPTION_KEY


def test_p4d_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()

    assert report["passed"] is True
    baseline = report["variants"]["single_key_no_lifecycle_baseline"]["metrics"]
    hardened = report["variants"]["versioned_key_lifecycle_boundary"]["metrics"]
    assert baseline["asr"] == [2, 2]
    assert hardened["asr"] == [0, 2]
    assert hardened["fpr"] == [0, 2]
    assert hardened["safe_task_rate"] == [2, 2]
    assert report["external_key_custody"] is False
    assert report["raw_key_bytes_in_report"] is False
    assert report["real_external_operations"] is False
    assert report["production_key_management_claim"] is False
