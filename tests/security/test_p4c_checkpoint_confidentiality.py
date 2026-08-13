import pytest

from aegis.agent.checkpoint_confidentiality import (
    P4C_CHECKPOINT_CONFIDENTIALITY_POLICY_VERSION,
    P4C_CIPHERTEXT_MAGIC,
    CheckpointConfidentialityError,
    CheckpointConfidentialityReason,
    ConfidentialDurableIntegrityCheckpointer,
)
from apps.api.dependencies import get_agent_checkpointer, get_agent_runner
from evals.p4c_checkpoint_confidentiality import build_report


def test_default_api_runner_uses_confidential_durable_checkpointer(client) -> None:
    checkpointer = get_agent_checkpointer()
    runner = get_agent_runner()

    assert isinstance(checkpointer, ConfidentialDurableIntegrityCheckpointer)
    assert runner.checkpointer is checkpointer
    assert checkpointer.policy_version == P4C_CHECKPOINT_CONFIDENTIALITY_POLICY_VERSION
    assert checkpointer.database_path.exists()
    assert checkpointer.anchor_database_path.exists()


def test_default_api_agent_message_is_not_plaintext_in_checkpoint_database(client) -> None:
    marker = "P4C-DEFAULT-API-PLAINTEXT-MARKER-4815"
    response = client.post(
        "/v1/agent/run",
        json={"message": f"search: {marker}"},
        headers={"X-Aegis-User": "alice@northstar-dynamics.test"},
    )

    assert response.status_code == 200
    raw_database = get_agent_checkpointer().database_path.read_bytes()
    assert marker.encode() not in raw_database
    assert P4C_CIPHERTEXT_MAGIC in raw_database


def test_sensitive_checkpoint_metadata_is_rejected(tmp_path) -> None:
    saver = ConfidentialDurableIntegrityCheckpointer(
        database_path=tmp_path / "checkpoints.sqlite3",
        anchor_database_path=tmp_path / "anchors.sqlite3",
    )
    checkpoint = {
        "v": 4,
        "ts": "2026-08-13T00:00:00+00:00",
        "id": "00000001",
        "channel_values": {},
        "channel_versions": {},
        "versions_seen": {},
        "updated_channels": [],
    }

    with pytest.raises(CheckpointConfidentialityError) as raised:
        saver.put(
            {"configurable": {"thread_id": "p4c-metadata-test"}},
            checkpoint,
            {"message": "must stay in encrypted graph state"},
            {},
        )

    assert raised.value.reason is CheckpointConfidentialityReason.SENSITIVE_METADATA_REJECTED


def test_p4c_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()

    assert report["passed"] is True
    baseline = report["variants"]["integrity_only_plaintext_baseline"]["metrics"]
    hardened = report["variants"]["encrypted_minimized_boundary"]["metrics"]
    assert baseline["asr"] == [3, 3]
    assert hardened["asr"] == [0, 3]
    assert hardened["fpr"] == [0, 2]
    assert hardened["safe_task_rate"] == [2, 2]
    assert report["wrong_key_fail_closed"] is True
    assert report["legacy_plaintext_fail_closed"] is True
    assert report["external_key_custody"] is False
    assert report["raw_sensitive_values_in_report"] is False
    assert report["raw_encryption_key_bytes_in_report"] is False
    assert report["real_external_operations"] is False
    assert report["production_confidentiality_claim"] is False
