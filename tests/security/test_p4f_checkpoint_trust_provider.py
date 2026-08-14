from __future__ import annotations

import pytest

from aegis.agent.checkpoint_trust import (
    LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST,
    P4F_CHECKPOINT_TRUST_POLICY_VERSION,
    CheckpointTrustBoundaryError,
    CheckpointTrustReason,
    CheckpointTrustSurface,
    LocalSyntheticCheckpointTrustProviderFactory,
)
from aegis.effects.trust_providers import TrustDeploymentProfile, TrustProviderKind
from apps.api.dependencies import (
    get_agent_checkpointer,
    get_checkpoint_backup_manager,
    get_checkpoint_key_provider,
    get_checkpoint_trust_provider_factory,
)
from evals.p4f_checkpoint_trust_provider_posture import build_report


def _clear_checkpoint_dependencies() -> None:
    get_checkpoint_backup_manager.cache_clear()
    get_agent_checkpointer.cache_clear()
    get_checkpoint_key_provider.cache_clear()
    get_checkpoint_trust_provider_factory.cache_clear()


def test_default_api_checkpoint_dependencies_share_explicit_local_trust_bundle(client) -> None:
    factory = get_checkpoint_trust_provider_factory()
    key_provider = get_checkpoint_key_provider()
    saver = get_agent_checkpointer()
    backup_manager = get_checkpoint_backup_manager()

    assert isinstance(factory, LocalSyntheticCheckpointTrustProviderFactory)
    assert factory.manifest.policy_version == P4F_CHECKPOINT_TRUST_POLICY_VERSION
    assert len(factory.manifest.providers) == len(CheckpointTrustSurface) == 5
    assert saver.key_provider is key_provider
    assert saver.key_id == factory.integrity_key_material().key_id
    assert backup_manager.saver is saver
    assert backup_manager.backup_key_id == factory.backup_authentication_material().key_id


def test_local_checkpoint_manifest_cannot_make_production_trust_claim() -> None:
    assert LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST.production_trust_claim_allowed() is False
    assert all(
        provider.kind is TrustProviderKind.LOCAL_SYNTHETIC
        for provider in LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST.providers
    )


def test_production_profile_fails_closed_before_local_checkpoint_state_is_created(
    tmp_path, monkeypatch
) -> None:
    database_path = tmp_path / "agent-checkpoints.sqlite3"
    anchor_path = tmp_path / "agent-checkpoint-anchor.sqlite3"
    monkeypatch.setenv(
        "AEGISDESK_TRUST_PROFILE",
        TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED.value,
    )
    monkeypatch.setenv("AEGISDESK_AGENT_CHECKPOINT_DB", str(database_path))
    monkeypatch.setenv("AEGISDESK_AGENT_CHECKPOINT_ANCHOR_DB", str(anchor_path))
    _clear_checkpoint_dependencies()

    with pytest.raises(CheckpointTrustBoundaryError) as raised:
        get_agent_checkpointer()

    assert raised.value.reason is CheckpointTrustReason.LOCAL_PROVIDER_IN_PRODUCTION
    assert raised.value.surface is CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY
    assert database_path.exists() is False
    assert anchor_path.exists() is False

    with pytest.raises(CheckpointTrustBoundaryError):
        get_checkpoint_backup_manager()
    assert database_path.exists() is False
    assert anchor_path.exists() is False
    _clear_checkpoint_dependencies()


def test_explicit_local_profile_remains_available_for_synthetic_lab() -> None:
    LOCAL_SYNTHETIC_CHECKPOINT_TRUST_MANIFEST.assert_allowed(
        TrustDeploymentProfile.LOCAL_SYNTHETIC
    )


def test_p4f_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    assert report["passed"] is True
    baseline = report["variants"]["implicit_local_production_trust_baseline"]["metrics"]
    hardened = report["variants"]["explicit_checkpoint_trust_boundary"]["metrics"]
    assert baseline["asr"] == [5, 5]
    assert hardened["asr"] == [0, 5]
    assert hardened["fpr"] == [0, 2]
    assert hardened["safe_task_rate"] == [2, 2]
    assert report["production_checkpoint_trust_claim_allowed_by_default"] is False
    assert report["external_contract_implementation_included"] is False
    assert report["raw_key_bytes_in_report"] is False
    assert report["real_external_trust_operations"] is False
    assert report["production_checkpoint_runtime_included"] is False
