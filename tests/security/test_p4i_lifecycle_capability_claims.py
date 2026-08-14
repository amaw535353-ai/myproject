from __future__ import annotations

import pytest

from aegis.agent.checkpoint_lifecycle_capabilities import (
    CheckpointLifecycleCapability,
    CheckpointLifecycleCapabilityError,
    CheckpointLifecycleReason,
)
from aegis.agent.checkpoint_operation_factory import (
    LocalSyntheticCheckpointOperationProviderFactory,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)


class _ClaimOnlyLifecycleProvider:
    provider_id = "synthetic-claim-only-lifecycle"
    capabilities = frozenset({CheckpointLifecycleCapability.MIGRATION})
    synthetic_in_process = True
    operationally_external = False

    def __init__(self, anchor_provider_id: str) -> None:
        self.anchor_provider_id = anchor_provider_id


def test_advertised_capability_without_operation_method_is_rejected(tmp_path) -> None:
    factory = LocalSyntheticCheckpointOperationProviderFactory()
    anchor_path = tmp_path / "anchors.sqlite3"
    anchor = factory.anchor_provider(anchor_path)
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=tmp_path / "checkpoints.sqlite3",
        anchor_database_path=anchor_path,
        key_provider=factory.encryption_key_provider(),
        integrity_provider=factory.integrity_provider(),
        anchor_provider=anchor,
        lifecycle_provider=_ClaimOnlyLifecycleProvider(anchor.provider_id),
    )

    with pytest.raises(CheckpointLifecycleCapabilityError) as raised:
        saver.migrate_to_active_encryption_key()

    assert raised.value.reason is CheckpointLifecycleReason.CAPABILITY_UNSUPPORTED
    assert raised.value.capability is CheckpointLifecycleCapability.MIGRATION
