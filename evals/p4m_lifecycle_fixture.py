from __future__ import annotations

import hashlib

from aegis.agent.checkpoint_keys import (
    CheckpointKeyState,
    LocalSyntheticCheckpointKey,
    LocalSyntheticCheckpointKeyProvider,
)


P4M_FIXTURE_LEGACY_KEY_ID = "p4m-local-synthetic-lifecycle-aesgcm-v1"
P4M_FIXTURE_ACTIVE_KEY_ID = "p4m-local-synthetic-lifecycle-aesgcm-v2"
_P4M_FIXTURE_LEGACY_KEY = hashlib.sha256(
    b"aegisdesk-p4m-local-synthetic-lifecycle-aead-key-v1"
).digest()
_P4M_FIXTURE_ACTIVE_KEY = hashlib.sha256(
    b"aegisdesk-p4m-local-synthetic-lifecycle-aead-key-v2"
).digest()


def build_p4m_legacy_fixture_key_provider() -> LocalSyntheticCheckpointKeyProvider:
    """Build the deterministic v1-only seed keyring for the P4-M migration fixture."""

    return LocalSyntheticCheckpointKeyProvider(
        active_key_id=P4M_FIXTURE_LEGACY_KEY_ID,
        keys={
            P4M_FIXTURE_LEGACY_KEY_ID: LocalSyntheticCheckpointKey(
                key_id=P4M_FIXTURE_LEGACY_KEY_ID,
                key=_P4M_FIXTURE_LEGACY_KEY,
                state=CheckpointKeyState.ACTIVE,
            )
        },
    )


def build_p4m_migration_fixture_key_provider() -> LocalSyntheticCheckpointKeyProvider:
    """Build the v2-active/v1-decrypt-only keyring used after the synthetic restart."""

    return LocalSyntheticCheckpointKeyProvider(
        active_key_id=P4M_FIXTURE_ACTIVE_KEY_ID,
        keys={
            P4M_FIXTURE_ACTIVE_KEY_ID: LocalSyntheticCheckpointKey(
                key_id=P4M_FIXTURE_ACTIVE_KEY_ID,
                key=_P4M_FIXTURE_ACTIVE_KEY,
                state=CheckpointKeyState.ACTIVE,
            ),
            P4M_FIXTURE_LEGACY_KEY_ID: LocalSyntheticCheckpointKey(
                key_id=P4M_FIXTURE_LEGACY_KEY_ID,
                key=_P4M_FIXTURE_LEGACY_KEY,
                state=CheckpointKeyState.DECRYPT_ONLY,
            ),
        },
    )
