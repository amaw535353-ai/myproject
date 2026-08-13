"""P2-S LOCAL SYNTHETIC LAB BASELINE ONLY.

This module is never imported by the hardened application. It models one narrow
trust defect for deterministic unit/evaluation coverage: treating checkpoint
metadata as trusted without authenticating or pinning its history. It performs
no network access, credential access, exploitation, or external side effect.
"""

from __future__ import annotations

VULNERABLE_P2S_POLICY_VERSION = "unsigned-unpinned-checkpoint-metadata-v1"


class MetadataOnlyCheckpointObserver:
    policy_version = VULNERABLE_P2S_POLICY_VERSION

    def __init__(self, *, expected_authority_id: str, expected_audience: str) -> None:
        self.expected_authority_id = expected_authority_id
        self.expected_audience = expected_audience

    def observe(self, receipt):
        payload = receipt.payload
        if payload.authority_id != self.expected_authority_id:
            raise ValueError("synthetic checkpoint authority mismatch")
        if payload.audience != self.expected_audience:
            raise ValueError("synthetic checkpoint audience mismatch")
        return payload
