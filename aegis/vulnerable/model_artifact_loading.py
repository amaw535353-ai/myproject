from __future__ import annotations

import hashlib
from dataclasses import dataclass

from aegis.model_supply_chain.provenance import ModelArtifactManifest, ModelArtifactRequest


@dataclass(frozen=True)
class VulnerableLoadedModelArtifact:
    artifact_id: str
    model_id: str
    revision: str
    declared_publisher_id: str
    declared_source: str
    declared_format: str
    actual_sha256: str
    size_bytes: int
    provenance_verified: bool = False
    request_identity_bound: bool = False
    format_policy_enforced: bool = False
    code_executed: bool = False


class VulnerableModelArtifactLoader:
    """Intentionally trusts declaration metadata and never verifies provenance.

    The baseline remains inert: it never deserializes or executes supplied bytes. Its
    vulnerability is acceptance of artifacts before identity, origin, signature, digest,
    size, or serialization-format policy checks.
    """

    def load(
        self,
        *,
        request: ModelArtifactRequest,
        manifest: ModelArtifactManifest,
        signature: bytes,
        payload: bytes,
    ) -> VulnerableLoadedModelArtifact:
        del request, signature
        return VulnerableLoadedModelArtifact(
            artifact_id=manifest.artifact_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
            declared_publisher_id=manifest.publisher_id,
            declared_source=manifest.source,
            declared_format=manifest.artifact_format,
            actual_sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
