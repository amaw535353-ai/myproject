from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from aegis.model_supply_chain.key_lifecycle import (
    BoundProvenanceSignature,
    LifecycleSignedModelArtifact,
)
from aegis.model_supply_chain.package_provenance import (
    ModelPackageManifest,
    ModelPackageRequest,
)


@dataclass(frozen=True)
class VulnerableLifecyclePackage:
    package_id: str
    model_id: str
    revision: str
    package_key_id: str
    artifact_key_ids: tuple[tuple[str, str], ...]
    lifecycle_verified: bool = False
    revocation_checked: bool = False
    code_executed: bool = False


class VulnerableKeyLifecyclePackageLoader:
    """Intentionally trust declared signer metadata and ignore key lifecycle policy."""

    def load(
        self,
        *,
        request: ModelPackageRequest,
        manifest: ModelPackageManifest,
        package_signature: BoundProvenanceSignature,
        artifacts: Mapping[str, LifecycleSignedModelArtifact],
    ) -> VulnerableLifecyclePackage:
        return VulnerableLifecyclePackage(
            package_id=manifest.package_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
            package_key_id=package_signature.key_id,
            artifact_key_ids=tuple(
                sorted(
                    (artifact_id, bundle.signature.key_id)
                    for artifact_id, bundle in artifacts.items()
                )
            ),
        )
