from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from aegis.model_supply_chain.package_provenance import (
    ModelPackageComponentRole,
    ModelPackageManifest,
    ModelPackageRequest,
    SignedModelArtifact,
)


@dataclass(frozen=True)
class VulnerableLoadedModelPackage:
    package_id: str
    model_id: str
    revision: str
    supplied_component_ids: tuple[str, ...]
    primary_present: bool
    package_signature_verified: bool = False
    transitive_components_verified: bool = False
    dependency_graph_verified: bool = False
    remote_code_policy_enforced: bool = False
    code_executed: bool = False


class VulnerableModelPackageLoader:
    """Intentionally trusts package declarations and validates only primary presence.

    The baseline remains inert. It does not deserialize artifacts or execute remote code,
    but it ignores package signatures, dependency closure, role-specific publisher policy,
    remote-code declarations, and provenance of non-primary artifacts.
    """

    def load(
        self,
        *,
        request: ModelPackageRequest,
        manifest: ModelPackageManifest,
        package_signature: bytes,
        artifacts: Mapping[str, SignedModelArtifact],
    ) -> VulnerableLoadedModelPackage:
        del request, package_signature
        primary_ids = {
            item.artifact_id
            for item in manifest.components
            if item.role is ModelPackageComponentRole.PRIMARY_MODEL
        }
        primary_present = bool(primary_ids & set(artifacts))
        if not primary_present:
            raise ValueError("primary model missing")
        return VulnerableLoadedModelPackage(
            package_id=manifest.package_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
            supplied_component_ids=tuple(sorted(artifacts)),
            primary_present=True,
        )
