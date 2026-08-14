from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .provenance import (
    ModelArtifactManifest,
    ModelArtifactRejected,
    ModelArtifactRequest,
    ModelArtifactTrustPolicy,
    RestrictedModelArtifactLoader,
    VerifiedModelArtifact,
)


P5B_PACKAGE_POLICY_VERSION = "transitive-model-package-provenance-v1"
P5B_PACKAGE_MANIFEST_SCHEMA_VERSION = "aegis-model-package-manifest-v1"
P5B_PACKAGE_LOADER_MODE = "verified-transitive-opaque-handoff-v1"


class ModelPackageComponentRole(StrEnum):
    PRIMARY_MODEL = "primary_model"
    CONFIG = "config"
    TOKENIZER = "tokenizer"
    ADAPTER = "adapter"
    QUANTIZATION_METADATA = "quantization_metadata"
    EXTERNAL_DATA = "external_data"


class ModelPackageRejectReason(StrEnum):
    MANIFEST_INVALID = "manifest_invalid"
    IDENTITY_MISMATCH = "identity_mismatch"
    PACKAGE_PUBLISHER_UNTRUSTED = "package_publisher_untrusted"
    PACKAGE_SIGNATURE_INVALID = "package_signature_invalid"
    COMPONENT_SET_MISMATCH = "component_set_mismatch"
    COMPONENT_ROLE_MISMATCH = "component_role_mismatch"
    COMPONENT_PUBLISHER_DISALLOWED = "component_publisher_disallowed"
    REMOTE_CODE_REQUIRED = "remote_code_required"
    DEPENDENCY_INVALID = "dependency_invalid"
    COMPONENT_INVALID = "component_invalid"


class ModelPackageRejected(ValueError):
    def __init__(
        self,
        reason: ModelPackageRejectReason,
        message: str,
        *,
        component_id: str | None = None,
        nested_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.component_id = component_id
        self.nested_reason = nested_reason


@dataclass(frozen=True)
class ModelPackageRequest:
    package_id: str
    model_id: str
    revision: str


@dataclass(frozen=True)
class ModelPackageComponent:
    artifact_id: str
    role: ModelPackageComponentRole
    artifact_format: str
    publisher_id: str
    sha256: str
    size_bytes: int
    depends_on: tuple[str, ...] = ()
    requires_remote_code: bool = False


@dataclass(frozen=True)
class ModelPackageManifest:
    package_id: str
    model_id: str
    revision: str
    publisher_id: str
    components: tuple[ModelPackageComponent, ...]
    requires_remote_code: bool = False
    schema_version: str = P5B_PACKAGE_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class SignedModelArtifact:
    manifest: ModelArtifactManifest
    signature: bytes
    payload: bytes


@dataclass(frozen=True)
class ModelPackageTrustPolicy:
    package_publishers: Mapping[str, bytes]
    artifact_policy: ModelArtifactTrustPolicy
    role_publishers: Mapping[ModelPackageComponentRole, frozenset[str]]
    allowed_roles: frozenset[ModelPackageComponentRole] = frozenset(ModelPackageComponentRole)
    allow_remote_code: bool = False


@dataclass(frozen=True)
class VerifiedModelPackage:
    package_id: str
    model_id: str
    revision: str
    package_publisher_id: str
    component_artifact_ids: tuple[str, ...]
    component_roles: tuple[str, ...]
    component_publishers: tuple[str, ...]
    package_signature_verified: bool = True
    transitive_components_verified: bool = True
    dependency_graph_verified: bool = True
    remote_code_required: bool = False
    policy_version: str = P5B_PACKAGE_POLICY_VERSION
    loader_mode: str = P5B_PACKAGE_LOADER_MODE
    deserialized: bool = False
    code_execution_capable: bool = False
    network_operations: int = 0


def canonical_package_manifest_bytes(manifest: ModelPackageManifest) -> bytes:
    components = [
        {
            "artifact_format": item.artifact_format,
            "artifact_id": item.artifact_id,
            "depends_on": sorted(item.depends_on),
            "publisher_id": item.publisher_id,
            "requires_remote_code": item.requires_remote_code,
            "role": item.role.value,
            "sha256": item.sha256,
            "size_bytes": item.size_bytes,
        }
        for item in sorted(manifest.components, key=lambda item: item.artifact_id)
    ]
    return json.dumps(
        {
            "components": components,
            "model_id": manifest.model_id,
            "package_id": manifest.package_id,
            "publisher_id": manifest.publisher_id,
            "requires_remote_code": manifest.requires_remote_code,
            "revision": manifest.revision,
            "schema_version": manifest.schema_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject(
    reason: ModelPackageRejectReason,
    message: str,
    *,
    component_id: str | None = None,
    nested_reason: str | None = None,
) -> None:
    raise ModelPackageRejected(
        reason,
        message,
        component_id=component_id,
        nested_reason=nested_reason,
    )


def _validate_manifest(manifest: ModelPackageManifest, policy: ModelPackageTrustPolicy) -> None:
    if manifest.schema_version != P5B_PACKAGE_MANIFEST_SCHEMA_VERSION:
        _reject(ModelPackageRejectReason.MANIFEST_INVALID, "unsupported model package manifest schema")
    if not manifest.package_id or not manifest.model_id or not manifest.revision or not manifest.publisher_id:
        _reject(ModelPackageRejectReason.MANIFEST_INVALID, "package identity fields must be non-empty")
    if not manifest.components:
        _reject(ModelPackageRejectReason.MANIFEST_INVALID, "model package must declare at least one component")

    ids = [item.artifact_id for item in manifest.components]
    if any(not item for item in ids) or len(ids) != len(set(ids)):
        _reject(ModelPackageRejectReason.MANIFEST_INVALID, "component artifact IDs must be unique and non-empty")

    primary_count = 0
    known_ids = set(ids)
    dependency_graph: dict[str, tuple[str, ...]] = {}
    for item in manifest.components:
        if item.role not in policy.allowed_roles:
            _reject(
                ModelPackageRejectReason.COMPONENT_ROLE_MISMATCH,
                "component role is not allowed by package policy",
                component_id=item.artifact_id,
            )
        if item.role is ModelPackageComponentRole.PRIMARY_MODEL:
            primary_count += 1
        if not item.artifact_format or not item.publisher_id:
            _reject(
                ModelPackageRejectReason.MANIFEST_INVALID,
                "component format and publisher must be non-empty",
                component_id=item.artifact_id,
            )
        digest = item.sha256.casefold()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            _reject(
                ModelPackageRejectReason.MANIFEST_INVALID,
                "component digest must be SHA-256 hex",
                component_id=item.artifact_id,
            )
        if item.size_bytes < 0:
            _reject(
                ModelPackageRejectReason.MANIFEST_INVALID,
                "component size must be non-negative",
                component_id=item.artifact_id,
            )
        if item.artifact_id in item.depends_on:
            _reject(
                ModelPackageRejectReason.DEPENDENCY_INVALID,
                "component may not depend on itself",
                component_id=item.artifact_id,
            )
        if len(item.depends_on) != len(set(item.depends_on)):
            _reject(
                ModelPackageRejectReason.DEPENDENCY_INVALID,
                "component dependency list contains duplicates",
                component_id=item.artifact_id,
            )
        missing = sorted(set(item.depends_on) - known_ids)
        if missing:
            _reject(
                ModelPackageRejectReason.DEPENDENCY_INVALID,
                "component dependency references an undeclared artifact",
                component_id=item.artifact_id,
            )
        dependency_graph[item.artifact_id] = item.depends_on

    if primary_count != 1:
        _reject(ModelPackageRejectReason.MANIFEST_INVALID, "model package must declare exactly one primary model")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(artifact_id: str) -> None:
        if artifact_id in visiting:
            _reject(
                ModelPackageRejectReason.DEPENDENCY_INVALID,
                "component dependency graph contains a cycle",
                component_id=artifact_id,
            )
        if artifact_id in visited:
            return
        visiting.add(artifact_id)
        for dependency in dependency_graph[artifact_id]:
            visit(dependency)
        visiting.remove(artifact_id)
        visited.add(artifact_id)

    for artifact_id in sorted(dependency_graph):
        visit(artifact_id)


class RestrictedModelPackageLoader:
    """Verify a signed package closure and every declared artifact before handoff."""

    def __init__(self, policy: ModelPackageTrustPolicy) -> None:
        self._policy = policy
        self._artifact_loader = RestrictedModelArtifactLoader(policy.artifact_policy)

    def load(
        self,
        *,
        request: ModelPackageRequest,
        manifest: ModelPackageManifest,
        package_signature: bytes,
        artifacts: Mapping[str, SignedModelArtifact],
    ) -> VerifiedModelPackage:
        _validate_manifest(manifest, self._policy)

        if (
            request.package_id != manifest.package_id
            or request.model_id != manifest.model_id
            or request.revision != manifest.revision
        ):
            _reject(
                ModelPackageRejectReason.IDENTITY_MISMATCH,
                "signed package identity does not match caller request",
            )

        package_key = self._policy.package_publishers.get(manifest.publisher_id)
        if package_key is None:
            _reject(
                ModelPackageRejectReason.PACKAGE_PUBLISHER_UNTRUSTED,
                "package publisher is not trusted by policy",
            )
        try:
            Ed25519PublicKey.from_public_bytes(package_key).verify(
                package_signature,
                canonical_package_manifest_bytes(manifest),
            )
        except (ValueError, InvalidSignature):
            _reject(
                ModelPackageRejectReason.PACKAGE_SIGNATURE_INVALID,
                "model package manifest signature verification failed",
            )

        if manifest.requires_remote_code and not self._policy.allow_remote_code:
            _reject(
                ModelPackageRejectReason.REMOTE_CODE_REQUIRED,
                "package requires remote code but policy forbids it",
            )
        for component in manifest.components:
            if component.requires_remote_code and not self._policy.allow_remote_code:
                _reject(
                    ModelPackageRejectReason.REMOTE_CODE_REQUIRED,
                    "package component requires remote code but policy forbids it",
                    component_id=component.artifact_id,
                )

        expected_ids = {item.artifact_id for item in manifest.components}
        supplied_ids = set(artifacts)
        if supplied_ids != expected_ids:
            _reject(
                ModelPackageRejectReason.COMPONENT_SET_MISMATCH,
                "supplied artifact set does not exactly match signed package closure",
            )

        verified: list[tuple[ModelPackageComponent, VerifiedModelArtifact]] = []
        for component in sorted(manifest.components, key=lambda item: item.artifact_id):
            bundle = artifacts[component.artifact_id]
            if (
                bundle.manifest.publisher_id != component.publisher_id
                or bundle.manifest.sha256.casefold() != component.sha256.casefold()
                or bundle.manifest.size_bytes != component.size_bytes
            ):
                _reject(
                    ModelPackageRejectReason.COMPONENT_ROLE_MISMATCH,
                    "artifact provenance metadata does not match the exact signed package pin",
                    component_id=component.artifact_id,
                )
            allowed_publishers = self._policy.role_publishers.get(component.role, frozenset())
            if bundle.manifest.publisher_id not in allowed_publishers:
                _reject(
                    ModelPackageRejectReason.COMPONENT_PUBLISHER_DISALLOWED,
                    "artifact publisher is not allowed for the signed component role",
                    component_id=component.artifact_id,
                )
            if bundle.manifest.artifact_format.casefold() != component.artifact_format.casefold():
                _reject(
                    ModelPackageRejectReason.COMPONENT_ROLE_MISMATCH,
                    "artifact format does not match signed package component declaration",
                    component_id=component.artifact_id,
                )
            try:
                handle = self._artifact_loader.load(
                    request=ModelArtifactRequest(
                        artifact_id=component.artifact_id,
                        model_id=manifest.model_id,
                        revision=manifest.revision,
                    ),
                    manifest=bundle.manifest,
                    signature=bundle.signature,
                    payload=bundle.payload,
                )
            except ModelArtifactRejected as exc:
                _reject(
                    ModelPackageRejectReason.COMPONENT_INVALID,
                    "transitive artifact failed provenance validation",
                    component_id=component.artifact_id,
                    nested_reason=exc.reason.value,
                )
            verified.append((component, handle))

        return VerifiedModelPackage(
            package_id=manifest.package_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
            package_publisher_id=manifest.publisher_id,
            component_artifact_ids=tuple(item.artifact_id for item, _ in verified),
            component_roles=tuple(item.role.value for item, _ in verified),
            component_publishers=tuple(handle.publisher_id for _, handle in verified),
        )
