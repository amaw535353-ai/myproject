from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from .package_provenance import ModelPackageComponentRole, VerifiedModelPackage


P5E_RUNTIME_POLICY_VERSION = "model-runtime-isolation-remote-code-denial-v1"
P5E_RUNTIME_ADMISSION_MODE = "verified-synthetic-sandbox-plan-v1"
P5E_REQUIRED_ISOLATION_MODE = "deny-by-default-worker-v1"


class RuntimeAdmissionRejectReason(StrEnum):
    PACKAGE_UNVERIFIED = "package_unverified"
    IDENTITY_MISMATCH = "identity_mismatch"
    COMPONENT_SET_MISMATCH = "component_set_mismatch"
    COMPONENT_ROLE_MISMATCH = "component_role_mismatch"
    PARSER_DISALLOWED = "parser_disallowed"
    BACKEND_DISALLOWED = "backend_disallowed"
    REMOTE_CODE_REQUIRED = "remote_code_required"
    DYNAMIC_CODE_DISALLOWED = "dynamic_code_disallowed"
    CAPABILITY_DISALLOWED = "capability_disallowed"
    ISOLATION_REQUIRED = "isolation_required"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"


class RuntimeAdmissionRejected(ValueError):
    def __init__(
        self,
        reason: RuntimeAdmissionRejectReason,
        message: str,
        *,
        component_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.component_id = component_id


@dataclass(frozen=True)
class ModelRuntimeRequest:
    package_id: str
    model_id: str
    revision: str
    runtime_id: str


@dataclass(frozen=True)
class RuntimeComponentPlan:
    artifact_id: str
    role: ModelPackageComponentRole
    parser: str
    requires_remote_code: bool = False
    dynamic_module: str | None = None
    native_extensions: bool = False
    custom_ops: bool = False


@dataclass(frozen=True)
class RuntimeCapabilityRequest:
    network_access: bool = False
    subprocess: bool = False
    host_filesystem_write: bool = False
    environment_passthrough: bool = False
    host_ipc: bool = False
    ptrace: bool = False


@dataclass(frozen=True)
class ModelRuntimePlan:
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    backend: str
    components: tuple[RuntimeComponentPlan, ...]
    capabilities: RuntimeCapabilityRequest = RuntimeCapabilityRequest()
    isolation_mode: str = P5E_REQUIRED_ISOLATION_MODE
    memory_limit_mb: int = 2048
    cpu_time_limit_seconds: int = 30
    thread_limit: int = 4


@dataclass(frozen=True)
class ModelRuntimePolicy:
    allowed_parsers_by_role: Mapping[ModelPackageComponentRole, frozenset[str]]
    allowed_backends: frozenset[str]
    required_isolation_mode: str = P5E_REQUIRED_ISOLATION_MODE
    max_memory_mb: int = 4096
    max_cpu_time_seconds: int = 60
    max_threads: int = 8


@dataclass(frozen=True)
class VerifiedRuntimePlan:
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    backend: str
    component_artifact_ids: tuple[str, ...]
    component_parsers: tuple[str, ...]
    isolation_mode: str
    memory_limit_mb: int
    cpu_time_limit_seconds: int
    thread_limit: int
    provenance_verified: bool = True
    transitive_package_verified: bool = True
    parser_policy_verified: bool = True
    backend_policy_verified: bool = True
    remote_code_allowed: bool = False
    dynamic_code_allowed: bool = False
    native_extensions_allowed: bool = False
    custom_ops_allowed: bool = False
    network_access: bool = False
    subprocess_allowed: bool = False
    host_filesystem_write: bool = False
    environment_passthrough: bool = False
    host_ipc: bool = False
    ptrace_allowed: bool = False
    sandbox_required: bool = True
    policy_version: str = P5E_RUNTIME_POLICY_VERSION
    admission_mode: str = P5E_RUNTIME_ADMISSION_MODE
    model_bytes_parsed: bool = False
    model_executed: bool = False
    network_operations: int = 0


def default_runtime_policy() -> ModelRuntimePolicy:
    return ModelRuntimePolicy(
        allowed_parsers_by_role={
            ModelPackageComponentRole.PRIMARY_MODEL: frozenset(
                {"safetensors_reader", "onnx_reader"}
            ),
            ModelPackageComponentRole.CONFIG: frozenset({"json_reader"}),
            ModelPackageComponentRole.TOKENIZER: frozenset({"json_reader"}),
            ModelPackageComponentRole.ADAPTER: frozenset({"safetensors_reader"}),
            ModelPackageComponentRole.QUANTIZATION_METADATA: frozenset({"json_reader"}),
            ModelPackageComponentRole.EXTERNAL_DATA: frozenset({"opaque_tensor_data"}),
        },
        allowed_backends=frozenset(
            {"sandboxed_tensor_runtime", "sandboxed_onnxruntime"}
        ),
    )


def _reject(
    reason: RuntimeAdmissionRejectReason,
    message: str,
    *,
    component_id: str | None = None,
) -> None:
    raise RuntimeAdmissionRejected(reason, message, component_id=component_id)


def _verified_package_roles(
    package: VerifiedModelPackage,
) -> dict[str, ModelPackageComponentRole]:
    if (
        not package.package_signature_verified
        or not package.transitive_components_verified
        or not package.dependency_graph_verified
        or package.remote_code_required
        or package.deserialized
        or package.code_execution_capable
        or package.network_operations != 0
    ):
        _reject(
            RuntimeAdmissionRejectReason.PACKAGE_UNVERIFIED,
            "runtime admission requires an intact non-executing P5-B verified package handle",
        )
    if len(package.component_artifact_ids) != len(package.component_roles):
        _reject(
            RuntimeAdmissionRejectReason.PACKAGE_UNVERIFIED,
            "verified package component metadata is inconsistent",
        )
    if len(package.component_artifact_ids) != len(set(package.component_artifact_ids)):
        _reject(
            RuntimeAdmissionRejectReason.PACKAGE_UNVERIFIED,
            "verified package component IDs must be unique",
        )

    roles: dict[str, ModelPackageComponentRole] = {}
    for artifact_id, role_value in zip(
        package.component_artifact_ids, package.component_roles, strict=True
    ):
        try:
            role = ModelPackageComponentRole(role_value)
        except ValueError:
            _reject(
                RuntimeAdmissionRejectReason.PACKAGE_UNVERIFIED,
                "verified package contains an unknown component role",
                component_id=artifact_id,
            )
        roles[artifact_id] = role
    return roles


class RestrictedModelRuntimeBoundary:
    """Validate a synthetic sandbox execution plan without parsing or executing model bytes.

    P5-E is an admission boundary, not a real sandbox implementation. It ensures that a
    previously verified package can only be handed to an explicitly data-only parser/backend
    plan with deny-by-default host capabilities and bounded synthetic resource requests.
    """

    def __init__(self, policy: ModelRuntimePolicy | None = None) -> None:
        self._policy = policy or default_runtime_policy()

    def admit(
        self,
        *,
        request: ModelRuntimeRequest,
        package: VerifiedModelPackage,
        plan: ModelRuntimePlan,
    ) -> VerifiedRuntimePlan:
        package_roles = _verified_package_roles(package)

        expected_identity = (request.package_id, request.model_id, request.revision)
        if expected_identity != (package.package_id, package.model_id, package.revision):
            _reject(
                RuntimeAdmissionRejectReason.IDENTITY_MISMATCH,
                "verified package identity does not match runtime request",
            )
        if (
            expected_identity
            != (plan.package_id, plan.model_id, plan.revision)
            or request.runtime_id != plan.runtime_id
        ):
            _reject(
                RuntimeAdmissionRejectReason.IDENTITY_MISMATCH,
                "runtime plan identity does not match runtime request",
            )

        if plan.backend not in self._policy.allowed_backends:
            _reject(
                RuntimeAdmissionRejectReason.BACKEND_DISALLOWED,
                "runtime backend is not in the explicit sandbox backend allowlist",
            )

        if plan.isolation_mode != self._policy.required_isolation_mode:
            _reject(
                RuntimeAdmissionRejectReason.ISOLATION_REQUIRED,
                "runtime plan does not request the required deny-by-default isolation mode",
            )

        if (
            plan.memory_limit_mb <= 0
            or plan.cpu_time_limit_seconds <= 0
            or plan.thread_limit <= 0
            or plan.memory_limit_mb > self._policy.max_memory_mb
            or plan.cpu_time_limit_seconds > self._policy.max_cpu_time_seconds
            or plan.thread_limit > self._policy.max_threads
        ):
            _reject(
                RuntimeAdmissionRejectReason.RESOURCE_LIMIT_EXCEEDED,
                "runtime resource request is outside configured limits",
            )

        requested_ids = [item.artifact_id for item in plan.components]
        if len(requested_ids) != len(set(requested_ids)) or set(requested_ids) != set(
            package_roles
        ):
            _reject(
                RuntimeAdmissionRejectReason.COMPONENT_SET_MISMATCH,
                "runtime component set must exactly match the verified package closure",
            )

        for component in sorted(plan.components, key=lambda item: item.artifact_id):
            expected_role = package_roles[component.artifact_id]
            if component.role is not expected_role:
                _reject(
                    RuntimeAdmissionRejectReason.COMPONENT_ROLE_MISMATCH,
                    "runtime component role does not match verified package role",
                    component_id=component.artifact_id,
                )

            allowed_parsers = self._policy.allowed_parsers_by_role.get(
                expected_role, frozenset()
            )
            if component.parser not in allowed_parsers:
                _reject(
                    RuntimeAdmissionRejectReason.PARSER_DISALLOWED,
                    "parser is not allowed for the verified component role",
                    component_id=component.artifact_id,
                )

            if component.requires_remote_code:
                _reject(
                    RuntimeAdmissionRejectReason.REMOTE_CODE_REQUIRED,
                    "runtime component requests remote or repository-supplied code",
                    component_id=component.artifact_id,
                )

            if (
                component.dynamic_module
                or component.native_extensions
                or component.custom_ops
            ):
                _reject(
                    RuntimeAdmissionRejectReason.DYNAMIC_CODE_DISALLOWED,
                    "dynamic modules, native extensions, and custom operators are denied",
                    component_id=component.artifact_id,
                )

        capabilities = plan.capabilities
        if (
            capabilities.network_access
            or capabilities.subprocess
            or capabilities.host_filesystem_write
            or capabilities.environment_passthrough
            or capabilities.host_ipc
            or capabilities.ptrace
        ):
            _reject(
                RuntimeAdmissionRejectReason.CAPABILITY_DISALLOWED,
                "runtime plan requests a denied host capability",
            )

        ordered = tuple(sorted(plan.components, key=lambda item: item.artifact_id))
        return VerifiedRuntimePlan(
            package_id=package.package_id,
            model_id=package.model_id,
            revision=package.revision,
            runtime_id=plan.runtime_id,
            backend=plan.backend,
            component_artifact_ids=tuple(item.artifact_id for item in ordered),
            component_parsers=tuple(item.parser for item in ordered),
            isolation_mode=plan.isolation_mode,
            memory_limit_mb=plan.memory_limit_mb,
            cpu_time_limit_seconds=plan.cpu_time_limit_seconds,
            thread_limit=plan.thread_limit,
        )
