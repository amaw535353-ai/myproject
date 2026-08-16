from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P11A_POLICY_VERSION = "platform-workload-isolation-v1"
P11A_SCHEMA_VERSION = "aegis-platform-workload-security-manifest-v1"
P11A_ASSESSMENT_SCHEMA_VERSION = "aegis-platform-workload-security-assessment-v1"
P11A_ASSESSMENT_MODE = "deterministic-evidence-bound-container-kubernetes-workload-isolation-v1"


class PlatformDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class WorkloadRisk(str, Enum):
    UPSTREAM_P10I_INVALID = "upstream_p10i_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    REQUEST_ROUTE_MISMATCH = "request_route_mismatch"
    WORKLOAD_IDENTITY_MISMATCH = "workload_identity_mismatch"
    WORKLOAD_TENANT_MISMATCH = "workload_tenant_mismatch"
    SERVICE_ACCOUNT_MISMATCH = "service_account_mismatch"
    WORKLOAD_TOKEN_POLICY_MISMATCH = "workload_token_policy_mismatch"
    CONTAINER_COVERAGE_MISMATCH = "container_coverage_mismatch"
    IMAGE_DIGEST_MISMATCH = "image_digest_mismatch"
    ROOT_USER_UNSAFE = "root_user_unsafe"
    PRIVILEGED_CONTAINER = "privileged_container"
    PRIVILEGE_ESCALATION_ENABLED = "privilege_escalation_enabled"
    ROOT_FILESYSTEM_WRITABLE = "root_filesystem_writable"
    HOST_NAMESPACE_EXPOSED = "host_namespace_exposed"
    HOST_PATH_MOUNTED = "host_path_mounted"
    CAPABILITY_POLICY_MISMATCH = "capability_policy_mismatch"
    SECCOMP_POLICY_MISMATCH = "seccomp_policy_mismatch"
    LSM_POLICY_MISMATCH = "lsm_policy_mismatch"
    PROC_MOUNT_UNSAFE = "proc_mount_unsafe"
    WRITABLE_PATH_POLICY_MISMATCH = "writable_path_policy_mismatch"
    SECRET_COVERAGE_MISMATCH = "secret_coverage_mismatch"
    SECRET_TENANT_MISMATCH = "secret_tenant_mismatch"
    SECRET_PERMISSION_UNSAFE = "secret_permission_unsafe"
    SECRET_SOURCE_MISMATCH = "secret_source_mismatch"
    SECRET_DIGEST_MISMATCH = "secret_digest_mismatch"
    SECRET_ROTATION_INVALID = "secret_rotation_invalid"
    NETWORK_POLICY_COVERAGE_MISMATCH = "network_policy_coverage_mismatch"
    DEFAULT_DENY_MISSING = "default_deny_missing"
    NETWORK_PEER_POLICY_MISMATCH = "network_peer_policy_mismatch"
    NETWORK_PORT_POLICY_MISMATCH = "network_port_policy_mismatch"
    CLOUD_METADATA_EXPOSED = "cloud_metadata_exposed"
    KUBE_API_ACCESS_UNEXPECTED = "kube_api_access_unexpected"
    RBAC_COVERAGE_MISMATCH = "rbac_coverage_mismatch"
    RBAC_SUBJECT_MISMATCH = "rbac_subject_mismatch"
    RBAC_CLUSTER_SCOPE = "rbac_cluster_scope"
    RBAC_ROLE_MISMATCH = "rbac_role_mismatch"
    RBAC_WILDCARD = "rbac_wildcard"
    RBAC_VERB_EXCESS = "rbac_verb_excess"
    RBAC_RESOURCE_EXCESS = "rbac_resource_excess"
    IMAGE_TRUST_COVERAGE_MISMATCH = "image_trust_coverage_mismatch"
    MUTABLE_IMAGE_TAG = "mutable_image_tag"
    IMAGE_SIGNATURE_EVIDENCE_MISMATCH = "image_signature_evidence_mismatch"
    IMAGE_SBOM_MISMATCH = "image_sbom_mismatch"
    IMAGE_PROVENANCE_MISMATCH = "image_provenance_mismatch"
    CRITICAL_VULNERABILITY_PRESENT = "critical_vulnerability_present"
    ADMISSION_EVIDENCE_MISSING = "admission_evidence_missing"
    RUNTIME_CLASS_MISMATCH = "runtime_class_mismatch"
    CGROUP_POLICY_MISMATCH = "cgroup_policy_mismatch"
    USER_NAMESPACE_POLICY_MISMATCH = "user_namespace_policy_mismatch"
    RUNTIME_SECCOMP_DEFAULT_MISSING = "runtime_seccomp_default_missing"
    RUNTIME_LSM_MISSING = "runtime_lsm_missing"
    DEVICE_ACCESS_UNSAFE = "device_access_unsafe"
    HOST_SOCKET_EXPOSED = "host_socket_exposed"
    PTRACE_POLICY_UNSAFE = "ptrace_policy_unsafe"
    NODE_PRIVILEGED_COLOCATION = "node_privileged_colocation"
    DEFERRED_MASTERY_DEBT_DROPPED = "deferred_mastery_debt_dropped"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class WorkloadRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class PlatformWorkloadSecurityRejected(ValueError):
    def __init__(self, reason: WorkloadRejectReason, message: str):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason.value}: {message}")


def reject(reason: WorkloadRejectReason, message: str) -> None:
    raise PlatformWorkloadSecurityRejected(reason, message)


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(key.value if isinstance(key, Enum) else key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json_text(value) -> str:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value) -> str:
    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WorkloadIdentityEvidence:
    workload_id: str
    namespace: str
    tenant_id: str
    service_account: str
    pod_uid: str
    node_id: str
    runtime_class: str
    run_as_user: int
    run_as_group: int
    supplemental_groups: tuple[int, ...]
    workload_identity_subject: str
    workload_identity_audience: str
    token_expiry_epoch: int
    token_sha256: str
    automount_service_account_token: bool


@dataclass(frozen=True)
class ContainerBoundaryEvidence:
    container_id: str
    container_name: str
    image_ref: str
    image_digest: str
    run_as_non_root: bool
    run_as_user: int
    run_as_group: int
    privileged: bool
    allow_privilege_escalation: bool
    read_only_root_filesystem: bool
    host_network: bool
    host_pid: bool
    host_ipc: bool
    host_path_mounts: tuple[str, ...]
    added_capabilities: tuple[str, ...]
    dropped_capabilities: tuple[str, ...]
    seccomp_profile: str
    apparmor_profile: str
    proc_mount: str
    writable_paths: tuple[str, ...]


@dataclass(frozen=True)
class SecretProjectionEvidence:
    secret_id: str
    workload_id: str
    namespace: str
    tenant_id: str
    mount_path: str
    source_kind: str
    source_ref: str
    read_only: bool
    file_mode: int
    owner_uid: int
    owner_gid: int
    content_sha256: str
    rotation_epoch: int
    expires_at_epoch: int


@dataclass(frozen=True)
class NetworkPolicyEvidence:
    policy_id: str
    namespace: str
    selector_workload_id: str
    default_deny_ingress: bool
    default_deny_egress: bool
    allowed_ingress_peers: tuple[str, ...]
    allowed_egress_peers: tuple[str, ...]
    allowed_egress_ports: tuple[int, ...]
    cloud_metadata_blocked: bool
    kube_api_access_allowed: bool


@dataclass(frozen=True)
class RbacBindingEvidence:
    binding_id: str
    namespace: str
    subject_service_account: str
    role_name: str
    verbs: tuple[str, ...]
    resources: tuple[str, ...]
    resource_names: tuple[str, ...]
    cluster_scope: bool


@dataclass(frozen=True)
class ImageTrustEvidence:
    image_ref: str
    image_digest: str
    registry: str
    mutable_tag_used: bool
    signature_bundle_sha256: str
    sbom_sha256: str
    provenance_sha256: str
    critical_vulnerability_count: int
    admission_verified: bool


@dataclass(frozen=True)
class RuntimeBoundaryEvidence:
    runtime_class: str
    cgroup_mode: str
    user_namespace_mode: str
    seccomp_default: bool
    lsm_mode: str
    rootless_or_userns_remap: bool
    device_access_mode: str
    host_socket_mounts: tuple[str, ...]
    ptrace_restricted: bool
    privileged_workloads_on_node: int


@dataclass(frozen=True)
class PlatformWorkloadSecurityManifest:
    schema_version: str
    manifest_id: str
    created_at_epoch: int
    p10i_assessment_sha256: str
    p10i_manifest_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    router_id: str
    router_generation: int
    identity: WorkloadIdentityEvidence
    containers: tuple[ContainerBoundaryEvidence, ...]
    secrets: tuple[SecretProjectionEvidence, ...]
    network_policies: tuple[NetworkPolicyEvidence, ...]
    rbac_bindings: tuple[RbacBindingEvidence, ...]
    image_trust: tuple[ImageTrustEvidence, ...]
    runtime_boundary: RuntimeBoundaryEvidence
    deferred_mastery_items: tuple[str, ...]
    network_operations: int = 0


@dataclass(frozen=True)
class PlatformWorkloadSecurityPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_p10i_assessment_sha256: str
    expected_p10i_manifest_sha256: str
    expected_request_id: str
    expected_tenant_id: str
    expected_session_id: str
    expected_target_model_id: str
    expected_target_model_revision: str
    expected_adapter_ids: tuple[str, ...]
    expected_adapter_generation: int
    expected_router_id: str
    minimum_router_generation: int
    expected_workload_id: str
    expected_namespace: str
    expected_service_account: str
    expected_pod_uid: str
    expected_node_id: str
    expected_runtime_class: str
    expected_run_as_user: int
    expected_run_as_group: int
    expected_supplemental_groups: tuple[int, ...]
    expected_workload_identity_subject: str
    expected_workload_identity_audience: str
    expected_workload_token_sha256: str
    max_workload_token_ttl_seconds: int
    expected_container_ids: tuple[str, ...]
    expected_image_ref_by_container: Mapping[str, str]
    expected_image_digest_by_container: Mapping[str, str]
    allowed_writable_paths: tuple[str, ...]
    expected_secret_ids: tuple[str, ...]
    expected_secret_source_by_id: Mapping[str, str]
    expected_secret_ref_by_id: Mapping[str, str]
    expected_secret_mount_path_by_id: Mapping[str, str]
    expected_secret_digest_by_id: Mapping[str, str]
    max_secret_file_mode: int
    expected_network_policy_ids: tuple[str, ...]
    expected_ingress_peers: tuple[str, ...]
    expected_egress_peers: tuple[str, ...]
    expected_egress_ports: tuple[int, ...]
    expected_rbac_binding_ids: tuple[str, ...]
    expected_rbac_role_by_id: Mapping[str, str]
    allowed_rbac_verbs: tuple[str, ...]
    allowed_rbac_resources: tuple[str, ...]
    expected_image_refs: tuple[str, ...]
    allowed_registries: tuple[str, ...]
    max_critical_vulnerabilities: int
    expected_cgroup_mode: str
    expected_user_namespace_mode: str
    expected_lsm_mode: str
    expected_device_access_mode: str
    required_deferred_mastery_items: tuple[str, ...]
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class PlatformWorkloadSecurityRequest:
    manifest_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_tenant_id: str
    declared_namespace: str
    declared_workload_id: str
    declared_service_account: str
    declared_upstream_p10i_bound: bool
    declared_workload_identity_verified: bool
    declared_privilege_boundary_verified: bool
    declared_filesystem_boundary_verified: bool
    declared_secret_projection_verified: bool
    declared_network_policy_verified: bool
    declared_rbac_verified: bool
    declared_image_supply_chain_verified: bool
    declared_runtime_boundary_verified: bool
    declared_gpu_debt_carried: bool
    declared_workload_security_safe: bool


@dataclass(frozen=True)
class VerifiedPlatformWorkloadSecurityAssessment:
    manifest_id: str
    manifest_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    decision: PlatformDecision
    risks: tuple[WorkloadRisk, ...]
    p10i_assessment_sha256: str
    p10i_manifest_sha256: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    router_id: str
    router_generation: int
    workload_id: str
    namespace: str
    service_account: str
    container_ids: tuple[str, ...]
    image_refs: tuple[str, ...]
    upstream_p10i_bound: bool
    workload_identity_verified: bool
    privilege_boundary_verified: bool
    filesystem_boundary_verified: bool
    secret_projection_verified: bool
    network_policy_verified: bool
    rbac_verified: bool
    image_supply_chain_verified: bool
    runtime_boundary_verified: bool
    deferred_mastery_debt_carried: bool
    caller_declared_safety_trusted: bool
    live_kubernetes_cluster_validated: bool
    production_admission_controller_validated: bool
    production_cni_enforcement_validated: bool
    cloud_workload_identity_validated: bool
    container_escape_resistance_validated: bool
    kernel_hardening_validated: bool
    production_container_runtime_integrated: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def platform_workload_security_manifest_digest(manifest: PlatformWorkloadSecurityManifest) -> str:
    return digest_json(manifest)
