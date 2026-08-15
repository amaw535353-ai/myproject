from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P10F_POLICY_VERSION = "inference-accelerator-isolation-v1"
P10F_SCHEMA_VERSION = "aegis-inference-accelerator-isolation-manifest-v1"
P10F_ASSESSMENT_SCHEMA_VERSION = "aegis-inference-accelerator-isolation-assessment-v1"
P10F_ASSESSMENT_MODE = "deterministic-evidence-bound-accelerator-isolation-v1"
P10F_HOST_PROBE_SCHEMA_VERSION = "aegis-p10f-host-accelerator-probe-v1"


class AcceleratorDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class AcceleratorPartitionMode(str, Enum):
    EXCLUSIVE_GPU = "exclusive_gpu"
    MIG = "mig"
    MPS = "mps"
    TIME_SLICE = "time_slice"


class AcceleratorRisk(str, Enum):
    UPSTREAM_P10E_INVALID = "upstream_p10e_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    REQUEST_ROUTE_MISMATCH = "request_route_mismatch"
    HOST_PROBE_BINDING_MISMATCH = "host_probe_binding_mismatch"
    DEVICE_COVERAGE_MISMATCH = "device_coverage_mismatch"
    DEVICE_IDENTITY_MISMATCH = "device_identity_mismatch"
    DEVICE_ASSIGNMENT_MISMATCH = "device_assignment_mismatch"
    UNSAFE_PARTITION_MODE = "unsafe_partition_mode"
    CROSS_TENANT_DEVICE_SHARE = "cross_tenant_device_share"
    MIG_INSTANCE_MISMATCH = "mig_instance_mismatch"
    MIG_MEMORY_SLICE_OVERLAP = "mig_memory_slice_overlap"
    DEVICE_NODE_SCOPE_MISMATCH = "device_node_scope_mismatch"
    CGROUP_DEVICE_POLICY_MISSING = "cgroup_device_policy_missing"
    IOMMU_DISABLED = "iommu_disabled"
    IOMMU_GROUP_MISMATCH = "iommu_group_mismatch"
    DMA_PEER_ACCESS_UNAUTHORIZED = "dma_peer_access_unauthorized"
    GPUDIRECT_RDMA_UNAUTHORIZED = "gpudirect_rdma_unauthorized"
    MEMORY_BUDGET_EXCEEDED = "memory_budget_exceeded"
    MEMORY_OWNER_MISMATCH = "memory_owner_mismatch"
    ADDRESS_SPACE_REUSE = "address_space_reuse"
    MEMORY_EPOCH_MISMATCH = "memory_epoch_mismatch"
    PROFILING_ACCESS_UNSAFE = "profiling_access_unsafe"
    TELEMETRY_ACCESS_UNSAFE = "telemetry_access_unsafe"
    SIDE_CHANNEL_PROFILE_UNSAFE = "side_channel_profile_unsafe"
    LEASE_COVERAGE_MISMATCH = "lease_coverage_mismatch"
    LEASE_EXPIRED = "lease_expired"
    LEASE_REPLAY = "lease_replay"
    LEASE_GENERATION_ROLLBACK = "lease_generation_rollback"
    LEASE_BINDING_MISMATCH = "lease_binding_mismatch"
    PRIOR_LEASE_LEDGER_MISMATCH = "prior_lease_ledger_mismatch"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class AcceleratorRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class InferenceAcceleratorIsolationRejected(ValueError):
    def __init__(self, reason: AcceleratorRejectReason, message: str):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason.value}: {message}")


def reject(reason: AcceleratorRejectReason, message: str) -> None:
    raise InferenceAcceleratorIsolationRejected(reason, message)


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


def digest_json(value) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class AcceleratorHostProbeEvidence:
    schema_version: str
    probe_id: str
    collected_at_epoch: int
    hostname_sha256: str
    kernel_release: str
    nvidia_smi_available: bool
    hardware_present: bool
    device_inventory_sha256: str
    device_node_inventory_sha256: str
    iommu_inventory_sha256: str
    runtime_visibility_sha256: str
    raw_evidence_sha256: str


@dataclass(frozen=True)
class AcceleratorPartitionEvidence:
    partition_id: str
    physical_gpu_id: str
    gpu_uuid: str
    pci_bdf: str
    driver_version: str
    partition_mode: AcceleratorPartitionMode
    tenant_id: str
    session_id: str
    mig_gpu_instance_id: str
    mig_compute_instance_id: str
    mig_profile: str
    memory_slice_ids: tuple[str, ...]
    co_resident_tenant_ids: tuple[str, ...]
    co_resident_partition_ids: tuple[str, ...]
    co_resident_mig_gpu_instance_ids: tuple[str, ...]
    co_resident_memory_slice_ids: tuple[str, ...]
    iommu_group_id: str
    iommu_group_members: tuple[str, ...]
    device_nodes: tuple[str, ...]
    cgroup_device_policy_enforced: bool
    iommu_enabled: bool
    peer_access_enabled: bool
    gpudirect_rdma_enabled: bool
    profiling_access_enabled: bool
    telemetry_admin_only: bool
    shared_l2: bool
    shared_memory_controller: bool
    shared_copy_engines: bool
    shared_scheduler: bool
    address_space_id: str
    memory_epoch: int
    memory_generation: int
    reserved_memory_bytes: int
    allocated_memory_bytes: int


@dataclass(frozen=True)
class AcceleratorLeaseEvidence:
    lease_id: str
    request_id: str
    tenant_id: str
    session_id: str
    partition_id: str
    issued_at_epoch: int
    expires_at_epoch: int
    generation: int
    allocation_sha256: str
    previous_lease_sha256: str


@dataclass(frozen=True)
class InferenceAcceleratorIsolationManifest:
    schema_version: str
    manifest_id: str
    created_at_epoch: int
    p10e_assessment_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    host_probe: AcceleratorHostProbeEvidence
    partitions: tuple[AcceleratorPartitionEvidence, ...]
    leases: tuple[AcceleratorLeaseEvidence, ...]
    prior_lease_ids: tuple[str, ...]
    prior_lease_ledger_sha256: str
    network_operations: int = 0


@dataclass(frozen=True)
class InferenceAcceleratorIsolationPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_p10e_assessment_sha256: str
    expected_request_id: str
    expected_tenant_id: str
    expected_session_id: str
    expected_target_model_id: str
    expected_target_model_revision: str
    expected_adapter_ids: tuple[str, ...]
    expected_adapter_generation: int
    expected_host_probe_schema_version: str
    expected_host_probe_id: str
    expected_host_probe_raw_evidence_sha256: str
    require_hardware_present: bool
    require_nvidia_smi: bool
    expected_partition_ids: tuple[str, ...]
    expected_physical_gpu_id_by_partition: Mapping[str, str]
    expected_gpu_uuid_by_partition: Mapping[str, str]
    expected_pci_bdf_by_partition: Mapping[str, str]
    expected_partition_mode_by_partition: Mapping[str, AcceleratorPartitionMode]
    expected_partition_topology_sha256_by_partition: Mapping[str, str]
    expected_mig_gpu_instance_by_partition: Mapping[str, str]
    expected_mig_compute_instance_by_partition: Mapping[str, str]
    expected_mig_profile_by_partition: Mapping[str, str]
    expected_memory_slice_ids_by_partition: Mapping[str, tuple[str, ...]]
    expected_iommu_group_id_by_partition: Mapping[str, str]
    expected_iommu_group_members_by_partition: Mapping[str, tuple[str, ...]]
    allowed_device_nodes_by_partition: Mapping[str, tuple[str, ...]]
    expected_address_space_id_by_partition: Mapping[str, str]
    minimum_memory_epoch_by_partition: Mapping[str, int]
    minimum_memory_generation_by_partition: Mapping[str, int]
    max_reserved_memory_bytes_by_partition: Mapping[str, int]
    max_allocated_memory_bytes_by_partition: Mapping[str, int]
    allowed_partition_modes: tuple[AcceleratorPartitionMode, ...]
    allow_peer_access: bool
    allow_gpudirect_rdma: bool
    require_cgroup_device_policy: bool
    require_iommu: bool
    require_profiling_disabled: bool
    require_telemetry_admin_only: bool
    require_strict_side_channel_profile: bool
    expected_lease_ids: tuple[str, ...]
    expected_prior_lease_ledger_sha256: str
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class InferenceAcceleratorIsolationRequest:
    manifest_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_request_id: str
    declared_tenant_id: str
    declared_session_id: str
    declared_partition_ids: tuple[str, ...]
    declared_lease_ids: tuple[str, ...]
    declared_upstream_p10e_bound: bool
    declared_host_probe_bound: bool
    declared_device_assignment_safe: bool
    declared_dma_isolation_safe: bool
    declared_memory_isolation_safe: bool
    declared_side_channel_profile_safe: bool
    declared_lease_safe: bool
    declared_accelerator_safe: bool


@dataclass(frozen=True)
class VerifiedInferenceAcceleratorIsolationAssessment:
    manifest_id: str
    manifest_sha256: str
    request_id: str
    tenant_id: str
    session_id: str
    decision: AcceleratorDecision
    risks: tuple[AcceleratorRisk, ...]
    p10e_assessment_sha256: str
    target_model_id: str
    target_model_revision: str
    adapter_ids: tuple[str, ...]
    adapter_generation: int
    partition_ids: tuple[str, ...]
    lease_ids: tuple[str, ...]
    upstream_p10e_bound: bool
    host_probe_bound: bool
    device_assignment_verified: bool
    dma_isolation_verified: bool
    memory_isolation_verified: bool
    side_channel_profile_verified: bool
    lease_safety_verified: bool
    caller_declared_safety_trusted: bool
    live_gpu_hardware_validated: bool
    production_gpu_runtime_integrated: bool
    production_cgroup_enforcement_verified: bool
    production_iommu_enforcement_verified: bool
    physical_vram_zeroization_verified: bool
    dma_attack_resistance_validated: bool
    side_channel_resistance_validated: bool
    hardware_attestation_verified: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def host_probe_payload_digest(probe: AcceleratorHostProbeEvidence) -> str:
    return digest_json(
        {
            "schema_version": probe.schema_version,
            "probe_id": probe.probe_id,
            "collected_at_epoch": probe.collected_at_epoch,
            "hostname_sha256": probe.hostname_sha256,
            "kernel_release": probe.kernel_release,
            "nvidia_smi_available": probe.nvidia_smi_available,
            "hardware_present": probe.hardware_present,
            "device_inventory_sha256": probe.device_inventory_sha256,
            "device_node_inventory_sha256": probe.device_node_inventory_sha256,
            "iommu_inventory_sha256": probe.iommu_inventory_sha256,
            "runtime_visibility_sha256": probe.runtime_visibility_sha256,
        }
    )


def host_probe_digest(probe: AcceleratorHostProbeEvidence) -> str:
    return digest_json(probe)


def accelerator_partition_topology_digest(partition: AcceleratorPartitionEvidence) -> str:
    return digest_json(
        {
            "partition_id": partition.partition_id,
            "physical_gpu_id": partition.physical_gpu_id,
            "gpu_uuid": partition.gpu_uuid,
            "pci_bdf": partition.pci_bdf.casefold(),
            "driver_version": partition.driver_version,
            "partition_mode": partition.partition_mode,
            "mig_gpu_instance_id": partition.mig_gpu_instance_id,
            "mig_compute_instance_id": partition.mig_compute_instance_id,
            "mig_profile": partition.mig_profile,
            "memory_slice_ids": partition.memory_slice_ids,
            "co_resident_tenant_ids": partition.co_resident_tenant_ids,
            "co_resident_partition_ids": partition.co_resident_partition_ids,
            "co_resident_mig_gpu_instance_ids": partition.co_resident_mig_gpu_instance_ids,
            "co_resident_memory_slice_ids": partition.co_resident_memory_slice_ids,
            "iommu_group_id": partition.iommu_group_id,
            "iommu_group_members": tuple(x.casefold() for x in partition.iommu_group_members),
            "device_nodes": partition.device_nodes,
        }
    )


def accelerator_partition_digest(partition: AcceleratorPartitionEvidence) -> str:
    return digest_json(partition)


def accelerator_lease_digest(lease: AcceleratorLeaseEvidence) -> str:
    return digest_json(lease)


def prior_lease_ledger_digest(ids: tuple[str, ...]) -> str:
    return digest_json({"prior_lease_ids": tuple(sorted(ids))})


def inference_accelerator_isolation_manifest_digest(
    manifest: InferenceAcceleratorIsolationManifest,
) -> str:
    return digest_json(manifest)
