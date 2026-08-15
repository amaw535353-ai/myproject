from __future__ import annotations

import re

from .adapter_routing_types import (
    P10E_ASSESSMENT_MODE,
    P10E_ASSESSMENT_SCHEMA_VERSION,
    AdapterDecision,
    VerifiedInferenceAdapterRoutingAssessment,
)
from .accelerator_isolation_types import *

_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9._:/@+-]{1,127}$")
_PCI = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")


class InferenceAcceleratorIsolationAnalyzer:
    def __init__(self, policy: InferenceAcceleratorIsolationPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA.fullmatch(str(value)))

    @staticmethod
    def _id(value: str) -> bool:
        return bool(_ID.fullmatch(str(value)))

    @staticmethod
    def _pci(value: str) -> bool:
        return bool(_PCI.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P10F_POLICY_VERSION:
            reject(AcceleratorRejectReason.POLICY_INVALID, "unexpected policy version")
        ids = (
            p.expected_manifest_id,
            p.expected_request_id,
            p.expected_tenant_id,
            p.expected_session_id,
            p.expected_target_model_id,
            p.expected_target_model_revision,
            p.expected_host_probe_id,
        )
        if not all(map(self._id, ids)) or not p.expected_session_id.startswith(
            f"tenant/{p.expected_tenant_id}/session/"
        ):
            reject(AcceleratorRejectReason.POLICY_INVALID, "policy identity pins invalid")
        if p.expected_host_probe_schema_version != P10F_HOST_PROBE_SCHEMA_VERSION:
            reject(AcceleratorRejectReason.POLICY_INVALID, "unexpected host probe schema")
        if not all(
            map(
                self._sha,
                (
                    p.expected_manifest_sha256,
                    p.expected_p10e_assessment_sha256,
                    p.expected_host_probe_raw_evidence_sha256,
                    p.expected_prior_lease_ledger_sha256,
                ),
            )
        ):
            reject(AcceleratorRejectReason.POLICY_INVALID, "policy digest pins invalid")
        partitions = set(p.expected_partition_ids)
        if not partitions or len(partitions) != len(p.expected_partition_ids):
            reject(AcceleratorRejectReason.POLICY_INVALID, "partition identifiers invalid")
        maps = (
            p.expected_physical_gpu_id_by_partition,
            p.expected_gpu_uuid_by_partition,
            p.expected_pci_bdf_by_partition,
            p.expected_partition_mode_by_partition,
            p.expected_partition_topology_sha256_by_partition,
            p.expected_mig_gpu_instance_by_partition,
            p.expected_mig_compute_instance_by_partition,
            p.expected_mig_profile_by_partition,
            p.expected_memory_slice_ids_by_partition,
            p.expected_iommu_group_id_by_partition,
            p.expected_iommu_group_members_by_partition,
            p.allowed_device_nodes_by_partition,
            p.expected_address_space_id_by_partition,
            p.minimum_memory_epoch_by_partition,
            p.minimum_memory_generation_by_partition,
            p.max_reserved_memory_bytes_by_partition,
            p.max_allocated_memory_bytes_by_partition,
        )
        if any(set(mapping) != partitions for mapping in maps):
            reject(AcceleratorRejectReason.POLICY_INVALID, "partition policy coverage invalid")
        if not p.allowed_partition_modes or any(
            mode not in (AcceleratorPartitionMode.EXCLUSIVE_GPU, AcceleratorPartitionMode.MIG)
            for mode in p.allowed_partition_modes
        ):
            reject(AcceleratorRejectReason.POLICY_INVALID, "unsafe partition mode allowlist")
        if p.expected_adapter_generation < 0 or min(
            p.max_manifest_age_seconds, p.max_future_skew_seconds
        ) < 0:
            reject(AcceleratorRejectReason.POLICY_INVALID, "policy bounds invalid")
        for partition_id in p.expected_partition_ids:
            if not self._id(partition_id):
                reject(AcceleratorRejectReason.POLICY_INVALID, "partition id malformed")
            if not self._id(p.expected_physical_gpu_id_by_partition[partition_id]):
                reject(AcceleratorRejectReason.POLICY_INVALID, "physical gpu id malformed")
            if not self._id(p.expected_gpu_uuid_by_partition[partition_id]):
                reject(AcceleratorRejectReason.POLICY_INVALID, "gpu uuid malformed")
            if not self._pci(p.expected_pci_bdf_by_partition[partition_id]):
                reject(AcceleratorRejectReason.POLICY_INVALID, "pci bdf malformed")
            if p.expected_partition_mode_by_partition[partition_id] not in p.allowed_partition_modes:
                reject(AcceleratorRejectReason.POLICY_INVALID, "expected partition mode disallowed")
            if p.minimum_memory_epoch_by_partition[partition_id] < 0 or p.minimum_memory_generation_by_partition[partition_id] < 0:
                reject(AcceleratorRejectReason.POLICY_INVALID, "memory generation floor invalid")
            if p.max_reserved_memory_bytes_by_partition[partition_id] <= 0 or p.max_allocated_memory_bytes_by_partition[partition_id] <= 0:
                reject(AcceleratorRejectReason.POLICY_INVALID, "memory budget invalid")
            if p.max_allocated_memory_bytes_by_partition[partition_id] > p.max_reserved_memory_bytes_by_partition[partition_id]:
                reject(AcceleratorRejectReason.POLICY_INVALID, "allocated budget exceeds reserved budget")
            if not p.allowed_device_nodes_by_partition[partition_id]:
                reject(AcceleratorRejectReason.POLICY_INVALID, "device node allowlist empty")
        leases = set(p.expected_lease_ids)
        if not leases or len(leases) != len(p.expected_lease_ids) or not all(map(self._id, leases)):
            reject(AcceleratorRejectReason.POLICY_INVALID, "lease policy coverage invalid")

    def _validate_manifest(self, m: InferenceAcceleratorIsolationManifest) -> None:
        if (
            m.schema_version != P10F_SCHEMA_VERSION
            or m.manifest_id != self.policy.expected_manifest_id
            or not self._id(m.manifest_id)
            or m.created_at_epoch <= 0
        ):
            reject(AcceleratorRejectReason.MANIFEST_INVALID, "manifest identity/schema/time invalid")
        ids = (
            m.request_id,
            m.tenant_id,
            m.session_id,
            m.target_model_id,
            m.target_model_revision,
            m.host_probe.probe_id,
        )
        if not all(map(self._id, ids)) or not m.session_id.startswith(
            f"tenant/{m.tenant_id}/session/"
        ):
            reject(AcceleratorRejectReason.MANIFEST_INVALID, "route identifiers malformed")
        if not self._sha(m.p10e_assessment_sha256):
            reject(AcceleratorRejectReason.MANIFEST_INVALID, "upstream digest malformed")
        probe = m.host_probe
        if (
            probe.schema_version != P10F_HOST_PROBE_SCHEMA_VERSION
            or probe.collected_at_epoch <= 0
            or not self._id(probe.probe_id)
            or not probe.kernel_release
            or not all(
                map(
                    self._sha,
                    (
                        probe.hostname_sha256,
                        probe.device_inventory_sha256,
                        probe.device_node_inventory_sha256,
                        probe.iommu_inventory_sha256,
                        probe.runtime_visibility_sha256,
                        probe.raw_evidence_sha256,
                    ),
                )
            )
        ):
            reject(AcceleratorRejectReason.MANIFEST_INVALID, "host probe evidence malformed")
        if not m.partitions or len({x.partition_id for x in m.partitions}) != len(m.partitions):
            reject(AcceleratorRejectReason.MANIFEST_INVALID, "partition evidence empty or duplicated")
        for x in m.partitions:
            if not all(
                map(
                    self._id,
                    (
                        x.partition_id,
                        x.physical_gpu_id,
                        x.gpu_uuid,
                        x.tenant_id,
                        x.session_id,
                        x.iommu_group_id,
                        x.address_space_id,
                    ),
                )
            ) or not self._pci(x.pci_bdf):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "partition identity malformed")
            if not x.driver_version or not x.session_id.startswith(f"tenant/{x.tenant_id}/session/"):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "partition route malformed")
            if x.memory_epoch < 0 or x.memory_generation < 0 or min(
                x.reserved_memory_bytes, x.allocated_memory_bytes
            ) < 0 or x.allocated_memory_bytes > x.reserved_memory_bytes:
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "partition memory evidence malformed")
            sequences = (
                x.memory_slice_ids,
                x.co_resident_tenant_ids,
                x.co_resident_partition_ids,
                x.co_resident_mig_gpu_instance_ids,
                x.co_resident_memory_slice_ids,
                x.iommu_group_members,
                x.device_nodes,
            )
            if any(len(seq) != len(set(seq)) for seq in sequences):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "partition evidence duplicated")
            if any(not self._id(v) for v in x.memory_slice_ids + x.co_resident_tenant_ids + x.co_resident_partition_ids + x.co_resident_mig_gpu_instance_ids + x.co_resident_memory_slice_ids):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "partition topology identifier malformed")
            if any(not self._pci(v) for v in x.iommu_group_members):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "iommu member malformed")
            if any(not v.startswith("/dev/") for v in x.device_nodes):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "device node path malformed")
            if x.partition_mode == AcceleratorPartitionMode.MIG:
                if not all((x.mig_gpu_instance_id, x.mig_compute_instance_id, x.mig_profile, x.memory_slice_ids)):
                    reject(AcceleratorRejectReason.MANIFEST_INVALID, "MIG evidence incomplete")
            elif any((x.mig_gpu_instance_id, x.mig_compute_instance_id, x.mig_profile, x.memory_slice_ids)):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "non-MIG partition carries MIG evidence")
        if not m.leases or len({x.lease_id for x in m.leases}) != len(m.leases):
            reject(AcceleratorRejectReason.MANIFEST_INVALID, "lease evidence empty or duplicated")
        for lease in m.leases:
            if not all(
                map(
                    self._id,
                    (
                        lease.lease_id,
                        lease.request_id,
                        lease.tenant_id,
                        lease.session_id,
                        lease.partition_id,
                    ),
                )
            ) or not all(map(self._sha, (lease.allocation_sha256, lease.previous_lease_sha256))):
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "lease evidence malformed")
            if lease.issued_at_epoch <= 0 or lease.expires_at_epoch <= lease.issued_at_epoch or lease.generation < 0:
                reject(AcceleratorRejectReason.MANIFEST_INVALID, "lease time/generation malformed")
        if len(m.prior_lease_ids) != len(set(m.prior_lease_ids)) or any(
            not self._id(v) for v in m.prior_lease_ids
        ) or not self._sha(m.prior_lease_ledger_sha256) or m.network_operations < 0:
            reject(AcceleratorRejectReason.MANIFEST_INVALID, "lease ledger/network malformed")

    @staticmethod
    def _upstream_ok(a: VerifiedInferenceAdapterRoutingAssessment) -> bool:
        flags = (
            a.upstream_p10d_bound,
            a.base_route_verified,
            a.adapter_artifacts_verified,
            a.tenant_composition_verified,
            a.authorization_verified,
            a.hot_swap_verified,
            a.route_snapshot_verified,
        )
        nonclaims = (
            a.caller_declared_safety_trusted,
            a.production_adapter_manager_integrated,
            a.production_model_router_integrated,
            a.cryptographic_adapter_signature_verified,
            a.atomic_hot_swap_validated,
            a.distributed_route_consistency_validated,
            a.side_channel_resistance_validated,
        )
        return (
            a.decision == AdapterDecision.ALLOW
            and not a.risks
            and all(flags)
            and not any(nonclaims)
            and a.assessment_schema_version == P10E_ASSESSMENT_SCHEMA_VERSION
            and a.assessment_mode == P10E_ASSESSMENT_MODE
        )

    def derive(
        self,
        m: InferenceAcceleratorIsolationManifest,
        a: VerifiedInferenceAdapterRoutingAssessment,
    ) -> tuple[AcceleratorRisk, ...]:
        self._validate_manifest(m)
        p = self.policy
        risks: set[AcceleratorRisk] = set()
        partitions = {x.partition_id: x for x in m.partitions}
        leases = {x.lease_id: x for x in m.leases}

        if not self._upstream_ok(a):
            risks.add(AcceleratorRisk.UPSTREAM_P10E_INVALID)
        if (
            m.p10e_assessment_sha256.casefold() != p.expected_p10e_assessment_sha256.casefold()
            or a.assessment_evidence_sha256.casefold() != p.expected_p10e_assessment_sha256.casefold()
        ):
            risks.add(AcceleratorRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            (m.request_id, m.tenant_id, m.session_id)
            != (p.expected_request_id, p.expected_tenant_id, p.expected_session_id)
            or (a.request_id, a.tenant_id, a.session_id)
            != (m.request_id, m.tenant_id, m.session_id)
            or (m.target_model_id, m.target_model_revision)
            != (p.expected_target_model_id, p.expected_target_model_revision)
            or (a.target_model_id, a.target_model_revision)
            != (m.target_model_id, m.target_model_revision)
            or m.adapter_ids != p.expected_adapter_ids
            or a.after_adapter_ids != m.adapter_ids
            or m.adapter_generation != p.expected_adapter_generation
            or a.after_generation != m.adapter_generation
        ):
            risks.add(AcceleratorRisk.REQUEST_ROUTE_MISMATCH)

        probe = m.host_probe
        if (
            probe.raw_evidence_sha256.casefold() != host_probe_payload_digest(probe).casefold()
            or probe.schema_version != p.expected_host_probe_schema_version
            or probe.probe_id != p.expected_host_probe_id
            or probe.raw_evidence_sha256.casefold()
            != p.expected_host_probe_raw_evidence_sha256.casefold()
            or (p.require_hardware_present and not probe.hardware_present)
            or (p.require_nvidia_smi and not probe.nvidia_smi_available)
            or probe.collected_at_epoch < m.created_at_epoch - p.max_manifest_age_seconds
            or probe.collected_at_epoch > m.created_at_epoch + p.max_future_skew_seconds
        ):
            risks.add(AcceleratorRisk.HOST_PROBE_BINDING_MISMATCH)

        if tuple(x.partition_id for x in m.partitions) != p.expected_partition_ids or set(
            partitions
        ) != set(p.expected_partition_ids):
            risks.add(AcceleratorRisk.DEVICE_COVERAGE_MISMATCH)

        for x in m.partitions:
            if accelerator_partition_topology_digest(x).casefold() != p.expected_partition_topology_sha256_by_partition.get(x.partition_id, "").casefold():
                risks.add(AcceleratorRisk.DEVICE_IDENTITY_MISMATCH)
            if (
                x.physical_gpu_id != p.expected_physical_gpu_id_by_partition.get(x.partition_id)
                or x.gpu_uuid != p.expected_gpu_uuid_by_partition.get(x.partition_id)
                or x.pci_bdf.casefold()
                != p.expected_pci_bdf_by_partition.get(x.partition_id, "").casefold()
                or x.partition_mode != p.expected_partition_mode_by_partition.get(x.partition_id)
            ):
                risks.add(AcceleratorRisk.DEVICE_IDENTITY_MISMATCH)
            if x.partition_mode not in p.allowed_partition_modes:
                risks.add(AcceleratorRisk.UNSAFE_PARTITION_MODE)
            if (x.tenant_id, x.session_id) != (m.tenant_id, m.session_id):
                risks.add(AcceleratorRisk.DEVICE_ASSIGNMENT_MISMATCH)
            if any(t != m.tenant_id for t in x.co_resident_tenant_ids):
                if x.partition_mode != AcceleratorPartitionMode.MIG:
                    risks.add(AcceleratorRisk.CROSS_TENANT_DEVICE_SHARE)
                if not x.co_resident_partition_ids or not x.co_resident_mig_gpu_instance_ids:
                    risks.add(AcceleratorRisk.MIG_INSTANCE_MISMATCH)
            if x.partition_mode == AcceleratorPartitionMode.MIG:
                if (
                    x.mig_gpu_instance_id
                    != p.expected_mig_gpu_instance_by_partition.get(x.partition_id)
                    or x.mig_compute_instance_id
                    != p.expected_mig_compute_instance_by_partition.get(x.partition_id)
                    or x.mig_profile != p.expected_mig_profile_by_partition.get(x.partition_id)
                    or x.memory_slice_ids
                    != p.expected_memory_slice_ids_by_partition.get(x.partition_id)
                ):
                    risks.add(AcceleratorRisk.MIG_INSTANCE_MISMATCH)
                if set(x.memory_slice_ids) & set(x.co_resident_memory_slice_ids):
                    risks.add(AcceleratorRisk.MIG_MEMORY_SLICE_OVERLAP)
                if x.mig_gpu_instance_id in set(x.co_resident_mig_gpu_instance_ids):
                    risks.add(AcceleratorRisk.MIG_INSTANCE_MISMATCH)
            if tuple(x.device_nodes) != p.allowed_device_nodes_by_partition.get(x.partition_id):
                risks.add(AcceleratorRisk.DEVICE_NODE_SCOPE_MISMATCH)
            if p.require_cgroup_device_policy and not x.cgroup_device_policy_enforced:
                risks.add(AcceleratorRisk.CGROUP_DEVICE_POLICY_MISSING)
            if p.require_iommu and not x.iommu_enabled:
                risks.add(AcceleratorRisk.IOMMU_DISABLED)
            if (
                x.iommu_group_id != p.expected_iommu_group_id_by_partition.get(x.partition_id)
                or x.iommu_group_members
                != p.expected_iommu_group_members_by_partition.get(x.partition_id)
            ):
                risks.add(AcceleratorRisk.IOMMU_GROUP_MISMATCH)
            if x.peer_access_enabled and not p.allow_peer_access:
                risks.add(AcceleratorRisk.DMA_PEER_ACCESS_UNAUTHORIZED)
            if x.gpudirect_rdma_enabled and not p.allow_gpudirect_rdma:
                risks.add(AcceleratorRisk.GPUDIRECT_RDMA_UNAUTHORIZED)
            if (
                x.reserved_memory_bytes > p.max_reserved_memory_bytes_by_partition.get(x.partition_id, -1)
                or x.allocated_memory_bytes > p.max_allocated_memory_bytes_by_partition.get(x.partition_id, -1)
            ):
                risks.add(AcceleratorRisk.MEMORY_BUDGET_EXCEEDED)
            if x.address_space_id != p.expected_address_space_id_by_partition.get(x.partition_id):
                risks.add(AcceleratorRisk.ADDRESS_SPACE_REUSE)
            if (
                x.memory_epoch < p.minimum_memory_epoch_by_partition.get(x.partition_id, 0)
                or x.memory_generation
                < p.minimum_memory_generation_by_partition.get(x.partition_id, 0)
            ):
                risks.add(AcceleratorRisk.MEMORY_EPOCH_MISMATCH)
            if p.require_profiling_disabled and x.profiling_access_enabled:
                risks.add(AcceleratorRisk.PROFILING_ACCESS_UNSAFE)
            if p.require_telemetry_admin_only and not x.telemetry_admin_only:
                risks.add(AcceleratorRisk.TELEMETRY_ACCESS_UNSAFE)
            if p.require_strict_side_channel_profile and any(
                (x.shared_l2, x.shared_memory_controller, x.shared_copy_engines, x.shared_scheduler)
            ):
                risks.add(AcceleratorRisk.SIDE_CHANNEL_PROFILE_UNSAFE)

        address_spaces = [x.address_space_id for x in m.partitions]
        if len(address_spaces) != len(set(address_spaces)):
            risks.add(AcceleratorRisk.ADDRESS_SPACE_REUSE)

        if tuple(x.lease_id for x in m.leases) != p.expected_lease_ids or set(leases) != set(
            p.expected_lease_ids
        ):
            risks.add(AcceleratorRisk.LEASE_COVERAGE_MISMATCH)
        previous = m.prior_lease_ledger_sha256
        for index, lease in enumerate(m.leases, 1):
            partition = partitions.get(lease.partition_id)
            if lease.lease_id in m.prior_lease_ids:
                risks.add(AcceleratorRisk.LEASE_REPLAY)
            if (
                (lease.request_id, lease.tenant_id, lease.session_id)
                != (m.request_id, m.tenant_id, m.session_id)
                or partition is None
            ):
                risks.add(AcceleratorRisk.LEASE_BINDING_MISMATCH)
            if not (lease.issued_at_epoch <= m.created_at_epoch <= lease.expires_at_epoch):
                risks.add(AcceleratorRisk.LEASE_EXPIRED)
            if partition and lease.generation < partition.memory_generation:
                risks.add(AcceleratorRisk.LEASE_GENERATION_ROLLBACK)
            expected_allocation = digest_json(
                {
                    "partition_id": lease.partition_id,
                    "tenant_id": lease.tenant_id,
                    "session_id": lease.session_id,
                    "generation": lease.generation,
                    "memory_epoch": partition.memory_epoch if partition else -1,
                    "address_space_id": partition.address_space_id if partition else "missing",
                }
            )
            if lease.allocation_sha256.casefold() != expected_allocation.casefold():
                risks.add(AcceleratorRisk.MEMORY_OWNER_MISMATCH)
            if lease.previous_lease_sha256.casefold() != previous.casefold():
                risks.add(AcceleratorRisk.LEASE_BINDING_MISMATCH)
            previous = accelerator_lease_digest(lease)

        ledger = prior_lease_ledger_digest(m.prior_lease_ids)
        if (
            ledger.casefold() != m.prior_lease_ledger_sha256.casefold()
            or ledger.casefold() != p.expected_prior_lease_ledger_sha256.casefold()
        ):
            risks.add(AcceleratorRisk.PRIOR_LEASE_LEDGER_MISMATCH)
        if m.network_operations:
            risks.add(AcceleratorRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(risks, key=lambda risk: risk.value))

    def evaluate(
        self,
        request: InferenceAcceleratorIsolationRequest,
        m: InferenceAcceleratorIsolationManifest,
        a: VerifiedInferenceAdapterRoutingAssessment,
    ) -> VerifiedInferenceAcceleratorIsolationAssessment:
        self._validate_manifest(m)
        actual = inference_accelerator_isolation_manifest_digest(m)
        if actual.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(
                AcceleratorRejectReason.MANIFEST_DIGEST_MISMATCH,
                "accelerator manifest differs from policy-pinned evidence",
            )
        if request.manifest_id != m.manifest_id or request.manifest_sha256.casefold() != actual.casefold():
            reject(AcceleratorRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if request.evaluated_at_epoch < m.created_at_epoch - self.policy.max_future_skew_seconds or request.evaluated_at_epoch > m.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(AcceleratorRejectReason.REQUEST_INVALID, "accelerator manifest freshness invalid")
        identity = (
            request.declared_request_id,
            request.declared_tenant_id,
            request.declared_session_id,
            request.declared_partition_ids,
            request.declared_lease_ids,
        )
        evidence = (
            m.request_id,
            m.tenant_id,
            m.session_id,
            tuple(x.partition_id for x in m.partitions),
            tuple(x.lease_id for x in m.leases),
        )
        if identity != evidence:
            reject(
                AcceleratorRejectReason.DECLARED_SUMMARY_MISMATCH,
                "caller accelerator identity summary disagrees with evidence",
            )
        risks = self.derive(m, a)
        decision = AcceleratorDecision.ALLOW if not risks else AcceleratorDecision.DENY
        safe = not risks
        declared = (
            request.declared_upstream_p10e_bound,
            request.declared_host_probe_bound,
            request.declared_device_assignment_safe,
            request.declared_dma_isolation_safe,
            request.declared_memory_isolation_safe,
            request.declared_side_channel_profile_safe,
            request.declared_lease_safe,
            request.declared_accelerator_safe,
        )
        if declared != (safe,) * 8:
            reject(
                AcceleratorRejectReason.DECLARED_SUMMARY_MISMATCH,
                "caller accelerator safety summary disagrees with derived evidence",
            )
        device_bad = {
            AcceleratorRisk.DEVICE_COVERAGE_MISMATCH,
            AcceleratorRisk.DEVICE_IDENTITY_MISMATCH,
            AcceleratorRisk.DEVICE_ASSIGNMENT_MISMATCH,
            AcceleratorRisk.UNSAFE_PARTITION_MODE,
            AcceleratorRisk.CROSS_TENANT_DEVICE_SHARE,
            AcceleratorRisk.MIG_INSTANCE_MISMATCH,
            AcceleratorRisk.MIG_MEMORY_SLICE_OVERLAP,
            AcceleratorRisk.DEVICE_NODE_SCOPE_MISMATCH,
        }
        dma_bad = {
            AcceleratorRisk.CGROUP_DEVICE_POLICY_MISSING,
            AcceleratorRisk.IOMMU_DISABLED,
            AcceleratorRisk.IOMMU_GROUP_MISMATCH,
            AcceleratorRisk.DMA_PEER_ACCESS_UNAUTHORIZED,
            AcceleratorRisk.GPUDIRECT_RDMA_UNAUTHORIZED,
        }
        memory_bad = {
            AcceleratorRisk.MEMORY_BUDGET_EXCEEDED,
            AcceleratorRisk.MEMORY_OWNER_MISMATCH,
            AcceleratorRisk.ADDRESS_SPACE_REUSE,
            AcceleratorRisk.MEMORY_EPOCH_MISMATCH,
        }
        side_bad = {
            AcceleratorRisk.PROFILING_ACCESS_UNSAFE,
            AcceleratorRisk.TELEMETRY_ACCESS_UNSAFE,
            AcceleratorRisk.SIDE_CHANNEL_PROFILE_UNSAFE,
        }
        lease_bad = {
            AcceleratorRisk.LEASE_COVERAGE_MISMATCH,
            AcceleratorRisk.LEASE_EXPIRED,
            AcceleratorRisk.LEASE_REPLAY,
            AcceleratorRisk.LEASE_GENERATION_ROLLBACK,
            AcceleratorRisk.LEASE_BINDING_MISMATCH,
            AcceleratorRisk.PRIOR_LEASE_LEDGER_MISMATCH,
        }
        evidence_sha = digest_json(
            {
                "manifest_id": m.manifest_id,
                "request_id": m.request_id,
                "tenant_id": m.tenant_id,
                "partitions": tuple(x.partition_id for x in m.partitions),
                "leases": tuple(x.lease_id for x in m.leases),
                "risks": risks,
                "decision": decision,
                "schema": P10F_ASSESSMENT_SCHEMA_VERSION,
                "mode": P10F_ASSESSMENT_MODE,
            }
        )
        return VerifiedInferenceAcceleratorIsolationAssessment(
            m.manifest_id,
            actual,
            m.request_id,
            m.tenant_id,
            m.session_id,
            decision,
            risks,
            m.p10e_assessment_sha256,
            m.target_model_id,
            m.target_model_revision,
            m.adapter_ids,
            m.adapter_generation,
            tuple(x.partition_id for x in m.partitions),
            tuple(x.lease_id for x in m.leases),
            AcceleratorRisk.UPSTREAM_P10E_INVALID not in risks
            and AcceleratorRisk.UPSTREAM_BINDING_MISMATCH not in risks,
            AcceleratorRisk.HOST_PROBE_BINDING_MISMATCH not in risks,
            not bool(set(risks) & device_bad),
            not bool(set(risks) & dma_bad),
            not bool(set(risks) & memory_bad),
            not bool(set(risks) & side_bad),
            not bool(set(risks) & lease_bad),
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            P10F_ASSESSMENT_SCHEMA_VERSION,
            P10F_ASSESSMENT_MODE,
            evidence_sha,
        )
