from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.inference.adapter_routing_types import *
from aegis.inference.accelerator_isolation_types import *

NOW = 1_800_030_900
MANIFEST_ID = "p10f-accelerator-isolation-001"
P10E_CLEAN_ASSESSMENT_SHA256 = "27dfed5cf9281c4105be59e3e38b00998d86314c46bf9bff0b438b9f25ebddc7"
P10E_MANIFEST_SHA256 = "3d56d2692349e1bdda7d26dd9adc6a261647d4d3c3f00fb40f2ef20393e53802"
REQUEST_ID = "request-acme-0001"
TENANT_ID = "acme"
SESSION_ID = "tenant/acme/session/s-001"
TARGET_MODEL_ID = "aegisdesk-helpdesk-security"
TARGET_MODEL_REVISION = "rev-2026-08-p9h"
ADAPTER_IDS = ("adapter-security-policy", "adapter-acme-helpdesk")
ADAPTER_GENERATION = 12


def h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def p10e_assessment() -> VerifiedInferenceAdapterRoutingAssessment:
    return VerifiedInferenceAdapterRoutingAssessment(
        "p10e-adapter-routing-001",
        P10E_MANIFEST_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        "principal-acme-agent",
        AdapterDecision.ALLOW,
        (),
        h("p10d-clean"),
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ("adapter-security-policy",),
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        ("adapter-swap-acme-0001",),
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        P10E_ASSESSMENT_SCHEMA_VERSION,
        P10E_ASSESSMENT_MODE,
        P10E_CLEAN_ASSESSMENT_SHA256,
    )


def _probe() -> AcceleratorHostProbeEvidence:
    probe = AcceleratorHostProbeEvidence(
        P10F_HOST_PROBE_SCHEMA_VERSION,
        "gpu-host-probe-001",
        NOW - 5,
        h("host:gpu-node-01"),
        "6.8.0-aegis",
        True,
        True,
        h("device-inventory:gpu-node-01"),
        h("device-nodes:gpu-node-01"),
        h("iommu-inventory:gpu-node-01"),
        h("runtime-visibility:gpu-node-01"),
        "0" * 64,
    )
    return replace(probe, raw_evidence_sha256=host_probe_payload_digest(probe))


def _partitions() -> tuple[AcceleratorPartitionEvidence, ...]:
    mig = AcceleratorPartitionEvidence(
        "partition-acme-mig-0",
        "physical-gpu-0",
        "gpu-a100-0001",
        "0000:65:00.0",
        "570.133.20",
        AcceleratorPartitionMode.MIG,
        TENANT_ID,
        SESSION_ID,
        "gi-3",
        "ci-0",
        "2g.20gb",
        ("mem-slice-0", "mem-slice-1"),
        ("beta",),
        ("partition-beta-mig-0",),
        ("gi-4",),
        ("mem-slice-2", "mem-slice-3"),
        "iommu-group-42",
        ("0000:65:00.0", "0000:65:00.1"),
        ("/dev/nvidia-caps/nvidia-cap12", "/dev/nvidia-caps/nvidia-cap13"),
        True,
        True,
        False,
        False,
        False,
        True,
        False,
        False,
        False,
        False,
        "cuda-as-acme-mig-0",
        7,
        19,
        20 * 1024**3,
        12 * 1024**3,
    )
    exclusive = AcceleratorPartitionEvidence(
        "partition-acme-exclusive-1",
        "physical-gpu-1",
        "gpu-h100-0002",
        "0000:b3:00.0",
        "570.133.20",
        AcceleratorPartitionMode.EXCLUSIVE_GPU,
        TENANT_ID,
        SESSION_ID,
        "",
        "",
        "",
        (),
        (),
        (),
        (),
        (),
        "iommu-group-57",
        ("0000:b3:00.0",),
        ("/dev/nvidia1", "/dev/nvidiactl", "/dev/nvidia-uvm"),
        True,
        True,
        False,
        False,
        False,
        True,
        False,
        False,
        False,
        False,
        "cuda-as-acme-exclusive-1",
        4,
        8,
        40 * 1024**3,
        24 * 1024**3,
    )
    return (mig, exclusive)


def _lease(
    lease_id: str,
    partition: AcceleratorPartitionEvidence,
    generation: int,
    previous: str,
) -> AcceleratorLeaseEvidence:
    allocation = digest_json(
        {
            "partition_id": partition.partition_id,
            "tenant_id": TENANT_ID,
            "session_id": SESSION_ID,
            "generation": generation,
            "memory_epoch": partition.memory_epoch,
            "address_space_id": partition.address_space_id,
        }
    )
    return AcceleratorLeaseEvidence(
        lease_id,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        partition.partition_id,
        NOW - 20,
        NOW + 120,
        generation,
        allocation,
        previous,
    )


def _manifest() -> InferenceAcceleratorIsolationManifest:
    partitions = _partitions()
    prior = ("gpu-lease-prior-0001", "gpu-lease-prior-0002")
    ledger = prior_lease_ledger_digest(prior)
    first = _lease("gpu-lease-acme-mig-001", partitions[0], 19, ledger)
    second = _lease(
        "gpu-lease-acme-exclusive-002",
        partitions[1],
        8,
        accelerator_lease_digest(first),
    )
    return InferenceAcceleratorIsolationManifest(
        P10F_SCHEMA_VERSION,
        MANIFEST_ID,
        NOW,
        P10E_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        _probe(),
        partitions,
        (first, second),
        prior,
        ledger,
        0,
    )


def request_for(m: InferenceAcceleratorIsolationManifest) -> InferenceAcceleratorIsolationRequest:
    return InferenceAcceleratorIsolationRequest(
        m.manifest_id,
        inference_accelerator_isolation_manifest_digest(m),
        m.created_at_epoch + 10,
        m.request_id,
        m.tenant_id,
        m.session_id,
        tuple(x.partition_id for x in m.partitions),
        tuple(x.lease_id for x in m.leases),
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
    )


def policy_for(m: InferenceAcceleratorIsolationManifest) -> InferenceAcceleratorIsolationPolicy:
    partitions = {x.partition_id: x for x in m.partitions}
    return InferenceAcceleratorIsolationPolicy(
        P10F_POLICY_VERSION,
        m.manifest_id,
        inference_accelerator_isolation_manifest_digest(m),
        P10E_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        P10F_HOST_PROBE_SCHEMA_VERSION,
        m.host_probe.probe_id,
        m.host_probe.raw_evidence_sha256,
        True,
        True,
        tuple(partitions),
        {k: v.physical_gpu_id for k, v in partitions.items()},
        {k: v.gpu_uuid for k, v in partitions.items()},
        {k: v.pci_bdf for k, v in partitions.items()},
        {k: v.partition_mode for k, v in partitions.items()},
        {k: accelerator_partition_topology_digest(v) for k, v in partitions.items()},
        {k: v.mig_gpu_instance_id for k, v in partitions.items()},
        {k: v.mig_compute_instance_id for k, v in partitions.items()},
        {k: v.mig_profile for k, v in partitions.items()},
        {k: v.memory_slice_ids for k, v in partitions.items()},
        {k: v.iommu_group_id for k, v in partitions.items()},
        {k: v.iommu_group_members for k, v in partitions.items()},
        {k: v.device_nodes for k, v in partitions.items()},
        {k: v.address_space_id for k, v in partitions.items()},
        {k: v.memory_epoch for k, v in partitions.items()},
        {k: v.memory_generation for k, v in partitions.items()},
        {k: v.reserved_memory_bytes for k, v in partitions.items()},
        {k: v.reserved_memory_bytes for k, v in partitions.items()},
        (AcceleratorPartitionMode.EXCLUSIVE_GPU, AcceleratorPartitionMode.MIG),
        False,
        False,
        True,
        True,
        True,
        True,
        True,
        tuple(x.lease_id for x in m.leases),
        m.prior_lease_ledger_sha256,
        300,
        5,
    )


def build_fixture():
    m = _manifest()
    return {
        "manifest": m,
        "policy": policy_for(m),
        "request": request_for(m),
        "p10e": p10e_assessment(),
    }


def rebind(f, m, *, refresh_manifest_pin: bool = True, refresh_security_pins: bool = False):
    p = f["policy"]
    if refresh_manifest_pin:
        p = replace(p, expected_manifest_sha256=inference_accelerator_isolation_manifest_digest(m))
    if refresh_security_pins:
        p = replace(
            p,
            expected_host_probe_raw_evidence_sha256=m.host_probe.raw_evidence_sha256,
            expected_partition_topology_sha256_by_partition={
                x.partition_id: accelerator_partition_topology_digest(x) for x in m.partitions
            },
        )
    return {"manifest": m, "policy": p, "request": request_for(m), "p10e": f["p10e"]}


def safe_lower_memory_fixture():
    f = build_fixture()
    xs = list(f["manifest"].partitions)
    xs[0] = replace(xs[0], allocated_memory_bytes=8 * 1024**3)
    xs[1] = replace(xs[1], allocated_memory_bytes=16 * 1024**3)
    return rebind(f, replace(f["manifest"], partitions=tuple(xs)), refresh_security_pins=True)


def safe_no_coresident_fixture():
    f = build_fixture()
    xs = list(f["manifest"].partitions)
    xs[0] = replace(
        xs[0],
        co_resident_tenant_ids=(),
        co_resident_partition_ids=(),
        co_resident_mig_gpu_instance_ids=(),
        co_resident_memory_slice_ids=(),
    )
    return rebind(f, replace(f["manifest"], partitions=tuple(xs)), refresh_security_pins=True)


def safe_longer_lease_fixture():
    f = build_fixture()
    leases = list(f["manifest"].leases)
    leases[0] = replace(leases[0], expires_at_epoch=NOW + 600)
    leases[1] = replace(
        leases[1],
        previous_lease_sha256=accelerator_lease_digest(leases[0]),
        expires_at_epoch=NOW + 600,
    )
    return rebind(f, replace(f["manifest"], leases=tuple(leases)), refresh_security_pins=True)
