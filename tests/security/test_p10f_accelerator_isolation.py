from __future__ import annotations

from dataclasses import replace
import json
import subprocess
import sys

import pytest

from aegis.inference.accelerator_isolation_security import InferenceAcceleratorIsolationAnalyzer
from aegis.inference.accelerator_isolation_types import *
from evals.p10f_accelerator_isolation import adversarial_cases, safe_cases
from evals.p10f_fixture import build_fixture


def _evaluate(f):
    return InferenceAcceleratorIsolationAnalyzer(f["policy"]).evaluate(
        f["request"], f["manifest"], f["p10e"]
    )


def test_clean_fixture_allows():
    a = _evaluate(build_fixture())
    assert a.decision == AcceleratorDecision.ALLOW
    assert a.risks == ()


def test_clean_fixture_binds_upstream_and_route():
    a = _evaluate(build_fixture())
    assert a.upstream_p10e_bound
    assert a.host_probe_bound
    assert a.device_assignment_verified


def test_clean_fixture_verifies_dma_memory_side_channel_and_lease_model():
    a = _evaluate(build_fixture())
    assert a.dma_isolation_verified
    assert a.memory_isolation_verified
    assert a.side_channel_profile_verified
    assert a.lease_safety_verified


def test_clean_fixture_does_not_claim_live_hardware_validation():
    a = _evaluate(build_fixture())
    assert not a.live_gpu_hardware_validated
    assert not a.production_gpu_runtime_integrated
    assert not a.production_cgroup_enforcement_verified
    assert not a.production_iommu_enforcement_verified
    assert not a.physical_vram_zeroization_verified
    assert not a.dma_attack_resistance_validated
    assert not a.side_channel_resistance_validated
    assert not a.hardware_attestation_verified


def test_caller_safety_is_never_trusted():
    assert not _evaluate(build_fixture()).caller_declared_safety_trusted


@pytest.mark.parametrize("name,fixture", safe_cases())
def test_safe_corpus(name, fixture):
    assert _evaluate(fixture).decision == AcceleratorDecision.ALLOW, name


def test_entire_adversarial_corpus_fails_closed():
    unexpected = []
    for name, fixture in adversarial_cases():
        try:
            if _evaluate(fixture).decision == AcceleratorDecision.ALLOW:
                unexpected.append(name)
        except InferenceAcceleratorIsolationRejected:
            pass
    assert unexpected == []


REPRESENTATIVE_ATTACKS = tuple(adversarial_cases()[i] for i in (
    0, 3, 7, 12, 14, 17, 20, 24, 27, 31,
    36, 40, 44, 49, 54, 58, 63, 68, 72, 77,
    82, 87, 92, 97, 102, 107, 112, 117, 122, 127,
    132, 137, 142, 147, 152, 156,
))


@pytest.mark.parametrize("name,fixture", REPRESENTATIVE_ATTACKS)
def test_representative_attack_fixtures_do_not_allow(name, fixture):
    try:
        result = _evaluate(fixture)
    except InferenceAcceleratorIsolationRejected:
        return
    assert result.decision == AcceleratorDecision.DENY, name


def test_mps_is_not_an_allowed_strict_tenant_partition_mode():
    f = build_fixture()
    x = f["manifest"].partitions[0]
    m = replace(
        f["manifest"],
        partitions=(
            replace(
                x,
                partition_mode=AcceleratorPartitionMode.MPS,
                mig_gpu_instance_id="",
                mig_compute_instance_id="",
                mig_profile="",
                memory_slice_ids=(),
            ),
            f["manifest"].partitions[1],
        ),
    )
    f = {**f, "manifest": m, "request": replace(f["request"], manifest_sha256=inference_accelerator_isolation_manifest_digest(m))}
    f = {**f, "policy": replace(f["policy"], expected_manifest_sha256=inference_accelerator_isolation_manifest_digest(m))}
    risks = InferenceAcceleratorIsolationAnalyzer(f["policy"]).derive(m, f["p10e"])
    assert AcceleratorRisk.UNSAFE_PARTITION_MODE in risks


def test_mig_memory_slice_overlap_is_denied():
    f = build_fixture()
    x = f["manifest"].partitions[0]
    m = replace(f["manifest"], partitions=(replace(x, co_resident_memory_slice_ids=("mem-slice-1",)), f["manifest"].partitions[1]))
    f = {**f, "manifest": m, "request": replace(f["request"], manifest_sha256=inference_accelerator_isolation_manifest_digest(m)), "policy": replace(f["policy"], expected_manifest_sha256=inference_accelerator_isolation_manifest_digest(m))}
    risks = InferenceAcceleratorIsolationAnalyzer(f["policy"]).derive(m, f["p10e"])
    assert AcceleratorRisk.MIG_MEMORY_SLICE_OVERLAP in risks


def test_peer_access_is_denied_by_default():
    f = build_fixture()
    x = f["manifest"].partitions[0]
    m = replace(f["manifest"], partitions=(replace(x, peer_access_enabled=True), f["manifest"].partitions[1]))
    f = {**f, "manifest": m, "request": replace(f["request"], manifest_sha256=inference_accelerator_isolation_manifest_digest(m)), "policy": replace(f["policy"], expected_manifest_sha256=inference_accelerator_isolation_manifest_digest(m))}
    risks = InferenceAcceleratorIsolationAnalyzer(f["policy"]).derive(m, f["p10e"])
    assert AcceleratorRisk.DMA_PEER_ACCESS_UNAUTHORIZED in risks


def test_gpudirect_rdma_is_denied_by_default():
    f = build_fixture()
    x = f["manifest"].partitions[0]
    m = replace(f["manifest"], partitions=(replace(x, gpudirect_rdma_enabled=True), f["manifest"].partitions[1]))
    f = {**f, "manifest": m, "request": replace(f["request"], manifest_sha256=inference_accelerator_isolation_manifest_digest(m)), "policy": replace(f["policy"], expected_manifest_sha256=inference_accelerator_isolation_manifest_digest(m))}
    risks = InferenceAcceleratorIsolationAnalyzer(f["policy"]).derive(m, f["p10e"])
    assert AcceleratorRisk.GPUDIRECT_RDMA_UNAUTHORIZED in risks


def test_profiling_access_is_denied_for_tenant_partition():
    f = build_fixture()
    x = f["manifest"].partitions[0]
    m = replace(f["manifest"], partitions=(replace(x, profiling_access_enabled=True), f["manifest"].partitions[1]))
    f = {**f, "manifest": m, "request": replace(f["request"], manifest_sha256=inference_accelerator_isolation_manifest_digest(m)), "policy": replace(f["policy"], expected_manifest_sha256=inference_accelerator_isolation_manifest_digest(m))}
    risks = InferenceAcceleratorIsolationAnalyzer(f["policy"]).derive(m, f["p10e"])
    assert AcceleratorRisk.PROFILING_ACCESS_UNSAFE in risks


def test_host_probe_payload_is_self_bound():
    f = build_fixture()
    assert f["manifest"].host_probe.raw_evidence_sha256 == host_probe_payload_digest(f["manifest"].host_probe)


def test_partition_topology_is_policy_pinned():
    f = build_fixture()
    for x in f["manifest"].partitions:
        assert f["policy"].expected_partition_topology_sha256_by_partition[x.partition_id] == accelerator_partition_topology_digest(x)


def test_live_collector_is_non_destructive_and_emits_schema():
    proc = subprocess.run(
        [sys.executable, "scripts/collect_p10f_gpu_evidence.py", "--probe-id", "pytest-gpu-probe"],
        text=True,
        capture_output=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    assert data["schema_version"] == P10F_HOST_PROBE_SCHEMA_VERSION
    assert data["probe_id"] == "pytest-gpu-probe"
    assert isinstance(data["hardware_present"], bool)
    assert isinstance(data["nvidia_smi_available"], bool)
    assert data["claim_boundary"]["cryptographic_attestation"] is False
    assert data["claim_boundary"]["side_channel_resistance_validated"] is False


def test_live_collector_payload_digest_matches_core_contract():
    proc = subprocess.run(
        [sys.executable, "scripts/collect_p10f_gpu_evidence.py", "--probe-id", "pytest-gpu-probe-digest"],
        text=True,
        capture_output=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    payload = {
        key: data[key]
        for key in (
            "schema_version",
            "probe_id",
            "collected_at_epoch",
            "hostname_sha256",
            "kernel_release",
            "nvidia_smi_available",
            "hardware_present",
            "device_inventory_sha256",
            "device_node_inventory_sha256",
            "iommu_inventory_sha256",
            "runtime_visibility_sha256",
        )
    }
    assert data["raw_evidence_sha256"] == digest_json(payload)
