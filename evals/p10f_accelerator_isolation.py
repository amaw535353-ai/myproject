from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from aegis.inference.accelerator_isolation_security import InferenceAcceleratorIsolationAnalyzer
from aegis.inference.accelerator_isolation_types import *
from aegis.inference.adapter_routing_types import AdapterDecision, AdapterRisk
from aegis.vulnerable.accelerator_isolation import VulnerableCallerDeclaredAcceleratorSafety
from evals.p10f_fixture import (
    NOW,
    build_fixture,
    rebind,
    safe_longer_lease_fixture,
    safe_lower_memory_fixture,
    safe_no_coresident_fixture,
    h,
)


def safe_cases():
    return (
        ("canonical", build_fixture()),
        ("lower-memory-use", safe_lower_memory_fixture()),
        ("no-mig-coresident", safe_no_coresident_fixture()),
        ("longer-valid-lease", safe_longer_lease_fixture()),
    )


def _m(f, **changes):
    return rebind(f, replace(f["manifest"], **changes))


def _probe(f, **changes):
    probe = replace(f["manifest"].host_probe, **changes)
    return _m(f, host_probe=probe)


def _partition(f, index: int, **changes):
    xs = list(f["manifest"].partitions)
    xs[index] = replace(xs[index], **changes)
    return _m(f, partitions=tuple(xs))


def _lease(f, index: int, **changes):
    xs = list(f["manifest"].leases)
    xs[index] = replace(xs[index], **changes)
    return _m(f, leases=tuple(xs))


def _p10e(f, **changes):
    out = dict(f)
    out["p10e"] = replace(f["p10e"], **changes)
    return out


def _request(f, **changes):
    out = dict(f)
    out["request"] = replace(f["request"], **changes)
    return out


def adversarial_cases():
    cases = []

    def add(name, fixture):
        cases.append((name, fixture))

    f = build_fixture()
    m = f["manifest"]
    add("manifest-schema", _m(f, schema_version="aegis-inference-accelerator-isolation-manifest-v0"))
    add("manifest-id", _m(f, manifest_id="p10f-accelerator-isolation-evil"))
    add("manifest-created-zero", _m(f, created_at_epoch=0))
    add("upstream-digest-substitution", _m(f, p10e_assessment_sha256=h("wrong-p10e")))
    add("request-route-id", _m(f, request_id="request-acme-evil"))
    add("request-route-tenant", _m(f, tenant_id="beta", session_id="tenant/beta/session/s-001"))
    add("request-route-session", _m(f, session_id="tenant/acme/session/s-evil"))
    add("target-model-id", _m(f, target_model_id="aegisdesk-helpdesk-security-evil"))
    add("target-model-revision", _m(f, target_model_revision="rev-evil"))
    add("adapter-order", _m(f, adapter_ids=tuple(reversed(m.adapter_ids))))
    add("adapter-generation", _m(f, adapter_generation=m.adapter_generation - 1))
    add("network-operation", _m(f, network_operations=1))

    probe_mutations = {
        "probe-schema": {"schema_version": "aegis-p10f-host-accelerator-probe-v0"},
        "probe-id": {"probe_id": "gpu-host-probe-evil"},
        "probe-old": {"collected_at_epoch": NOW - 1000},
        "probe-future": {"collected_at_epoch": NOW + 1000},
        "probe-hostname": {"hostname_sha256": h("evil-host")},
        "probe-kernel": {"kernel_release": "5.4.0-unknown"},
        "probe-nvidia-smi-missing": {"nvidia_smi_available": False},
        "probe-hardware-missing": {"hardware_present": False},
        "probe-device-inventory": {"device_inventory_sha256": h("evil-device-inventory")},
        "probe-device-node-inventory": {"device_node_inventory_sha256": h("evil-device-nodes")},
        "probe-iommu-inventory": {"iommu_inventory_sha256": h("evil-iommu")},
        "probe-runtime-visibility": {"runtime_visibility_sha256": h("evil-runtime")},
        "probe-raw-digest": {"raw_evidence_sha256": h("evil-raw")},
    }
    for name, changes in probe_mutations.items():
        add(name, _probe(f, **changes))

    for i, base in enumerate(m.partitions):
        prefix = f"partition-{i}"
        add(prefix + "-physical-gpu", _partition(f, i, physical_gpu_id=base.physical_gpu_id + "-evil"))
        add(prefix + "-uuid", _partition(f, i, gpu_uuid=base.gpu_uuid + "-evil"))
        add(prefix + "-pci", _partition(f, i, pci_bdf="0000:66:00.0" if i == 0 else "0000:b4:00.0"))
        add(prefix + "-driver", _partition(f, i, driver_version="999.0"))
        add(prefix + "-tenant", _partition(f, i, tenant_id="beta", session_id="tenant/beta/session/s-009"))
        add(prefix + "-session", _partition(f, i, session_id="tenant/acme/session/s-evil"))
        add(prefix + "-device-nodes", _partition(f, i, device_nodes=base.device_nodes + ("/dev/nvidia0",)))
        add(prefix + "-cgroup", _partition(f, i, cgroup_device_policy_enforced=False))
        add(prefix + "-iommu-disabled", _partition(f, i, iommu_enabled=False))
        add(prefix + "-iommu-group", _partition(f, i, iommu_group_id=base.iommu_group_id + "-evil"))
        add(prefix + "-iommu-members", _partition(f, i, iommu_group_members=base.iommu_group_members + (("0000:66:00.1" if i == 0 else "0000:b4:00.1"),)))
        add(prefix + "-peer-access", _partition(f, i, peer_access_enabled=True))
        add(prefix + "-gpudirect", _partition(f, i, gpudirect_rdma_enabled=True))
        add(prefix + "-profiling", _partition(f, i, profiling_access_enabled=True))
        add(prefix + "-telemetry", _partition(f, i, telemetry_admin_only=False))
        add(prefix + "-shared-l2", _partition(f, i, shared_l2=True))
        add(prefix + "-shared-memory-controller", _partition(f, i, shared_memory_controller=True))
        add(prefix + "-shared-copy-engines", _partition(f, i, shared_copy_engines=True))
        add(prefix + "-shared-scheduler", _partition(f, i, shared_scheduler=True))
        add(prefix + "-address-space", _partition(f, i, address_space_id=base.address_space_id + "-evil"))
        add(prefix + "-memory-epoch", _partition(f, i, memory_epoch=max(0, base.memory_epoch - 1)))
        add(prefix + "-memory-generation", _partition(f, i, memory_generation=max(0, base.memory_generation - 1)))
        add(prefix + "-reserved-budget", _partition(f, i, reserved_memory_bytes=base.reserved_memory_bytes + 1024**3))
        add(prefix + "-allocated-budget", _partition(f, i, allocated_memory_bytes=base.reserved_memory_bytes + 1))
        add(prefix + "-unsafe-mps", _partition(f, i, partition_mode=AcceleratorPartitionMode.MPS, mig_gpu_instance_id="", mig_compute_instance_id="", mig_profile="", memory_slice_ids=()))
        add(prefix + "-unsafe-timeslice", _partition(f, i, partition_mode=AcceleratorPartitionMode.TIME_SLICE, mig_gpu_instance_id="", mig_compute_instance_id="", mig_profile="", memory_slice_ids=()))
        add(prefix + "-cross-tenant-share-mps", _partition(f, i, partition_mode=AcceleratorPartitionMode.MPS, mig_gpu_instance_id="", mig_compute_instance_id="", mig_profile="", memory_slice_ids=(), co_resident_tenant_ids=("beta",), co_resident_partition_ids=("partition-beta-shared",), co_resident_mig_gpu_instance_ids=(), co_resident_memory_slice_ids=()))
        if base.partition_mode == AcceleratorPartitionMode.MIG:
            add(prefix + "-mig-gi", _partition(f, i, mig_gpu_instance_id="gi-evil"))
            add(prefix + "-mig-ci", _partition(f, i, mig_compute_instance_id="ci-evil"))
            add(prefix + "-mig-profile", _partition(f, i, mig_profile="1g.10gb"))
            add(prefix + "-mig-slices", _partition(f, i, memory_slice_ids=("mem-slice-0",)))
            add(prefix + "-mig-overlap", _partition(f, i, co_resident_memory_slice_ids=("mem-slice-1", "mem-slice-2")))
            add(prefix + "-mig-shared-gi", _partition(f, i, co_resident_mig_gpu_instance_ids=(base.mig_gpu_instance_id,)))
            add(prefix + "-mig-missing-coresident-partition", _partition(f, i, co_resident_partition_ids=()))
            add(prefix + "-mig-missing-coresident-gi", _partition(f, i, co_resident_mig_gpu_instance_ids=()))
        else:
            add(prefix + "-exclusive-with-mig-evidence", _partition(f, i, mig_gpu_instance_id="gi-9", mig_compute_instance_id="ci-0", mig_profile="1g.10gb", memory_slice_ids=("mem-slice-9",)))
            add(prefix + "-exclusive-cross-tenant", _partition(f, i, co_resident_tenant_ids=("beta",), co_resident_partition_ids=("partition-beta-shared",)))

    xs = list(m.partitions)
    xs[1] = replace(xs[1], address_space_id=xs[0].address_space_id)
    add("duplicate-address-space", _m(f, partitions=tuple(xs)))

    for i, base in enumerate(m.leases):
        prefix = f"lease-{i}"
        add(prefix + "-id", _lease(f, i, lease_id=base.lease_id + "-evil"))
        add(prefix + "-request", _lease(f, i, request_id="request-acme-evil"))
        add(prefix + "-tenant", _lease(f, i, tenant_id="beta", session_id="tenant/beta/session/s-009"))
        add(prefix + "-session", _lease(f, i, session_id="tenant/acme/session/s-evil"))
        add(prefix + "-partition", _lease(f, i, partition_id="partition-missing"))
        add(prefix + "-issued-future", _lease(f, i, issued_at_epoch=NOW + 1, expires_at_epoch=NOW + 120))
        add(prefix + "-expired", _lease(f, i, issued_at_epoch=NOW - 120, expires_at_epoch=NOW - 1))
        add(prefix + "-generation", _lease(f, i, generation=max(0, base.generation - 1)))
        add(prefix + "-allocation", _lease(f, i, allocation_sha256=h("evil-allocation")))
        add(prefix + "-previous", _lease(f, i, previous_lease_sha256=h("evil-previous")))

    add("prior-ledger", _m(f, prior_lease_ledger_sha256=h("evil-ledger")))
    add("prior-lease-replay", _m(f, prior_lease_ids=m.prior_lease_ids + (m.leases[0].lease_id,)))
    add("lease-order", _m(f, leases=tuple(reversed(m.leases))))
    add("partition-order", _m(f, partitions=tuple(reversed(m.partitions))))

    upstream = f["p10e"]
    add("upstream-deny", _p10e(f, decision=AdapterDecision.DENY))
    add("upstream-risk", _p10e(f, risks=(AdapterRisk.UPSTREAM_P10D_INVALID,)))
    positive_flags = (
        "upstream_p10d_bound",
        "base_route_verified",
        "adapter_artifacts_verified",
        "tenant_composition_verified",
        "authorization_verified",
        "hot_swap_verified",
        "route_snapshot_verified",
    )
    for field in positive_flags:
        add("upstream-flag-" + field, _p10e(f, **{field: False}))
    nonclaims = (
        "caller_declared_safety_trusted",
        "production_adapter_manager_integrated",
        "production_model_router_integrated",
        "cryptographic_adapter_signature_verified",
        "atomic_hot_swap_validated",
        "distributed_route_consistency_validated",
        "side_channel_resistance_validated",
    )
    for field in nonclaims:
        add("upstream-nonclaim-" + field, _p10e(f, **{field: True}))
    add("upstream-schema", _p10e(f, assessment_schema_version="aegis-inference-adapter-hot-swap-assessment-v0"))
    add("upstream-mode", _p10e(f, assessment_mode="caller-trusted"))
    add("upstream-evidence", _p10e(f, assessment_evidence_sha256=h("evil-p10e-assessment")))
    add("upstream-request", _p10e(f, request_id="request-acme-evil"))
    add("upstream-tenant", _p10e(f, tenant_id="beta"))
    add("upstream-session", _p10e(f, session_id="tenant/acme/session/s-evil"))
    add("upstream-target-model", _p10e(f, target_model_id="aegisdesk-helpdesk-security-evil"))
    add("upstream-target-revision", _p10e(f, target_model_revision="rev-evil"))
    add("upstream-adapters", _p10e(f, after_adapter_ids=tuple(reversed(upstream.after_adapter_ids))))
    add("upstream-adapter-generation", _p10e(f, after_generation=upstream.after_generation - 1))

    add("request-manifest-id", _request(f, manifest_id="p10f-accelerator-isolation-evil"))
    add("request-manifest-sha", _request(f, manifest_sha256=h("evil-manifest")))
    add("request-stale", _request(f, evaluated_at_epoch=NOW + 1000))
    add("request-too-early", _request(f, evaluated_at_epoch=NOW - 1000))
    add("request-declared-id", _request(f, declared_request_id="request-acme-evil"))
    add("request-declared-tenant", _request(f, declared_tenant_id="beta"))
    add("request-declared-session", _request(f, declared_session_id="tenant/acme/session/s-evil"))
    add("request-declared-partitions", _request(f, declared_partition_ids=tuple(reversed(f["request"].declared_partition_ids))))
    add("request-declared-leases", _request(f, declared_lease_ids=tuple(reversed(f["request"].declared_lease_ids))))
    for field in (
        "declared_upstream_p10e_bound",
        "declared_host_probe_bound",
        "declared_device_assignment_safe",
        "declared_dma_isolation_safe",
        "declared_memory_isolation_safe",
        "declared_side_channel_profile_safe",
        "declared_lease_safe",
    ):
        add("request-summary-" + field, _request(f, **{field: False}))

    add("policy-version", {**f, "policy": replace(f["policy"], policy_version="inference-accelerator-isolation-v0")})
    add("policy-partition-map-coverage", {**f, "policy": replace(f["policy"], expected_gpu_uuid_by_partition={m.partitions[0].partition_id: m.partitions[0].gpu_uuid})})
    add("policy-unsafe-mode", {**f, "policy": replace(f["policy"], allowed_partition_modes=(AcceleratorPartitionMode.MIG, AcceleratorPartitionMode.MPS))})
    add("policy-zero-memory-budget", {**f, "policy": replace(f["policy"], max_reserved_memory_bytes_by_partition={**f["policy"].max_reserved_memory_bytes_by_partition, m.partitions[0].partition_id: 0})})

    return tuple(cases)


def _hardened_accepts(fixture) -> bool:
    try:
        result = InferenceAcceleratorIsolationAnalyzer(fixture["policy"]).evaluate(
            fixture["request"], fixture["manifest"], fixture["p10e"]
        )
        return result.decision == AcceleratorDecision.ALLOW
    except InferenceAcceleratorIsolationRejected:
        return False


def _file_hash(paths: tuple[Path, ...]) -> str:
    hsh = hashlib.sha256()
    for path in paths:
        hsh.update(path.read_bytes())
    return hsh.hexdigest()


def evaluate() -> dict[str, object]:
    vulnerable = VulnerableCallerDeclaredAcceleratorSafety()
    attacks = adversarial_cases()
    safe = safe_cases()
    vulnerable_success = sum(vulnerable.accepts(f["request"]) for _, f in attacks)
    hardened_success = sum(_hardened_accepts(f) for _, f in attacks)
    false_positives = sum(not _hardened_accepts(f) for _, f in safe)
    safe_task_rate = sum(_hardened_accepts(f) for _, f in safe)
    clean = build_fixture()
    clean_assessment = InferenceAcceleratorIsolationAnalyzer(clean["policy"]).evaluate(
        clean["request"], clean["manifest"], clean["p10e"]
    )
    root = Path(__file__).resolve().parents[1]
    dataset_sha = hashlib.sha256(
        json.dumps([name for name, _ in attacks], separators=(",", ":")).encode()
    ).hexdigest()
    fixture_eval_sha = _file_hash(
        (root / "evals" / "p10f_fixture.py", root / "evals" / "p10f_accelerator_isolation.py")
    )
    result = {
        "adversarial_cases": len(attacks),
        "vulnerable_attack_successes": vulnerable_success,
        "hardened_attack_successes": hardened_success,
        "hardened_false_positives": false_positives,
        "safe_task_successes": safe_task_rate,
        "safe_task_total": len(safe),
        "accelerator_manifest_sha256": inference_accelerator_isolation_manifest_digest(clean["manifest"]),
        "adversarial_dataset_sha256": dataset_sha,
        "fixture_evaluator_sha256": fixture_eval_sha,
        "clean_assessment_sha256": clean_assessment.assessment_evidence_sha256,
        "decision": clean_assessment.decision.value,
        "live_gpu_hardware_validated": clean_assessment.live_gpu_hardware_validated,
    }
    if vulnerable_success != len(attacks) or hardened_success or false_positives or safe_task_rate != len(safe):
        raise SystemExit(json.dumps(result, sort_keys=True))
    return result


def main() -> int:
    print(json.dumps(evaluate(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
