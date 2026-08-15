# P10-F professional lab — real GPU isolation

This lab is the hands-on mastery gate for P10-F. Run it only on a dedicated GPU lab machine or disposable GPU node where you are authorized to inspect device topology and launch test workloads. Do not reconfigure MIG geometry or reset production GPUs for this exercise.

## Goal

Demonstrate that you can inspect and reason about a real accelerator security boundary rather than only evaluate synthetic evidence. You should be able to explain the physical GPU, MIG/device assignment, `/dev` exposure, container/device controls, PCI/IOMMU grouping, peer/DMA surfaces, memory budget, profiling surface, and the residual side-channel risk.

## 1. Collect host evidence

Run:

```bash
python scripts/collect_p10f_gpu_evidence.py \
  --probe-id p10f-real-gpu-lab-001 \
  --require-gpu \
  --output p10f-real-gpu-probe.json
```

The collector is read-only. It records NVIDIA PCI devices, IOMMU-group membership, NVIDIA device nodes and permissions, selected runtime visibility variables, `nvidia-smi -L`, a basic GPU query, and MIG instance listing when available. It also emits explicit false claim flags for cryptographic attestation, physical VRAM zeroization, DMA-attack resistance, and side-channel resistance.

## 2. Explain the isolation mechanism

For every tenant-visible accelerator, record whether it is an exclusive GPU or MIG partition. If two tenants share one physical GPU, require distinct MIG GPU Instance identities for this lab. Do not treat MPS or scheduler time-slicing as an equivalent hard multi-tenant boundary.

For a MIG assignment, record the GPU UUID, PCI BDF, GPU Instance, Compute Instance, profile, visible device nodes/capabilities, and any known co-resident instances. Confirm the tenant does not receive a broad physical-GPU device node that bypasses the intended partition exposure.

## 3. Verify device access boundaries

From the tenant workload/container, enumerate visible NVIDIA devices and compare them with the host evidence. A negative test should attempt to open or enumerate a GPU device that is not assigned to that tenant and confirm that access is denied. Record the exact command, exit status, and relevant runtime/cgroup configuration.

If Kubernetes is used, also record the requested GPU resource, the resulting device assignment, RuntimeClass/CDI or device-plugin path in use, and the container-visible device set. Do not infer isolation merely from a pod resource request; inspect the resulting device exposure.

## 4. Verify PCI/IOMMU and DMA assumptions

For each assigned physical GPU, inspect its IOMMU group and group members. Explain whether the group matches the expected pass-through/isolation boundary. Record whether peer GPU access, GPUDirect RDMA, or other DMA-capable peers are enabled. This lab's default posture is deny unless the path is required and separately justified.

## 5. Verify profiling and telemetry exposure

From the tenant context, determine whether privileged GPU profiling/performance-counter functionality or broad management telemetry is exposed. The strict P10-F profile expects tenant profiling to be disabled and management telemetry to be admin-only. Record the exact mechanism enforcing that boundary.

## 6. Controlled memory-pressure exercise

Only on a disposable lab partition, run an authorized workload that approaches—but does not intentionally exceed—the assigned memory budget. Observe allocation failure and neighboring tenant/partition behavior. Do not use this step on shared production infrastructure. Record memory limits, observed allocation usage, failure mode, and whether another tenant's visible allocation or service was affected.

## 7. Produce the mastery evidence packet

Keep the following together:

- `p10f-real-gpu-probe.json`;
- the tenant/container launch specification;
- device-visibility and denied-access outputs;
- IOMMU-group evidence;
- peer-access / GPUDirect/RDMA status;
- profiling/telemetry evidence;
- controlled memory-pressure notes;
- a short residual-risk analysis covering physical zeroization, DMA, timing/cache side channels, host-root compromise, driver vulnerabilities, and distributed scheduling.

## Pass condition

P10-F professional mastery is complete only after a real GPU run demonstrates the expected device boundary and you can explain why the evidence supports—or fails to support—each isolation claim. Synthetic evaluator success alone does not satisfy this gate.
