# P10-F threat model — accelerator/GPU isolation

P10-F moves the Phase 10 trust boundary from logical adapter routing into accelerator assignment, device exposure, DMA boundaries, memory ownership, and side-channel-relevant sharing. The analyzer consumes the exact P10-E assessment and fails closed unless the request/tenant/session, target model, final adapter stack, and adapter generation remain unchanged.

## Assets

- tenant prompts, KV/prefix state, activations, logits, outputs, and adapter-weight material resident in accelerator memory;
- GPU/MIG device assignment, CUDA address-space identity, memory epochs and allocation generations;
- PCI/IOMMU topology, device nodes, cgroup device filters, peer-access and GPUDirect/RDMA state;
- accelerator leases and replay history;
- operational isolation properties such as profiling access and whether L2, memory controllers, copy engines, or schedulers are modeled as shared.

## Adversary

The adversary can control caller declarations and may attempt to substitute accelerator inventory, move a request to another device or tenant, downgrade a MIG assignment to MPS/time-slicing, overlap MIG memory slices, broaden device-node visibility, disable cgroup/IOMMU controls, enable peer DMA or GPUDirect RDMA, exceed memory budgets, reuse an address space, roll back allocation generations, replay leases, enable profiling, or claim a stricter side-channel profile than the evidence supports.

## Security invariants

1. The exact P10-E assessment SHA-256, request/tenant/session, target model, ordered adapter IDs, and adapter generation are immutable inputs to P10-F.
2. Host-probe evidence is self-bound by a canonical payload digest and policy-pinned. A probe that reports no required GPU hardware or no required `nvidia-smi` capability fails closed.
3. Accelerator partition topology is policy-pinned. Strict multi-tenant policy permits only exclusive physical GPU assignment or MIG evidence; MPS and time-slicing are rejected for this threat model.
4. A cross-tenant MIG assignment requires a distinct GPU Instance identity and non-overlapping memory-slice evidence. Sharing the same MIG GPU Instance or memory slice fails closed.
5. Device-node exposure must equal the policy allowlist, cgroup device filtering must be evidenced, and the PCI/IOMMU group must match policy-owned topology.
6. Peer access and GPUDirect/RDMA are denied unless explicitly permitted by policy.
7. Accelerator memory use is tenant/session-bound to a unique address-space identity, minimum epoch/generation floors, and policy budgets.
8. Tenant profiling access is disabled and privileged telemetry remains admin-only in the strict profile.
9. The strict side-channel profile rejects evidence that marks L2, memory controllers, copy engines, or scheduling as shared for the assigned tenant partition.
10. Accelerator leases are fresh, monotonically generation-bound, chained from the prior-lease ledger, and non-replayable.

## NVIDIA-specific rationale used by the lab

NVIDIA's current MIG documentation describes GPU Instances as having dedicated memory-system resources and fault-isolation properties, while its concurrency comparison notes that MPS shares memory bandwidth, caches, capacity, and lacks error isolation between clients. The MIG deployment guidance also recommends `/dev`-based access control for MIG devices through cgroups on supported drivers. P10-F therefore treats strict cross-tenant MPS/time-slicing as unsafe and requires narrower device exposure plus IOMMU/cgroup evidence.

These vendor properties are deployment facts to verify on the actual target hardware and driver version; the deterministic analyzer does not convert documentation into proof that a specific host is configured correctly.

## Claim boundary

P10-F's deterministic fixture is not live GPU evidence. SHA-256 is an integrity binding, not authenticity or hardware attestation. The host collector is non-destructive inventory collection and is not a trusted attestation agent. A clean synthetic assessment deliberately leaves `live_gpu_hardware_validated`, production runtime/cgroup/IOMMU enforcement, physical VRAM zeroization, DMA attack resistance, side-channel resistance, and hardware attestation claims false.

The professional-mastery gate for P10-F remains open until the host collector and negative isolation exercises are run on a real dedicated GPU lab host and the resulting evidence is reviewed.
