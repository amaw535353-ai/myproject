# Phase 10 progress — secure inference runtime and multi-tenant serving

Phase 10 secures shared inference runtime state: request routing, scheduling, KV/prefix caches, speculative serving, adapters, accelerators, streaming outputs, and multi-replica serving. From P10-F onward the project explicitly distinguishes **deterministic portfolio evidence** from **professional-mastery evidence gathered on real infrastructure**.

## Milestone status

- **P10-A:** inference tenant/request/session isolation and immutable runtime-state route binding — deterministic scope complete.
- **P10-B:** dynamic batching, scheduler fairness, admission control, and resource-exhaustion isolation — deterministic scope complete.
- **P10-C:** KV/prefix-cache lifecycle, eviction/reuse, modeled zeroization, and rollback-safe ownership — deterministic scope complete.
- **P10-D:** speculative decoding, draft-model trust, disaggregated prefill/decode, and cross-service state binding — deterministic scope complete.
- **P10-E:** adapter/LoRA hot-swap, per-tenant composition, authorization, and runtime model-routing integrity — deterministic scope complete.
- **P10-F:** accelerator/GPU device, memory, DMA, and modeled side-channel-profile isolation — implementation/evaluator complete; **real GPU professional-mastery lab pending**.

## Reproducible focused evidence

| Milestone | Tests | Attacks | Vulnerable ASR | Hardened ASR | FPR | SafeTaskRate | Clean assessment SHA-256 |
|---|---:|---:|---:|---:|---:|---:|---|
| P10-A | 30 | 136 | 136/136 | 0/136 | 0/4 | 4/4 | `3fcd0475ddc05727dad597f375bd3929e2f96bd665aa0cf137d33ea9fc28904d` |
| P10-B | 31 | 135 | 135/135 | 0/135 | 0/4 | 4/4 | `a46197f548332077d3245fd10bc37d2a356b51e5f9e035add82a9751f68f0388` |
| P10-C | 30 | 117 | 117/117 | 0/117 | 0/4 | 4/4 | `27edbe07d57ea8074742416aa028860dec3ae1125899b57a608e1d00c633866f` |
| P10-D | 34 | 145 | 145/145 | 0/145 | 0/4 | 4/4 | `3d1d51ad6fddcd75c77ef31c39e9b86a93201c743a9221ab551c73ed96b7c3fa` |
| P10-E | 36 | 157 | 157/157 | 0/157 | 0/4 | 4/4 | `27dfed5cf9281c4105be59e3e38b00998d86314c46bf9bff0b438b9f25ebddc7` |
| P10-F | 55 | 160 | 160/160 | 0/160 | 0/4 | 4/4 | `a84cad654ea4ee8aadf8f8a0750c55fc0fa1a7826a188504ca99c254a2627053` |

P10-F accelerator manifest SHA-256: `bd141b7af9903eaecd169507c1ac4aeb9879e49bd654b040ddbaf0304d15a2dc`.

P10-F adversarial dataset SHA-256: `8d1bbedfb460d046a29ca251283dbd59b2a283e94bd9661228a113dd66106e2c`.

P10-F fixture/evaluator SHA-256: `bf12c0c7f889583b8e72d15e0a60ff316cff910e9e55363c59a96aae9f05c2ff`.

`scripts/verify_phase10.py --focused-p10f` is the focused deterministic verification path. The isolated harness uses API-compatible upstream imports; it does not claim the complete repository or P10-A through P10-E were rerun in that same environment.

## P10-F — accelerator/GPU isolation

`InferenceAcceleratorIsolationAnalyzer` consumes the exact P10-E assessment and preserves request/tenant/session, target-model, ordered adapter-stack, and adapter-generation identity. It binds a self-digested host probe plus policy-owned accelerator topology and evaluates exclusive-GPU/MIG assignment, cross-tenant sharing, MIG GPU Instance and memory-slice separation, exact device-node exposure, cgroup device-filter evidence, PCI/IOMMU grouping, peer-DMA and GPUDirect/RDMA policy, accelerator memory budgets, CUDA address-space identity, memory epoch/generation floors, profiling/telemetry exposure, strict side-channel-profile evidence, fresh accelerator leases, hash chaining, and replay protection.

The synthetic safe fixture deliberately includes both an exclusive GPU assignment and a cross-tenant physical GPU represented as distinct MIG GPU Instances with disjoint memory-slice evidence. Strict policy rejects MPS and time-slicing as hard cross-tenant isolation mechanisms.

A new non-destructive collector, `scripts/collect_p10f_gpu_evidence.py`, inventories NVIDIA PCI devices, IOMMU groups, NVIDIA `/dev` nodes, runtime visibility variables, `nvidia-smi` device output, and MIG listing when available. Its output is evidence collection only, not hardware attestation.

The collector was smoke-tested in the local CPU-only execution environment and correctly reported `hardware_present=false` and `nvidia_smi_available=false`; this validates the no-GPU failure path only. It is **not** live GPU validation.

## P10-F professional-mastery gate

P10-F is not professionally complete until `docs/labs/p10f-gpu-isolation-lab.md` is executed on an authorized dedicated GPU host or disposable GPU node. The evidence packet must include the live host probe, tenant/container device visibility, a denied unassigned-device access test, IOMMU grouping, peer/GD-RDMA state, profiling/telemetry exposure, a controlled memory-pressure observation, and a residual-risk analysis.

Until that run is reviewed, the clean P10-F assessment keeps these claims false: `live_gpu_hardware_validated`, production GPU runtime integration, production cgroup enforcement, production IOMMU enforcement, physical VRAM zeroization, DMA attack resistance, side-channel resistance, and hardware attestation.

## Hosted CI classification

Hosted CI is an external execution dependency. A GitHub Actions job that reaches a terminal `failure` state with `steps: null` / `steps: []` because runner provisioning is blocked is classified as `REMOTE_CI_BLOCKED`, not as a test failure and not as a hosted CI pass.

## Claim boundary

P10-A through P10-F deterministic evidence proves only the implemented evidence contracts and fail-closed logic. SHA-256 provides integrity binding, not authenticity. Modeled zeroization does not prove physical memory overwrite. Service, adapter, device, IOMMU, and lease digests do not prove production enforcement. P10-F's side-channel profile is a policy model; it does not establish empirical timing/cache side-channel resistance.

No runtime dependency is added. Package version is **0.96.0**.

## Remaining Phase 10 roadmap

- **P10-G:** streaming response, cancellation, backpressure, output-channel, and tool-call framing integrity.
- **P10-H:** replica autoscaling, failover, routing consistency, and rollback-safe serving lineage.
- **P10-I:** integrated multi-tenant inference compromise exercise and machine-readable Phase 10 exit gate.

The immediate professional-mastery action is the **real P10-F GPU isolation lab**. P10-G should follow after the hardware gate is completed or explicitly recorded as unavailable, rather than treating synthetic P10-F success as professional mastery.
