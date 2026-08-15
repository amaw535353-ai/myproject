# Phase 10 progress — secure inference runtime and multi-tenant serving

Phase 10 moves beyond model provenance and training security into the runtime state of shared inference systems: request routing, dynamic batching, KV/prefix caches, adapters, speculative decoding, accelerators, streaming outputs, and multi-replica serving.

## Completed milestones

- **P10-A:** inference tenant/request/session isolation and immutable runtime-state route binding — complete for the current deterministic synthetic scope.
- **P10-B:** dynamic batching, scheduler fairness, admission control, and resource-exhaustion isolation — complete for the current deterministic synthetic scope.
- **P10-C:** KV/prefix-cache lifecycle, eviction/reuse, modeled zeroization, and rollback-safe ownership — complete for the current deterministic synthetic scope.
- **P10-D:** speculative decoding, draft-model trust, disaggregated prefill/decode, and cross-service state binding — complete for the current deterministic synthetic scope.

## P10-A — tenant and runtime-state isolation

`InferenceTenantIsolationAnalyzer` binds an opaque deployment-attestation identity/digest and the exact P9-H promotion assessment SHA-256 to an immutable deployment/endpoint/model/tokenizer route. It derives tenant/principal/session authorization, same-tenant batch partitioning, KV-cache owner/session/epoch namespaces, tenant-scoped prefix-cache reuse, exact adapter and speculative draft-model routing, tenant/session output routing, and request-replay state.

Focused P10-A evidence: 30 tests passed; 136 adversarial cases; vulnerable ASR 136/136; hardened ASR 0/136; hardened FPR 0/4; SafeTaskRate 4/4; manifest `80ac9247fa6253426957a7b4e0c5f717f94365743338898ed688ef0d860e66f3`; dataset `8c240c1480447b7725a2ec5a1c294011795621f23f8766da1766f75438a8e148`; fixture/evaluator `8d6c9b4096476d6aa43716c34eeb549fc1ba9a08a0bbeaae1272b1dfedf5bac7`; assessment `3fcd0475ddc05727dad597f375bd3929e2f96bd665aa0cf137d33ea9fc28904d`.

## P10-B — scheduler fairness, admission, and resource isolation

`InferenceSchedulerSecurityAnalyzer` consumes an exact P10-A assessment and binds it to concurrent scheduler evidence. It verifies scheduler/worker identity, tenant/session ownership, request uniqueness and replay state, policy-owned request/tenant/global resource limits, priority and starvation bounds, deterministic weighted-deficit accounting, deterministic fair tenant selection, and a capacity-bounded greedy batch plan.

Focused P10-B evidence: 31 tests passed; 135 adversarial cases; vulnerable ASR 135/135; hardened ASR 0/135; hardened FPR 0/4; SafeTaskRate 4/4; manifest `2ab1b0b48fbadb206db07dc763b992ea0ccc2eadc7c838b07c16c1655238c929`; dataset `7c496ff36a20e59d3116dfa4d14ac497ffcec3263874c6fe2d6ee02f6e54f02d`; fixture/evaluator `e9040f0ec24b3829ec84c09f3e4fb658f49de8b5f4f5eda0c05f4068edfe3926`; assessment `a46197f548332077d3245fd10bc37d2a356b51e5f9e035add82a9751f68f0388`.

## P10-C — cache lifecycle, reuse, zeroization, and rollback-safe ownership

`InferenceCacheLifecycleAnalyzer` consumes the exact P10-B assessment contract and binds cache entries to policy-owned tenant/session namespaces, cache epoch/generation, key and payload digests, reuse lineage, active-entry limits, retired-entry replay state, a zeroization-method digest, deterministic zeroization receipts, and rollback authorization handles. It fails closed on cross-tenant reuse, cross-session KV reuse, stale-generation resurrection, unzeroized eviction, forged zeroization evidence, retired-entry resurrection, cache-capacity abuse, stale active state, or an unauthorized/wrong-owner rollback target.

Focused P10-C evidence: 30 tests passed; 117 adversarial cases; vulnerable ASR 117/117; hardened ASR 0/117; hardened FPR 0/4; SafeTaskRate 4/4; manifest `7e0ab033e702a0846cdf5197a185a01f22a9637c586ce503c9d9c40b7c07659b`; dataset `430a52385b8ce90d75f97ca1cdae69f923ae976e42b0544bed6ce96813ddbb86`; fixture/evaluator `416777e9607c7322fdfb6f6c282c22f7638338c1bed5d0de4c4373ba7dd7f526`; assessment `27edbe07d57ea8074742416aa028860dec3ae1125899b57a608e1d00c633866f`.

## P10-D — speculative decoding and disaggregated serving

`InferenceSpeculativeServingAnalyzer` consumes the exact P10-C assessment and introduces separate policy-owned request/model/service evidence because P10-C does not carry final serving-model or RPC topology identities. It binds request/tenant/session and request-input evidence, target and draft model revisions/artifact digests, tokenizer and draft-trust profile digests, exact prefill/draft/decode service identities, a policy-pinned handoff-state digest, ordered prefill-to-draft/decode transfers with replay-chain evidence, target verification of every draft proposal, and final decode-state binding.

Focused deterministic evidence from the isolated API-compatible P10-C harness:

- tests: **34 passed**;
- adversarial cases: **145**;
- vulnerable ASR: **145/145**;
- hardened ASR: **0/145**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- serving manifest SHA-256: `76cc93eefe3fae01edbf9b4f5f3c83039d8c1ab6515e024ebdcf82ce556c24fc`;
- adversarial dataset SHA-256: `c65af4045490228319049d70f4c413b9914aab87143161c1a0d91c5496059e33`;
- fixture/evaluator SHA-256: `a2db3929835ca82c4d0f9a0bf2ad09390911f2d7074f1f34321ba1aaa249278e`;
- clean assessment SHA-256: `3d1d51ad6fddcd75c77ef31c39e9b86a93201c743a9221ab551c73ed96b7c3fa`.

The safe corpus includes a fully target-verified speculative round in which all draft proposals are rejected, demonstrating that draft trust does not imply draft acceptance. This is deterministic integrity evidence; it does not prove a real target model recomputed probabilities or that a production disaggregated serving transport executed. `scripts/verify_phase10.py --focused-p10d` is the explicit focused path.

Hosted CI remains an external execution dependency. A GitHub job with zero executed steps because runner provisioning is blocked must be classified as `REMOTE_CI_BLOCKED`, not as a security-test failure and not as a hosted CI pass.

### Claim boundary

P10-A through P10-D are deterministic synthetic evidence. SHA-256 is integrity binding, not authenticity. P10-C's zeroization receipt does not prove physical CPU/GPU/HBM memory was overwritten. P10-D's service-identity and target-verification digests do not prove cryptographic service attestation or real target-model execution. These milestones do not claim production inference-gateway/scheduler/cache-manager/speculative-decoder integration, RPC confidentiality, distributed linearizability, physical cache/GPU-memory isolation, kernel/cgroup quota enforcement, DMA isolation, side-channel resistance, autoscaling correctness, hardware attestation, semantic token equivalence, or semantic model safety.

No runtime dependency is added. Package version is **0.94.0**.

## Phase 10 roadmap

- **P10-E:** adapter/LoRA hot-swap, per-tenant composition, and runtime model-routing integrity.
- **P10-F:** accelerator/GPU memory, device, DMA, and modeled side-channel isolation evidence.
- **P10-G:** streaming response, cancellation, backpressure, output-channel, and tool-call framing integrity.
- **P10-H:** replica autoscaling, failover, routing consistency, and rollback-safe serving lineage.
- **P10-I:** integrated multi-tenant inference compromise exercise and machine-readable Phase 10 exit gate.

The next milestone is **P10-E**, moving from disaggregated speculative-serving state into adapter/LoRA hot-swap and per-tenant runtime composition integrity.
