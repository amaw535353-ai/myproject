# P10-C threat model — KV/prefix-cache lifecycle and rollback-safe ownership

## Security objective

P10-C adds a deterministic evidence boundary for inference-cache lifecycle state after P10-B scheduler admission. The objective is to prevent cache ownership, reuse, retirement, zeroization, or rollback metadata from being substituted so that one tenant/session can consume another tenant/session's runtime state or resurrect retired cache generations.

The hardened `InferenceCacheLifecycleAnalyzer` requires an exact P10-B assessment contract and evidence digest. It binds cache entries to tenant/session namespaces, a cache epoch and generation, exact policy-owned key/payload digests, active-entry capacity limits, deterministic prefix/KV reuse lineage, retired-entry ledgers, a policy-pinned zeroization method and deterministic zeroization receipt, and explicitly authorized rollback targets.

## Modeled assets and trust boundaries

The modeled assets are KV-cache and prefix-cache entry identities, owner tenant/session, cache namespace, epoch/generation, key and payload digests, lifecycle state, parent/reuse lineage, eviction/zeroization timestamps, zeroization receipts, rollback authorization handles, and the retired-entry ledger. The P10-B scheduler assessment is an upstream evidence dependency and is not re-derived here.

Caller-declared cache safety is not trusted. Policy-owned identities, digests, generation floors, tenant limits, rollback authorization handles, and the prior retired-entry ledger determine admissibility.

## Fail-closed invariants

The analyzer denies or rejects evidence when the P10-B contract is invalid or substituted; cache owner/session/namespace/epoch does not match; policy-pinned entry key/payload evidence changes; an active generation drops below its policy floor; a retired entry is resurrected; reuse crosses tenants or KV sessions; reuse lineage/generation/key identity is inconsistent; an evicted entry lacks modeled zeroization; a zeroization receipt does not match the policy-pinned method and retired payload digest; active-entry capacity or freshness bounds are exceeded; rollback is unauthorized or targets the wrong owner/state/generation; the retired ledger is inconsistent; a caller summary disagrees with derived evidence; or modeled network operations are unexpectedly nonzero.

## Adversary model

The adversary can alter caller summaries, cache manifests, cache ownership and namespaces, generations, entry digests, reuse evidence, eviction/zeroization evidence, rollback evidence, or upstream assessment fields. The adversary can attempt cross-tenant prefix reuse, cross-session KV reuse, stale-generation resurrection, missing zeroization, forged receipts, retired-entry replay, cache-capacity abuse, stale active state, or policy-map substitution.

## Focused deterministic evidence

The isolated API-compatible harness exercises 117 meaningful adversarial cases and four safe cases, including an explicitly authorized same-owner rollback case. Focused results are 30 passing tests, vulnerable ASR 117/117, hardened ASR 0/117, hardened FPR 0/4, and SafeTaskRate 4/4.

Deterministic evidence hashes:

- cache manifest SHA-256: `7e0ab033e702a0846cdf5197a185a01f22a9637c586ce503c9d9c40b7c07659b`;
- adversarial dataset SHA-256: `430a52385b8ce90d75f97ca1cdae69f923ae976e42b0544bed6ce96813ddbb86`;
- fixture/evaluator SHA-256: `416777e9607c7322fdfb6f6c282c22f7638338c1bed5d0de4c4373ba7dd7f526`;
- clean assessment SHA-256: `27edbe07d57ea8074742416aa028860dec3ae1125899b57a608e1d00c633866f`.

## Claim boundary

P10-C is deterministic synthetic lifecycle evidence. SHA-256 provides deterministic integrity binding in this model, not authenticity. A zeroization receipt is modeled evidence, not proof that physical CPU/GPU/HBM memory was overwritten. P10-C does **not** claim production cache-manager integration, physical memory zeroization, distributed cache coherence, allocator/GPU enforcement, DMA isolation, timing/cache side-channel resistance, production failover behavior, or semantic confidentiality of model outputs. It does not prove a real inference server executed the modeled eviction, reuse, or rollback operations.
