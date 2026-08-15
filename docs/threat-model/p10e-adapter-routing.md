# P10-E threat model — adapter/LoRA hot-swap and runtime routing

## Scope

P10-E governs deterministic evidence for changing an adapter stack after P10-D speculative/disaggregated serving has established the request, tenant/session, and target-model route. It does not modify P10-D's target/draft verification logic. Instead it binds runtime adapter artifacts and route-generation changes to the exact P10-D clean assessment and to policy-owned model, tenant, principal, authorization, composition, and replay evidence.

## Security objectives

The hardened boundary requires the exact P10-D assessment contract to remain admissible; exact request/tenant/session and target-model revision continuity; policy-pinned adapter IDs, kinds, revisions, generations, artifacts, provenance handles, base-model/tokenizer bindings, and parent relationships; data-only adapter serialization; tenant ownership; bounded rank/alpha/target modules; explicitly allowed stack order/compositions; an unexpired principal/tenant/base-model authorization for the final stack; monotonic route generations; exact before/after composition digests; ordered hot-swap evidence; prior-swap replay protection; and no modeled network operation.

## Fail-closed cases

The gate denies or rejects cross-tenant adapter use, adapter/base-model or tokenizer substitution, unapproved serialization, artifact/provenance replacement, adapter-kind/revision/generation substitution, self/unknown parent lineage, unauthorized stack order or depth, expired or wrong-principal authorization, stale/non-monotonic route generation, mismatched route snapshots, swap-chain reordering, replay of a prior swap, retired-adapter resurrection, request/tenant/session replay onto a different route, upstream P10-D degradation, and caller-declared safety that disagrees with derived evidence.

## Trust and claim boundary

SHA-256 and deterministic composition/swap digests provide integrity binding only; they are not authenticity or custody proof. Adapter provenance is an opaque policy-owned evidence handle and is not a cryptographic signature. P10-E does not claim a production adapter manager/model router, atomic GPU weight mutation, distributed replica consistency, cryptographic adapter signatures, physical memory zeroization, DMA isolation, side-channel resistance, hardware attestation, semantic equivalence of composed adapters, production availability, or proof that a real inference engine performed the modeled hot-swap.

The focused evaluator uses an API-compatible P10-D assessment contract and synthetic adapter artifacts. A passing deterministic P10-E assessment is therefore evidence for this modeled boundary only, not production certification.
