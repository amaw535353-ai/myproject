# P10-D threat model — speculative decoding and disaggregated serving

## Scope

P10-D models the integrity boundary between a trusted target model, a separately trusted draft model, and disaggregated prefill/draft/decode services. The analyzer consumes the exact P10-C cache-lifecycle assessment and binds it to one request-specific serving manifest. The manifest carries explicit request/tenant/session identity, target and draft model identities/digests, tokenizer and draft-trust profile digests, policy-pinned service identities, a request-input digest, a handoff-state digest, ordered cross-service state transfers, speculative-round evidence, final decode state, and a prior-transfer replay ledger.

The design intentionally does not infer route or model identity from P10-C: P10-C exposes scheduler, batch, and cache-epoch evidence, not final serving-model or RPC-service identities. P10-D therefore introduces separate policy-owned pins for those identities instead of claiming they are transitively contained upstream.

## Security invariants

The hardened `InferenceSpeculativeServingAnalyzer` fails closed unless all of the following hold:

- the P10-C assessment is `allow`, risk-free, has every positive P10-C verification flag set, every P10-C production/non-claim flag clear, and matches the exact P10-C schema/mode and assessment SHA-256;
- scheduler ID, batch ID, and cache epoch are bound exactly to P10-C and policy;
- request, tenant, session, request-input digest, target model, target revision/artifact digest, draft model, draft revision/artifact digest, tokenizer digest, draft-trust profile, and the cross-service handoff-state digest match policy-owned evidence;
- the service set is exactly one prefill, one draft, and one decode service, with exact service IDs, roles, model route, tokenizer, and deterministic service-identity digests;
- prefill input equals the request-input digest, prefill output equals the policy-pinned handoff state, and both draft/decode inputs equal that same handoff state;
- every state transfer is request/tenant/session/cache-epoch bound, follows the exact prefill-to-draft or prefill-to-decode topology, preserves the handoff-state digest, forms a deterministic previous-transfer hash chain, and cannot replay an ID from the prior-transfer ledger;
- speculative-round IDs/order are exact, draft proposals originate from the bound draft service, all proposed tokens are target-verified before acceptance, accepted tokens never exceed the target-verified count, and the target-verification evidence digest is deterministically recomputed;
- the final state equals the decode-service output and the last speculative-round result;
- no modeled network operation is present in this deterministic evidence path;
- caller-declared identity and safety summaries exactly match derived evidence.

## Adversary model

The adversarial corpus includes upstream P10-C decision/risk/flag/schema/mode degradation; request, tenant, session, scheduler, batch, cache-epoch, target-model, draft-model, tokenizer, trust-profile, request-input, and handoff-state substitutions; service role/model/tokenizer/input/output/identity tampering; transfer edge, owner, sequence, digest, epoch, previous-hash, replay-ledger, and state substitutions; speculative round service/owner/state/proposal/count/verification/result substitutions; token-budget abuse; partial or unverified draft acceptance; final-state substitution; stale/replayed manifests; policy downgrades; modeled network operations; and caller-summary lies.

A deliberately vulnerable baseline trusts only `declared_serving_safe`, demonstrating why caller assertions are not an admission boundary.

## Claim boundary

P10-D is deterministic synthetic evidence. SHA-256 provides integrity binding inside the modeled evidence graph; it is not authenticity, remote attestation, or proof of artifact custody. Deterministic service-identity and target-verification digests are not cryptographic service signatures and do not prove a real target model recomputed logits or token probabilities.

P10-D does **not** claim a production inference engine, RPC transport, disaggregated serving fabric, speculative decoder, tokenizer implementation, or cache/GPU allocator executed. It does not establish semantic equivalence between draft and target outputs, transport confidentiality, distributed linearizability, crash consistency, DMA isolation, timing/cache side-channel resistance, hardware attestation, or production availability/DoS resilience.

The local harness is API-compatible with the exact P10-C assessment contract but is not a full-repository execution. Hosted CI execution must be reported separately; zero-step GitHub Actions failures caused by runner/account provisioning are `REMOTE_CI_BLOCKED`, not test failures or passes.
