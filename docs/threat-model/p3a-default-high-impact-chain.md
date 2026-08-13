# P3-A: default high-impact security chain

## Scope

P3-A closes Phase 3 gap `P3-G01`: the default FastAPI high-impact approval path now composes the hardened P2-N through P2-S control-plane and effect-boundary primitives instead of stopping at P2-M. The downstream effect remains a local synthetic SQLite record. No real access grant, credential change, password reset, external IAM call, or public network target is introduced.

## Security property

Before the first synthetic high-impact effect is recorded, the server-owned path must require all of the following:

1. The original P2-K approval workflow is durable, tenant-bound, requester-bound, action-bound, and argument-bound.
2. P2-L consumes the approved request and creates its idempotent outbox record through the existing transactional coordinator.
3. P2-M current server-owned authorization state permits the exact requester, tenant, action, and normalized arguments.
4. P2-N policy version and revocation epoch in the authorization evidence match authoritative execution state.
5. P2-O verifies Ed25519 authorization provenance, expected issuer/audience, current signing-key epoch, validity window, and exact request binding.
6. P2-P requires the signed authorization envelope to carry the independently stored current control-plane generation.
7. P2-Q requires the local execution database and independent generation journal to be converged with no pending control-plane change.
8. P2-R requires the protected checkpoint generation and canonical journal head to match the local active generation.
9. P2-S authenticates a predecessor-linked checkpoint receipt and pins that single observed history in the separate local witness database.
10. Only after those checks may the synthetic idempotent effect ledger record the first effect.

The model never authorizes any of these steps. Identity, tenant, approval state, versions, signing-key trust, generations, checkpoints, receipt history, and final effect authorization are server-owned data and control decisions.

## Default runtime composition

`apps/api/dependencies.py` builds one cached `DefaultHighImpactSecurityStack` from `aegis/effects/default_high_impact.py`. The stack keeps distinct local paths for approval/outbox state, execution authorization/effect state, the control-plane generation journal, the protected checkpoint authority, and the receipt witness. The default `AgentRunner` receives the stack's `DurableApprovedEffectPipeline`.

The local P3-A checkpoint receipt source is deliberately synthetic. It derives an Ed25519 test key from the public synthetic fixture seed label and persists predecessor-linked receipts in the synthetic protected-checkpoint database. The consumer sees only the corresponding trusted public key. This demonstrates the P2-S verification contract; it does not model production private-key custody.

## Fail-closed behavior

Startup validates control-plane convergence and the current authenticated checkpoint receipt before returning the default stack. New effect delivery fails closed if any control-plane generation, protected checkpoint, receipt signature/history, authorization version, authorization signature, key epoch, tenant binding, or request binding check fails. P2-L idempotency semantics remain responsible for duplicate suppression of an already committed identical synthetic effect.

P3-A intentionally does not add an administrative API for control-plane mutations. Existing P2-Q/P2-R mutation and recovery objects are composed into the runtime stack for controlled server-side use and deterministic tests only.

## Matched evaluation

`evals.p3a_default_high_impact_chain` compares the new default chain with the previous P2-M-only default composition isolated under `aegis/vulnerable/`. The deterministic adversarial set exercises an invalid checkpoint receipt and a deliberately non-converged generation state. The matched benign set exercises approved access and approved password-reset requests. All effects are local synthetic records.

Expected metrics are vulnerable ASR 2/2, hardened ASR 0/2, hardened FPR 0/2, and hardened safe-task rate 2/2.

## Evidence hygiene

Evaluation reports exclude approval identifiers, database contents, raw effect arguments, receipt signatures, and private-key bytes. No external service, real account, real grant, or real password reset is used.

## Residual risk

P3-A closes the **default runtime integration** gap, not the production trust-anchor gap. `P3-G06` remains open: the checkpoint authority, receipt witness, authorization signing key, and rollback domains are local synthetic abstractions. An attacker able to compromise all local trust domains and their key material is outside the guarantees demonstrated here. Production deployment needs independently operated or hardware/remote-backed trust, key custody, recovery policy, availability engineering, and multi-node consistency.

The current chain also does not solve the point-of-no-return problem for a real external side effect. The project still records only a synthetic local effect, so production-grade downstream idempotency and transactional semantics remain separate work.
