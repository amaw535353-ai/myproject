# P4-P Provider-Internal Crash-Safe Command State

## Security property

A lifecycle provider must not blindly re-run a command merely because it crashed after mutating lifecycle state but before persisting the P4-O outcome receipt. P4-P durably records provider-owned command identity and normalized operation-argument identity before mutation, then recovers an interrupted command only when observable state proves the intended mutation completed or when durable state proves mutation never started.

The provider-side state machine is `prepared -> mutation_started -> committed`. Exact command replay is bound to the complete lifecycle command digest and to an argument digest covering snapshot destinations or restore backup paths. A retry that reuses the same command with different lifecycle paths fails closed before another lifecycle mutation.

## Trust boundary

The lab boundary is:

`P4-M caller journal -> P4-P command-aware lifecycle provider -> authenticated provider command SQLite + authenticated P4-O outcome SQLite -> lifecycle mutation / anchor state -> proof-based provider recovery -> caller reconciliation`

The provider command database and outcome database each use separate local HMAC keys. They model durable provider-owned evidence, not an external transaction service. All artifacts remain same-host synthetic storage.

## Controls

- The provider persists exact command identity, argument digest, pre-operation observation, provider identity, and lifecycle state before invoking the underlying P4-J lifecycle operation.
- `prepared` means provider mutation has not started and can be safely retried after restart if the command and anchor precondition still match.
- `mutation_started` never causes blind re-execution. Recovery must prove the intended postcondition from observable state before creating the missing P4-O receipt.
- Migration recovery requires unchanged row counts, transition of all observed ciphertext to the active key, and anchor progression.
- Snapshot recovery requires the bound checkpoint destination to match the logical source checkpoint-store fingerprint and the bound anchor destination to match the pre-operation anchor fingerprint.
- Restore recovery binds the exact backup paths before mutation and requires the live checkpoint database and anchor state to match the pre-recorded backup fingerprints.
- A committed P4-O provider receipt is replayed without invoking the lifecycle mutation again.
- Provider command-state HMAC tampering or command/argument conflicts fail closed.
- If post-mutation evidence is missing or cannot prove the exact intended state, recovery fails closed rather than guessing.
- P4-K production rejection remains in force; the provider is synthetic, in-process, network-free, and not production-runtime eligible.

## Matched vulnerable baseline

`aegis/vulnerable/p4p_provider_internal_ambiguity.py` deliberately keeps no durable provider command state before mutation. A synthetic crash after lifecycle mutation therefore loses provider-side knowledge that the mutation started. An exact retry invokes the underlying provider again, and a retry can substitute different snapshot destinations or restore backup paths.

## What P4-P does not prove

P4-P does not make an exactly-once claim. Provider command state, lifecycle state, anchor state, and the P4-O outcome receipt are still separate local durability domains. The harness converges only when deterministic local evidence is sufficient to prove a single intended outcome. A torn or partially durable lifecycle mutation that does not satisfy the proof remains blocked.

The provider command database, outcome database, their HMAC keys, checkpoint database, and synthetic anchor still share a host and can be jointly rolled back or compromised. There is no remote idempotency service, distributed transaction, consensus protocol, cross-host lease/fence, hardware-backed key custody, independent failure domain, or production lifecycle provider. No network requests, real credentials, real accounts, or real external trust operations are used.

## Residual risk / next target

The checkpoint hardening phase now has enough depth that the next highest-value milestone should be an exit review rather than another local durability layer. P4-Q should consolidate P4-A through P4-P into a machine-readable Phase 4 claim/evidence gate, explicitly reject production durability/external-trust claims, record the remaining synthetic/local assumptions, and create a clean entry gate for a broader Phase 5 model and AI supply-chain security track.
