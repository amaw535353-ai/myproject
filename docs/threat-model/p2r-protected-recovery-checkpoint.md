# P2-R: externally protected monotonic recovery checkpoint

## Security objective

P2-Q makes covered control-plane changes crash-safe across the local execution database and local anchor/journal database, but those two files remain one rollback domain for snapshot restore. If both are restored to the same older generation, their local equality checks can agree on obsolete authorization state.

P2-R adds a third trust-domain abstraction: a **protected monotonic checkpoint authority** excluded from the two-file restore set. The protected record binds the current control-plane generation to the canonical hash-chain head of the active P2-Q change journal. New authorization evidence and the first synthetic effect fail closed unless execution generation, local anchor generation, and protected checkpoint generation are identical and the reconstructed active-journal head equals the protected head.

The repository implementation is deliberately local and synthetic. `SyntheticProtectedCheckpointAuthority` uses a third SQLite file so CI can model an independently protected authority without network calls, accounts, cloud services, or hardware. The security claim is conditional on that third store being outside the tested restore set; a third file on the same real host is not sufficient production isolation.

## Trust boundaries

P2-R separates three state domains:

1. **Execution database** — current authorization state, policy/revocation versions, trusted signing-key state, execution-generation marker, and synthetic effect ledger. This file is restoreable in the deterministic test.
2. **P2-Q anchor/journal database** — active generation and `prepared -> applied -> active` change journal. This file is also restoreable in the deterministic test.
3. **Protected checkpoint authority** — monotonic `(authority_id, generation, journal_head_sha256)`. The test does not restore this store.

The protected authority supports compare-and-swap advancement by exactly one generation and never decrements a generation.

## Journal-head binding

Generation 1 starts from a deterministic genesis head. Every active P2-Q change extends the chain with canonical fields containing the authority ID, prior generation, target generation, previous head, change ID, and the SHA-256 of the canonical typed `ControlPlaneMutation`.

Before local state is accepted, P2-R reconstructs the chain and validates contiguous generations, typed mutation decoding, mutation-hash integrity, the execution marker's last change/hash binding, and exact equality between the local current head and protected checkpoint head.

The hash chain is an integrity binding, not an administrative authorization system. It proves that the local journal being used matches the previously checkpointed journal prefix under the stated threat model; it does not prove that an administrator was entitled to request a change.

## Crash and recovery semantics

A P2-R commit first completes the P2-Q local `prepared -> applied -> active` protocol, then advances the protected checkpoint. This is intentionally not described as one distributed transaction.

There is one additional safe failure window: local stores can reach generation `N+1` while the protected checkpoint remains at generation `N`. During that window, authorization issuance and first-effect execution reject with `protected_checkpoint_behind_local_generation`. Recovery may move the protected checkpoint forward only after proving that the protected generation/head is an exact prefix of the reconstructed local active chain.

If the protected checkpoint is ahead of the local generation, P2-R treats local state as restored/obsolete and fails closed with `protected_checkpoint_ahead_of_local_generation`. Recovery never decrements the checkpoint. If generation numbers match but journal heads do not, or the local journal chain is malformed, P2-R also fails closed.

## Deterministic comparison

`evals/p2r_protected_checkpoint.py` uses temporary local SQLite databases and synthetic authorization state only.

- **P2R-A1** advances subject authorization state and all checkpoints to generation 2, then restores both local control-plane databases to their generation-1 snapshots while leaving the protected checkpoint at generation 2. The local-only comparison accepts the obsolete state; P2-R records no effect.
- **P2R-A2** repeats the restore pattern after signing-key rotation from epoch 1 to epoch 2. Restoring both local files makes the old key look locally current again. The local-only comparison accepts it; P2-R rejects before a first effect because the protected generation remains 2.

Matched benign cases prove that current generation-1 state and a correctly checkpointed generation-2 key rotation still complete exactly once.

The report excludes approval IDs, idempotency keys, database contents, signatures, private-key bytes, raw control-plane mutation payloads, credentials, and real side effects.

## Source alignment

SQLite documents transactions as atomic across program, operating-system, and power failures, and its atomic-commit documentation explains the assumptions behind durable single-database commits. P2-Q and P2-R rely on those properties for individual SQLite transactions, but P2-R does not infer cross-database atomicity.

Primary references:

- SQLite, **Atomic Commit In SQLite**: https://sqlite.org/atomiccommit.html
- SQLite, **SQLite Is Transactional**: https://www.sqlite.org/transactional.html
- Trusted Computing Group, **TPM 2.0 Library Specification**: https://trustedcomputinggroup.org/resource/tpm-library-specification/

The TPM reference is only an example of a standardized hardware-rooted trust primitive family a production design might evaluate. AegisDesk does not implement a TPM, HSM, cloud KMS, transparency log, or remote checkpoint service in P2-R.

## Security invariants

For every new authorization envelope and first synthetic effect, the P2-Q journal must have no pending change; execution and local anchor generations must agree; the active journal must reconstruct to a valid hash chain; local generation must equal the protected generation; local head must equal the protected head; and all existing P2-P/P2-O/P2-N provenance, key-epoch, freshness, binding, and idempotency checks still apply.

Protected-checkpoint mismatch is retryable at the outbox layer because a checkpoint-behind state can result from a recoverable crash. Protected-ahead local state remains fail closed until trusted recovery restores matching current local state.

## Residual risks and non-claims

P2-R does not solve compromise, deletion, rollback, equivocation, or loss of the protected checkpoint authority itself. If an attacker can restore the protected store together with both local databases, this lab has no fourth independent fact with which to detect the coordinated restore.

The third SQLite file is a deterministic CI stand-in, not a production external service. P2-R does not provide distributed consensus, multi-region generation allocation, quorum replication, fencing leases, Byzantine-fault tolerance, hardware attestation, secure provisioning, authenticated administrative APIs, or production checkpoint backup/restore procedures.

All covered authorization-state writers must still use the P2-Q/P2-R coordinator. Direct writes can violate the journal/checkpoint invariant. Availability is deliberately traded for safety: protected-authority unavailability or inconsistency stops new authorization issuance and first-effect execution.

The exactly-once limitation from P2-L remains: the synthetic ledger demonstrates idempotent local effects, but a real side-effecting system must supply its own durable idempotency contract across replay and recovery windows.
