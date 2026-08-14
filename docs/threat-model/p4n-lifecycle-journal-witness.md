# P4-N lifecycle-journal witness threat model

## Scope

P4-N hardens the P4-M same-filesystem lifecycle command journal against a narrower rollback class: the P4-M SQLite journal, or the journal together with its own local HMAC key, is restored to an older authentic state while an independently stored local witness remains newer.

The milestone remains a local synthetic harness. It does not claim an external monotonic service, independent host, distributed lock, consensus system, remote idempotency service, or production rollback resistance.

## Threat

P4-M authenticates journal rows and fence metadata, but its journal and authentication key are both local artifacts. An attacker or operator able to restore an older authentic journal copy can present a structurally valid earlier lifecycle history. If both the journal and its P4-M HMAC material are rolled back together, P4-M by itself cannot distinguish that state from legitimate older history.

The security consequence is loss of durable lifecycle command and fence history after reopen. A stale command may appear unissued or uncommitted, and a previously completed lifecycle operation may lose its durable receipt.

## Boundary

`WitnessedDurableSyntheticCheckpointLifecycleCoordinator` wraps the P4-M coordinator with a second local artifact:

- a witness JSON file;
- a separate 32-byte local HMAC key file;
- a monotonic witness generation;
- the P4-M highest issued and committed fence values;
- command and committed counts;
- a digest of the authenticated journal structure;
- per-fence command digest and lifecycle state summaries.

The witness stores command digests and structural state only. It does not duplicate checkpoint payloads, encryption keys, lifecycle arguments, or raw P4-M pre-operation observations.

## Verification and rollback detection

P4-N first asks P4-M to verify every journal row and metadata record using P4-M's existing authentication rules. It then derives the witness attestation from the authenticated journal.

On reopen, the current journal is compared with the authenticated witness. The coordinator rejects:

- lower issued or committed fence generations;
- fewer command or committed records;
- disappearance of a previously witnessed command;
- regression of a command lifecycle state;
- reuse of a witnessed fence with a different command digest;
- witness payload modification without a valid witness HMAC;
- a missing witness when the journal already contains command history.

An older authentic journal restored while the witness stays newer therefore fails closed with `checkpoint_lifecycle_journal_rollback_detected`.

## Non-atomic journal/witness crash window

The journal and witness are different local files, so their updates are not one atomic transaction. P4-N deliberately models a crash after a P4-M journal mutation but before the witness update.

A fresh coordinator may advance an older witness only when the current authenticated journal is provably monotonic-forward from every previously witnessed command: all witnessed command digests remain identical, no witnessed command disappears, all counters are non-decreasing, and each lifecycle state is equal or later in the allowed monotonic state ordering. This permits safe recovery from a stale witness without re-executing an already committed lifecycle operation.

If the current journal is not provably monotonic-forward, the coordinator fails closed rather than adopting it.

## Relationship to P4-M reconciliation

P4-N does not weaken P4-M's `PREPARED -> PROVIDER_STARTED -> RECONCILIATION_REQUIRED -> COMMITTED` semantics. P4-M remains responsible for deciding whether an ambiguous provider outcome can be reconciled. P4-N witnesses those durable journal transitions and allows only monotonic-forward witness recovery.

The P4-M synthetic migration reconciliation proof remains the only automatic ambiguous-outcome reconciliation currently supported. Snapshot and restore ambiguity remain fail closed.

## Explicit limitations

P4-N is not a production monotonic witness. The witness, witness key, P4-M journal, and P4-M journal key all live on the same host/filesystem in the harness. An actor able to roll back all four artifacts to one mutually consistent older snapshot can evade this boundary.

Therefore:

- joint journal-and-witness rollback detection: not guaranteed;
- rollback-resistant storage claim: false;
- independent failure domain: false;
- cross-host fencing: false;
- distributed lease or lock: false;
- consensus: false;
- exactly-once execution: not claimed;
- production external lifecycle provider: not included;
- network operations: zero.

A future stronger boundary would require an operationally independent monotonic witness or provider-side idempotency evidence. P4-N intentionally does not simulate that as a production capability.
