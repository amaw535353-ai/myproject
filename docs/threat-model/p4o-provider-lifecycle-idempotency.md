# P4-O — Provider-side lifecycle idempotency and outcome receipts

## Threat

P4-M durably records local lifecycle command state and P4-N independently witnesses that local history, but neither artifact is owned by a real lifecycle provider. If the caller loses the provider response after a migration, snapshot, or restore, a restarted caller can know that its local execution is ambiguous without knowing whether the provider actually applied the command. Blindly replaying the lifecycle operation can duplicate side effects or overwrite state.

P4-O introduces a synthetic provider-owned command ledger and authenticated outcome receipt contract so the lab can exercise the provider boundary explicitly. It remains local and in-process; it does not claim a production external provider.

## Provider command identity

Each provider request is bound to the P4-L command identity:

- command ID;
- canonical command digest;
- lifecycle operation;
- monotonic fence token;
- resource ID;
- expected anchor fingerprint;
- provider ID; and
- a request digest covering the operation-specific path arguments.

Reusing a command ID with a different command or request digest is rejected. A new command whose fence token is not greater than the provider ledger's highest accepted fence is rejected as stale.

## Durable provider states

The synthetic SQLite provider ledger uses three states:

1. `ACCEPTED` — command identity is durably reserved and no side effect has started;
2. `STARTED` — the provider may have performed a side effect, so replay is unsafe until the outcome is known;
3. `APPLIED` — the outcome and authenticated provider receipt are durable.

A retry of an exact `APPLIED` request returns the same authenticated outcome receipt without calling the wrapped P4-J lifecycle provider again. A surviving `STARTED` record returns `checkpoint_lifecycle_provider_outcome_unknown` and does not blindly reexecute.

## Outcome receipt

An applied receipt binds provider ID, command ID/digest, operation, fence, resource ID, expected anchor fingerprint, request digest, post-operation anchor fingerprint, and a result digest. The receipt is authenticated with separate local synthetic provider-ledger HMAC material. Tampered or command-spliced receipts fail closed.

The provider ledger itself authenticates its metadata and every command row. Ledger row tampering therefore fails closed on reopen. P4-O does not add an independent provider-ledger rollback witness, so an authentic rollback of the ledger and its local HMAC key remains outside this milestone.

## Crash windows

P4-O deterministically injects three synthetic failures:

- after `ACCEPTED` and before any side effect;
- after the wrapped lifecycle side effect but before `APPLIED` is durably recorded; and
- after `APPLIED` and its receipt are durable but before the response reaches the caller.

The first window is retryable because provider state proves the side effect never started. The second window remains fail closed as an unknown provider outcome. The third window is recoverable by querying the durable provider receipt after reopen, without re-invoking the lifecycle side effect.

## Local P4-M reconciliation

`ProviderOutcomeAwareDurableCheckpointLifecycleCoordinator` is a P4-M-compatible synthetic coordinator that invokes the command-aware P4-O provider API. If local P4-M state becomes `RECONCILIATION_REQUIRED` while the provider already has a valid `APPLIED` receipt, the coordinator verifies the receipt and current anchor fingerprint before committing the local receipt. If provider outcome is unknown or the anchor does not match the provider receipt, reconciliation fails closed.

This is outcome-based reconciliation, not exactly-once execution.

## Preserved boundaries

The wrapped P4-J lifecycle provider still performs migration, pair snapshot, and pair restore through its operation-bearing external-style anchor bridge. P4-O does not introduce access to the poisoned compatibility anchor path. P4-K production lifecycle trust remains unchanged and rejects this synthetic provider because it is in-process, has no independent operational failure domain, is not operationally external, and is not production-runtime eligible.

## Explicit limitations

P4-O provides no network service, remote durability, distributed transaction, consensus, cross-host fencing, provider SLA, provider-side rollback-resistant witness, exactly-once guarantee, or production external lifecycle provider. The provider ledger and its HMAC key are local synthetic artifacts on the same host. A host capable of coherently rolling back those artifacts can defeat this local ledger history. Production idempotency and outcome evidence would require an operationally independent external provider with its own durable identity, fencing, receipt, and recovery semantics.
