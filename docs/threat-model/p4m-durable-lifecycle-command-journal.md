# P4-M durable lifecycle command journal

P4-M closes the process-restart gap left by P4-L. P4-L keeps fence state and committed command receipts only in memory, so a process crash can erase the evidence needed to distinguish an already-completed lifecycle operation from a never-executed one. P4-M adds a synthetic local SQLite command journal authenticated by a separate local HMAC key file. It does not add a production lifecycle service, distributed lock, consensus protocol, remote idempotency ledger, or external monotonic witness.

## Security objective

Lifecycle command identity, fence generations, lifecycle state, and committed receipts must survive coordinator restart on the same local filesystem. A fresh coordinator must reject stale commands and conflicting command-id reuse, return a durable committed receipt without reinvoking the lifecycle provider, and fail closed when an in-flight provider outcome cannot be proven after restart.

The journal authenticates both the singleton fence metadata row and each lifecycle command row. The durable command record binds command id, operation, fence token, expected anchor-state fingerprint, logical resource id, command digest, provider identity, pre-operation observation, lifecycle state, and post-operation anchor fingerprint when committed.

## Durable state transitions

The synthetic state machine uses four states:

1. `prepared` — the command and fence are durable and the provider has not been marked as started;
2. `provider_started` — durable intent is recorded immediately before provider invocation;
3. `reconciliation_required` — restart or an ambiguous provider error prevents safe automatic replay;
4. `committed` — the provider returned successfully and the durable receipt/fence advancement was recorded.

A fresh coordinator converts any surviving `provider_started` record to `reconciliation_required`. This deliberately trades availability for safety: the coordinator refuses to infer that an interrupted provider invocation can be safely rerun.

## Crash windows

The deterministic harness covers three crash boundaries.

A crash after `prepared` but before provider invocation leaves enough durable evidence to retry the exact command after reopen, provided the command is not stale and its anchor precondition still matches.

A crash after the provider returns but before `committed` is durable leaves an ambiguous `provider_started` record. After reopen, normal execution is blocked. For synthetic key migration only, reconciliation can mark the command committed when durable pre-observation and current local state prove that legacy ciphertext existed before invocation, all observed ciphertext now uses the same active key, row counts are unchanged, and the anchor fingerprint changed. If the proof does not hold, reconciliation remains fail closed.

A crash after `committed` but before response delivery leaves a durable receipt. Exact replay after reopen returns that receipt without reinvoking the lifecycle provider.

## Tampering and missing state

The SQLite journal does not contain the HMAC secret. A separate local 32-byte key file authenticates fence metadata and command records. Row modification without a matching tag, invalid metadata authentication, an existing journal with a missing key file, malformed state, or inconsistent highest-fence metadata is rejected before lifecycle execution.

This integrity design is intentionally not rollback resistance. A principal able to roll back both the journal and the local HMAC key material can restore an older mutually consistent history. Deleting or restoring the entire pair is outside the protection offered by P4-M.

## Reconciliation limitations

P4-M implements a narrow proof for the synthetic P4-J encryption-migration path because the relevant effects can be observed through local ciphertext key ids, row counts, and anchor state. It does not claim a generic proof for ambiguous snapshot or restore operations. Those operations can involve external-style artifacts or state installation whose side effects cannot be proven from the P4-M journal alone, so ambiguous outcomes remain blocked.

The migration proof also does not create exactly-once semantics. It only reconstructs a committed receipt after restart when the included synthetic observations prove one safe outcome for the tested migration case.

## Trust and production posture

The journal, HMAC key, checkpoint SQLite database, and synthetic external-style anchor bridge all remain local or in process. There is no independent failure domain, remote witness, KMS/HSM custody, object store, provider-side idempotency token, distributed lease, cross-host fencing authority, or production recovery authority.

P4-K production lifecycle trust requirements are unchanged. P4-M cannot satisfy them. Production checkpoint lifecycle claim: none. Journal rollback-resistance claim: none. Distributed fencing claim: none. Exactly-once claim: none. Network operations: zero.
