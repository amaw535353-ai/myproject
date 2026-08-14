# P4-O Provider-Side Idempotency and Outcome Receipts

## Security property

A lifecycle command that has already reached the synthetic provider must not be blindly re-executed merely because the caller-side P4-M journal lost the provider response. The P4-O provider owns a durable authenticated outcome ledger keyed by the server-issued lifecycle `command_id` and binds each receipt to the complete command digest, operation, fence token, resource identifier, expected pre-operation anchor fingerprint, provider identity, and observed post-operation anchor fingerprint.

For a caller-side journal in `reconciliation_required`, the P4-O coordinator may transition the local command to `committed` only when the provider returns an authenticated receipt for the exact command and the receipt's post-operation anchor fingerprint still equals the current anchor state. Missing, conflicting, corrupted, or stale provider evidence fails closed.

## Trust boundary

The lab boundary is:

`P4-M caller journal -> command-aware lifecycle provider -> provider-owned outcome SQLite + separate HMAC key -> current checkpoint anchor state -> caller reconciliation`

The P4-O outcome database is separate from the P4-M caller journal and therefore models provider-owned command identity/result durability. It remains local, synthetic, same-host storage and does not establish an operational external trust service.

## Controls

- Exact replay of the same `command_id` and command digest returns the existing provider receipt without re-invoking the underlying lifecycle operation.
- Reuse of a `command_id` with a different command digest fails closed before provider execution.
- Provider receipts are authenticated with a separate local 32-byte HMAC key and are verified on store reopen.
- Receipts contain only normalized security metadata and fingerprints; raw checkpoint state, backup paths, ciphertext, key material, and credentials are not persisted in the receipt ledger.
- Reconciliation verifies the provider ID and current post-operation anchor fingerprint before committing the local P4-M journal.
- Ambiguous caller-side results for migration, snapshot, and restore are recovered from provider-owned receipts without provider re-execution in the deterministic evaluation.
- P4-K deployment posture remains fail closed: this synthetic in-process provider is not production-runtime eligible even when described as an external provider.

## Matched vulnerable baseline

`aegis/vulnerable/p4o_outcome_blind.py` deliberately preserves no provider-owned command identity or outcome receipt. Exact retries invoke the synthetic lifecycle provider again, and the same command ID can be reused with a conflicting digest. It exists only for the local deterministic comparison.

## What P4-O does not prove

P4-O makes no exactly-once claim. The underlying lifecycle mutation and persistence of the provider outcome receipt are still two local durability events. A provider process failure after the lifecycle mutation commits but before the provider receipt commits can therefore remain ambiguous. The caller must fail closed when no authenticated provider receipt exists rather than infer success from incomplete evidence.

The provider outcome database and HMAC key are local synthetic files. Rolling both back together, compromising the provider, or compromising its HMAC key can defeat this lab boundary. There is no remote signature, hardware-backed attestation, independent failure domain, quorum, distributed lease/fence service, or production lifecycle provider. P4-N's independent local journal witness remains a separate control for caller-journal rollback and is not replaced by provider receipts.

No network requests, real credentials, real accounts, or real external trust operations are used.

## Residual risk / next target

The highest-value remaining ambiguity is now inside the provider boundary itself: lifecycle state may commit before its durable outcome receipt. A follow-on milestone should model a provider-internal crash-safe command state machine so mutation and receipt recovery are idempotently convergent without claiming distributed exactly-once execution.
