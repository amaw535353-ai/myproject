# P4-B durable checkpoint integrity boundary

## Security property

The default API must not consume persisted LangGraph checkpoint state after an undetected local modification or rollback. Durable checkpoint rows are serialized with the P4-A exact application-type policy and are authenticated with a local synthetic HMAC. A separate local anchor database records the monotonic latest checkpoint head. Pending writes are authenticated individually and as a complete set.

This is a lab integrity boundary, not a production durability or key-custody claim. The checkpoint database, anchor database, and HMAC key all remain local synthetic components.

## Trust boundary

The default API constructs `DurableIntegrityCheckpointer` with two different SQLite paths. The checkpoint database stores serialized checkpoints and pending writes. The anchor database stores the current checkpoint generation/head digest and pending-write set digests. The process-local synthetic HMAC key authenticates canonical digests but is intentionally not treated as externally protected secret material.

The graph receives checkpoint data only after the saver verifies the checkpoint HMAC chain, the latest head against the separate anchor, and any pending-write set. The saver continues to use the P4-A serializer, so persisted application objects are limited to the explicit AegisDesk type allowlist.

## Adversarial cases

`P4B-A1-persisted-checkpoint-modification` changes a serialized checkpoint row after persistence without updating its integrity evidence. A durable store without integrity accepts the changed state. The P4-B saver rejects it with `checkpoint_integrity_mismatch` before returning state to the graph.

`P4B-A2-checkpoint-database-rollback` advances from generation 1 to generation 2, then restores only the checkpoint database to its generation-1 snapshot while leaving the separate anchor advanced. An unprotected durable store accepts the stale state. The P4-B saver rejects the mismatch with `checkpoint_rollback_detected`.

The security tests also remove a persisted pending-write row while leaving its write-set anchor unchanged. The saver rejects the incomplete write set instead of silently re-running from altered persistence state.

## Benign cases

`P4B-B1-legitimate-durable-reopen` closes and reopens the saver and verifies that legitimate `Principal` and `ToolCallProposal` values still reconstruct under the P4-A exact type policy.

`P4B-B2-legitimate-graph-resume-after-reopen` persists a synthetic LangGraph interrupt, creates a new saver and graph instance over the same local files, then resumes successfully. This demonstrates local restart/resume behavior without external services.

## Failure behavior

Checkpoint HMAC mismatch, broken checkpoint integrity chain, mismatch with the current monotonic head, pending-write HMAC mismatch, or pending-write set mismatch all fail closed with typed `CheckpointIntegrityError` reasons. The saver does not fall back to unverified state.

## Residual risk

The HMAC key is a visible local synthetic fixture and is not protected by KMS/HSM or another trust service. The separate SQLite anchor is only a second local file, not an independent production failure domain. An attacker able to replace the checkpoint database, anchor database, and local key together can forge a self-consistent local state. SQLite availability, backup, retention, multi-process coordination, operational recovery, key rotation, external attestation, and production-scale concurrency are also outside P4-B.

A production adapter must preserve the P4-A type restriction and P4-B fail-closed integrity semantics while moving checkpoint durability, monotonic anchoring, and signing-key custody into appropriately protected operational trust domains.
