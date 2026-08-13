# P4-E: authenticated encrypted checkpoint backup and restore

## Security boundary

P4-E protects local backup and restore of the LangGraph agent checkpoint state introduced by P4-B through P4-D. The backup contains SQLite snapshots of the checkpoint database and its monotonic anchor database. Dynamic checkpoint values and pending writes remain P4-C/P4-D ciphertext; P4-E does not decrypt them into a new backup format.

The backup manifest binds the checkpoint snapshot hash, anchor snapshot hash, checkpoint heads, P4-A serialization policy, P4-B integrity key identifier, P4-D key-lifecycle policy, active encryption key identifier, and the P4-E backup policy. A separate local synthetic HMAC authenticates that manifest.

## Restore rules

Restore fails closed before live state is changed when the manifest authentication is invalid, a snapshot hash does not match, the active encryption key differs, a backup contains decrypt-only or otherwise non-active checkpoint ciphertext, or the backup does not validate under the existing checkpoint integrity/confidentiality controls.

The current anchor is also a restore boundary. For every namespace already present on the target, the candidate backup must contain at least the current generation and must contain the current authenticated checkpoint digest at that generation. An older valid snapshot is rejected as rollback. A different valid history is rejected as a fork. A fresh target and a candidate that extends the current history are allowed.

The local restore replaces checkpoint rows, pending writes, checkpoint heads, and write heads in one attached-SQLite transaction after validation. The restored state is revalidated after commit.

## Key-lifecycle interaction

P4-E intentionally does not use P4-D decrypt-only keys as a backup compatibility path. Backup creation and restore require stored checkpoint and pending-write ciphertext to use the provider's active encryption key. Existing decrypt-only ciphertext must be migrated through the explicit P4-D migration operation before backup.

## Evaluation

The deterministic P4-E evaluation compares an unauthenticated restore baseline with the hardened boundary. The adversarial cases cover backup-file substitution and restoration of an internally valid but stale backup. Benign cases cover recovery to a fresh target and forward recovery where the target's current authenticated head is an ancestor of the backup.

The target metrics are baseline ASR 2/2, hardened ASR 0/2, hardened FPR 0/2, and hardened SafeTaskRate 2/2. Reports contain no raw key bytes or checkpoint contents and perform no external operations.

## Non-goals and residual risk

P4-E is local synthetic lab hardening, not production backup or disaster recovery. Backup authentication material, checkpoint integrity material, encryption keys, databases, and backup files remain in one local trust domain. There is no remote object store, KMS/HSM custody, independent recovery authority, retention policy, secure deletion guarantee, multi-host coordination, or production recovery SLA. Structural SQLite identifiers and the authenticated manifest remain plaintext by design.
