# P4-D checkpoint key lifecycle and migration

P4-D adds explicit lifecycle states for checkpoint encryption keys while preserving the P4-A strict type boundary, P4-B integrity and rollback checks, and P4-C encrypted checkpoint storage.

New checkpoint payloads and pending writes use only the active key. A prior key can be marked decrypt-only during a controlled migration window. A revoked key is rejected. The default API uses a local synthetic v2 key as active and the existing v1 key as decrypt-only.

The checkpointer depends on a `CheckpointEncryptionKeyProvider` interface for encryption, decryption, envelope key identification, and lifecycle state. The core checkpointer does not require raw encryption-key bytes in that provider contract. The included provider remains a local in-process synthetic implementation for deterministic CI and does not represent external key custody.

The explicit migration operation first reads existing namespaces through the current integrity and decryption checks. It then re-encrypts checkpoint payloads and pending writes under the active key, recomputes integrity digests and checkpoint-chain links, updates the local monotonic anchors, commits the attached SQLite databases transactionally, and verifies current heads again after the update.

The deterministic evaluation covers two boundary cases and two safe-use cases. It verifies that data moved to the active key is no longer readable by the old single-key reader, that revoked-key ciphertext is rejected, that decrypt-only legacy data can still be opened during staging, and that checkpoint and pending-write state survive migration.

This milestone remains local and synthetic. It makes no KMS, HSM, external custody, production rotation, or production durability claim. Multi-process migration coordination, automatic post-migration revocation, backup re-encryption and authenticity, restoration rollback protection, retention and deletion policy, external key availability, and production recovery procedures remain outside P4-D.
