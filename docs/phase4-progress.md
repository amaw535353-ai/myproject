# Phase 4 hardening progress

Phase 4 starts after the six Phase 3 integration gaps were closed. P4-A narrowed the LangGraph checkpoint type policy used by the default agent runtime. P4-B extended that boundary to local durable checkpoint persistence with tamper-evident integrity and a separate monotonic local anchor. P4-C added local authenticated encryption and structural metadata minimization. P4-D adds an explicit checkpoint encryption-key lifecycle boundary and controlled re-encryption migration.

Current posture after P4-D:

- Phase 3 integration gaps: 0 open.
- P4-A checkpoint type policy: implemented and evaluated.
- P4-B durable checkpoint integrity: implemented and evaluated.
- P4-C checkpoint confidentiality and secret minimization: implemented and evaluated.
- P4-D checkpoint encryption-key lifecycle and migration: implemented and evaluated.
- Default agent checkpoint application allowlist: 4 exact AegisDesk types.
- Pickle fallback: disabled.
- Custom JSON constructor revival: disabled.
- Default API checkpoint payloads and pending writes: local AES-256-GCM ciphertext before SQLite persistence.
- Default API checkpoint encryption key: local synthetic v2 active for new encryption.
- Previous P4-C v1 encryption key: decrypt-only during the explicit migration window.
- Revoked checkpoint encryption keys: rejected.
- Default API checkpoint integrity: local HMAC-authenticated checkpoint/write state and separate local monotonic head anchor.
- P4-D migration: explicit, re-encrypts checkpoint payloads and pending writes, recomputes P4-B integrity chains and local anchors, and verifies current heads after the transaction.
- Plaintext storage that remains by design: structural SQLite identifiers/type tags and minimized LangGraph control metadata.
- Legacy P4-B plaintext checkpoint rows: rejected rather than silently loaded as encrypted state.
- Real external operations introduced by P4-D: none.
- Production confidentiality, durability, or key-management claim: none.

The default API now injects a `KeyLifecycleConfidentialCheckpointer` backed by a `CheckpointEncryptionKeyProvider`. P4-A still constrains deserialization to the exact application type allowlist. P4-C still encrypts serialized checkpoint payloads and pending writes before storage, and P4-B still authenticates ciphertext, pending-write sets, and the monotonic checkpoint chain. P4-D makes encryption-key selection and lifecycle explicit rather than coupling the default runtime to one permanent local encryption key.

The default local provider stages v2 as active and the existing P4-C v1 key as decrypt-only. New writes use v2, while existing v1 ciphertext can be reopened for controlled migration. The migration operation re-encrypts durable checkpoint and pending-write ciphertext under the active key and updates the integrity chain and local anchors in the same attached-SQLite transaction.

P4-D remains intentionally local and synthetic. The AES-GCM and HMAC keys are embedded local lab material, and the anchor database is a second local file rather than an independent production trust service. The lifecycle contract creates an adapter boundary, but the included adapter does not provide external key custody, hardware protection, automated rotation, distributed migration coordination, or a production key-management claim.

The next hardening target should address encrypted checkpoint backup and restore: authenticated backup packaging, restoration against the current monotonic boundary, and rollback-safe recovery without reintroducing older-key or plaintext fallback paths.
