# Phase 4 hardening progress

Phase 4 starts after the six Phase 3 integration gaps were closed. P4-A narrowed the LangGraph checkpoint type policy used by the default agent runtime. P4-B extended that boundary to local durable checkpoint persistence with tamper-evident integrity and a separate monotonic local anchor. P4-C added local authenticated encryption and structural metadata minimization. P4-D added an explicit checkpoint encryption-key lifecycle boundary and controlled re-encryption migration. P4-E added authenticated local backup packaging and monotonic restore validation for that encrypted state. P4-F makes the remaining checkpoint trust dependencies explicit at deployment composition time and fails closed under a production-required profile unless external trust is supplied.

Current posture after P4-F:

- Phase 3 integration gaps: 0 open.
- P4-A checkpoint type policy: implemented and evaluated.
- P4-B durable checkpoint integrity: implemented and evaluated.
- P4-C checkpoint confidentiality and secret minimization: implemented and evaluated.
- P4-D checkpoint encryption-key lifecycle and migration: implemented and evaluated.
- P4-E authenticated encrypted checkpoint backup/restore: implemented and evaluated.
- P4-F checkpoint deployment trust-provider boundary: implemented and evaluated.
- Default agent checkpoint application allowlist: 4 exact AegisDesk types.
- Pickle fallback: disabled.
- Custom JSON constructor revival: disabled.
- Default API checkpoint payloads and pending writes: local AES-256-GCM ciphertext before SQLite persistence.
- Default API checkpoint encryption key: local synthetic v2 active for new encryption.
- Previous P4-C v1 encryption key: decrypt-only during the explicit migration window.
- Revoked checkpoint encryption keys: rejected.
- Default API checkpoint integrity: local HMAC-authenticated checkpoint/write state and separate local monotonic head anchor.
- P4-D migration: explicit, re-encrypts checkpoint payloads and pending writes, recomputes P4-B integrity chains and local anchors, and verifies current heads after the transaction.
- P4-E backup package: two local SQLite snapshots plus an authenticated manifest binding their SHA-256 digests, checkpoint heads, serialization policy, integrity key id, key-lifecycle policy, and active encryption key id.
- P4-E backup creation: refuses checkpoint or pending-write ciphertext that is not under the current active encryption key.
- P4-E restore: validates the manifest and both database snapshots before changing live state, rejects stale generations and forked histories against the current monotonic anchor, and performs the local database replacement in one attached-SQLite transaction.
- P4-F explicit checkpoint trust surfaces: encryption-key custody, integrity-key custody, monotonic anchor state, backup authentication, and recovery authority.
- P4-F local synthetic profile: accepted for the lab and explicitly ineligible for a production checkpoint trust claim.
- P4-F production-required profile: requires external providers in independent failure domains; key-bearing surfaces require external key custody, the anchor requires rollback-resistant external state, and recovery requires an external recovery authority.
- P4-F default API behavior: the local checkpoint trust factory is validated before local key providers, checkpoint databases, anchor databases, or backup manager composition are constructed. The production-required profile therefore fails closed instead of silently using the local synthetic runtime.
- Plaintext storage that remains by design: structural SQLite identifiers/type tags, minimized LangGraph control metadata, and the P4-E backup manifest. Dynamic checkpoint and pending-write payloads remain ciphertext in backup snapshots.
- Real external operations introduced by P4-F: none.
- External checkpoint trust implementation included: none.
- Production confidentiality, durability, key-management, backup, recovery, or disaster-recovery claim: none.

The default API still injects a `KeyLifecycleConfidentialCheckpointer` backed by a checkpoint encryption-key provider. P4-A constrains deserialization to the exact application type allowlist. P4-C encrypts serialized checkpoint payloads and pending writes before storage, P4-B authenticates ciphertext and the monotonic checkpoint chain, P4-D controls active/decrypt-only/revoked encryption-key lifecycle state, and P4-E wraps that existing local state without decrypting dynamic payloads into the backup package.

P4-F adds a deployment trust manifest around those checkpoint dependencies. The default `LocalSyntheticCheckpointTrustProviderFactory` supplies the existing local encryption keyring, P4-B integrity material, and P4-E backup authentication material, while its manifest also declares the local SQLite anchor and local-process recovery authority. Under `local_synthetic`, this preserves the existing deterministic lab. Under `production_external_required`, the local manifest is rejected before the checkpoint storage files are initialized.

The P3-F high-impact execution-control-plane trust boundary remains separate. It covers authorization signing, protected execution checkpoints, signed checkpoint receipts, and receipt witnesses. P4-F covers LangGraph agent checkpoint storage and recovery. Both use the same deployment-profile vocabulary but do not treat one domain's local trust provider as satisfying the other domain.

A P4-E restore still accepts a fresh target or a backup that extends the target's current authenticated history. For every current namespace, the backup must contain at least the current generation and the checkpoint digest at that generation must match the target's current monotonic anchor. A valid older backup is therefore rejected rather than being allowed to replace a newer current head. A valid backup from a forked history is also rejected.

P4-E intentionally requires backup checkpoint and pending-write ciphertext to use the provider's active encryption key. Decrypt-only legacy ciphertext must first pass through the explicit P4-D migration path; backup and restore do not create a second legacy-key fallback. The authenticated manifest uses separate local synthetic backup HMAC material and binds the backup file hashes, but all checkpoint security keys and backup files remain in the same local lab trust domain.

The next hardening target should add a concrete external checkpoint trust-provider adapter contract harness: exercise an external-style encryption-key provider, rollback-resistant anchor/witness abstraction, and recovery-authority adapter against the P4-F production profile using synthetic in-process doubles, without adding real credentials, network calls, or production claims.
