# Phase 4 hardening progress

Phase 4 starts after the six Phase 3 integration gaps were closed. P4-A narrowed the LangGraph checkpoint type policy used by the default agent runtime. P4-B extended that boundary to local durable checkpoint persistence with tamper-evident integrity and a separate monotonic local anchor. P4-C added local authenticated encryption and structural metadata minimization. P4-D added an explicit checkpoint encryption-key lifecycle boundary and controlled re-encryption migration. P4-E added authenticated local backup packaging and monotonic restore validation for that encrypted state. P4-F made the remaining checkpoint trust dependencies explicit at deployment composition time and fails closed under a production-required profile unless external trust is supplied. P4-G added an operation-bearing synthetic external adapter contract harness for all five P4-F checkpoint trust surfaces while preserving the distinction between contract shape and actual external trust. P4-H moves the default checkpoint persistence and recovery composition onto operation-bearing integrity, anchor, backup-authentication, and recovery-authority provider seams.

Current posture after P4-H:

- Phase 3 integration gaps: 0 open.
- P4-A checkpoint type policy: implemented and evaluated.
- P4-B durable checkpoint integrity: implemented and evaluated.
- P4-C checkpoint confidentiality and secret minimization: implemented and evaluated.
- P4-D checkpoint encryption-key lifecycle and migration: implemented and evaluated.
- P4-E authenticated encrypted checkpoint backup/restore: implemented and evaluated.
- P4-F checkpoint deployment trust-provider boundary: implemented and evaluated.
- P4-G synthetic external checkpoint adapter contract harness: implemented and evaluated.
- P4-H checkpoint runtime operation-provider seam: implemented and evaluated.
- Default agent checkpoint application allowlist: 4 exact AegisDesk types.
- Pickle fallback: disabled.
- Custom JSON constructor revival: disabled.
- Default API checkpoint payloads and pending writes: local AES-256-GCM ciphertext before SQLite persistence.
- Default API checkpoint encryption key: local synthetic v2 active for new encryption.
- Previous P4-C v1 encryption key: decrypt-only during the explicit migration window.
- Revoked checkpoint encryption keys: rejected.
- Default API checkpoint integrity: checkpoint and pending-write authenticators are produced and verified through an injected operation provider; the default provider is still a local synthetic HMAC implementation.
- Default API monotonic checkpoint head: read, compare-and-advance, pending-write-head publication, and thread deletion are routed through an injected anchor operation provider; the default provider still owns a local SQLite anchor file.
- Default API saver no longer retains the P4-B raw HMAC key after construction. The local operation-provider factory still contains synthetic fixture material internally and inherits legacy raw-material compatibility helpers, so this is a composition-boundary improvement rather than external custody.
- P4-D migration: explicit, re-encrypts checkpoint payloads and pending writes, recomputes integrity chains and local anchors, and verifies current heads after the transaction. The inherited migration path still assumes the injected anchor is represented by the saver's local anchor SQLite path; P4-H does not claim migration support for an operationally external anchor.
- P4-E backup package: two local SQLite snapshots plus an authenticated manifest binding their SHA-256 digests, checkpoint heads, serialization policy, integrity provider id, key-lifecycle policy, and active encryption key id.
- P4-E backup authentication: creation and verification can now use an operation-bearing backup-authentication provider instead of requiring the manager to retain raw HMAC material. The default provider remains local synthetic.
- P4-E recovery authority: authenticated and monotonic-boundary-validated restore now calls an injected recovery-authority provider before installing target state. Denial fails closed before the attached-SQLite replacement.
- P4-E anchor snapshot/restore: the operation path supports snapshot-capable providers that expose a local SQLite database path. A provider without that local snapshot capability is not silently downgraded; backup/restore is unsupported rather than treated as a production external-anchor recovery path.
- P4-F explicit checkpoint trust surfaces: encryption-key custody, integrity-key custody, monotonic anchor state, backup authentication, and recovery authority.
- P4-F local synthetic profile: accepted for the lab and explicitly ineligible for a production checkpoint trust claim.
- P4-F production-required profile: requires external providers in independent failure domains; key-bearing surfaces require external key custody, the anchor requires rollback-resistant external state, and recovery requires an external recovery authority.
- P4-F default API behavior remains fail closed: the inherited local trust manifest is validated before operation-provider checkpoint composition is constructed. `production_external_required` still rejects the local synthetic runtime.
- P4-G operation-bearing contract doubles: synthetic external-style encryption, integrity authentication, monotonic anchor, backup authentication, and recovery authorization adapters.
- P4-H runtime contract coverage: the actual saver can exercise the P4-G integrity operation contract and a P4-G monotonic-anchor bridge for checkpoint get/put integrity and rollback checks; backup authentication and recovery authority are also exercised through P4-G operation-bearing doubles.
- P4-H P4-G anchor bridge: pending-write heads remain a synthetic in-process extension because P4-G originally modeled checkpoint-head compare-and-advance only. It is not an external anchor implementation.
- P4-H default API composition: `OperationProviderKeyLifecycleCheckpointer` remains a subclass of the existing P4-D saver so P4-A through P4-G compatibility is retained while core integrity and anchor operations are overridden through providers.
- Compatibility local anchor artifact: the inherited saver setup still initializes the configured local anchor SQLite path even when a synthetic external-style anchor is injected for a P4-H harness. Core P4-H checkpoint operations do not consult that compatibility file in the harness, but its existence means P4-H does not claim complete removal of local anchor artifacts.
- Plaintext storage that remains by design: structural SQLite identifiers/type tags, minimized LangGraph control metadata, and the P4-E backup manifest. Dynamic checkpoint and pending-write payloads remain ciphertext in backup snapshots.
- Real external operations introduced by P4-H: none.
- Production external checkpoint adapter implementation included: none.
- Production confidentiality, durability, key-management, backup, recovery, disaster-recovery, or external-trust claim: none.

The default API now injects an `OperationProviderKeyLifecycleCheckpointer`. P4-A still constrains deserialization to the exact application type allowlist. P4-C encrypts serialized checkpoint payloads and pending writes before storage, P4-D controls active/decrypt-only/revoked encryption-key lifecycle state, and P4-H routes P4-B authentication and monotonic-head operations through injected providers rather than keeping the raw integrity key in the saver. The default implementations remain deterministic local synthetic providers.

P4-F still supplies the deployment trust manifest used before checkpoint composition. P4-H's `LocalSyntheticCheckpointOperationProviderFactory` subclasses the existing local factory so the same local manifest and fail-closed production-required policy remain in force. The default composition asks this factory for operation-bearing integrity, anchor, backup-authentication, and recovery-authority providers; it no longer asks for raw integrity or backup-authentication material. The inherited compatibility material methods still exist and are not a production secret-management interface.

P4-G's synthetic external-style contracts can now be used by the actual checkpoint runtime for the operations they model. The P4-H evaluation injects the P4-G integrity adapter and monotonic-anchor contract into a real `OperationProviderKeyLifecycleCheckpointer`, verifies checkpoint tamper and database rollback fail closed, and exercises P4-G backup authentication and recovery authorization through the P4-E manager. These adapters remain in-process doubles with zero network operations and no independent failure domain.

The P3-F high-impact execution-control-plane trust boundary remains separate. It covers authorization signing, protected execution checkpoints, signed checkpoint receipts, and receipt witnesses. P4-F through P4-H cover LangGraph agent checkpoint storage and recovery. Both use the same deployment-profile vocabulary but do not treat one domain's trust provider as satisfying the other domain.

A P4-E restore still accepts a fresh target or a backup that extends the target's current authenticated history. For every current namespace, the backup must contain at least the current generation and the checkpoint digest at that generation must match the target's current monotonic anchor. A valid older backup is rejected rather than being allowed to replace a newer current head, and a valid backup from a forked history is also rejected. P4-H adds recovery authorization after these authentication and monotonic checks but before installation.

P4-E intentionally requires backup checkpoint and pending-write ciphertext to use the provider's active encryption key. Decrypt-only legacy ciphertext must first pass through the explicit P4-D migration path; backup and restore do not create a second legacy-key fallback. P4-H changes how backup authentication is invoked, not the checkpoint ciphertext format or active-key requirement.

The next hardening target should make lifecycle migration and backup/restore capabilities explicit provider operations rather than assuming a local SQLite anchor snapshot path. That P4-I capability boundary should fail closed for providers that cannot supply atomic snapshot, restore, or migration semantics and should remain synthetic/local-only in this repository without adding real credentials, network calls, or production claims.
