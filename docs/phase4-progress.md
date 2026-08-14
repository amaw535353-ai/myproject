# Phase 4 hardening progress

Phase 4 starts after the six Phase 3 integration gaps were closed. P4-A narrowed the LangGraph checkpoint type policy used by the default agent runtime. P4-B extended that boundary to local durable checkpoint persistence with tamper-evident integrity and a separate monotonic local anchor. P4-C added local authenticated encryption and structural metadata minimization. P4-D added an explicit checkpoint encryption-key lifecycle boundary and controlled re-encryption migration. P4-E added authenticated local backup packaging and monotonic restore validation for that encrypted state. P4-F made the remaining checkpoint trust dependencies explicit at deployment composition time and fails closed under a production-required profile unless external trust is supplied. P4-G added an operation-bearing synthetic external adapter contract harness for all five P4-F checkpoint trust surfaces while preserving the distinction between contract shape and actual external trust. P4-H moves the default checkpoint persistence and recovery composition onto operation-bearing integrity, anchor, backup-authentication, and recovery-authority provider seams. P4-I makes checkpoint encryption migration, checkpoint/anchor pair snapshot, and checkpoint/anchor pair restore explicit lifecycle capabilities bound to the configured anchor-provider identity.

Current posture after P4-I:

- Phase 3 integration gaps: 0 open.
- P4-A checkpoint type policy: implemented and evaluated.
- P4-B durable checkpoint integrity: implemented and evaluated.
- P4-C checkpoint confidentiality and secret minimization: implemented and evaluated.
- P4-D checkpoint encryption-key lifecycle and migration: implemented and evaluated.
- P4-E authenticated encrypted checkpoint backup/restore: implemented and evaluated.
- P4-F checkpoint deployment trust-provider boundary: implemented and evaluated.
- P4-G synthetic external checkpoint adapter contract harness: implemented and evaluated.
- P4-H checkpoint runtime operation-provider seam: implemented and evaluated.
- P4-I checkpoint lifecycle capability-provider boundary: implemented and evaluated.
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
- P4-I lifecycle operations: `checkpoint_encryption_migration`, `checkpoint_backup_snapshot`, and `checkpoint_backup_restore` are explicit provider capabilities. The default API injects `local-sqlite-agent-checkpoint-lifecycle`, bound to the exact local anchor-provider instance used by the saver.
- P4-I fail-closed behavior: a missing lifecycle provider, a provider that does not advertise the requested capability, or a lifecycle provider bound to a different anchor-provider identity is rejected before the requested lifecycle operation changes checkpoint state. Backup creation checks the snapshot capability before creating the backup directory.
- P4-I external-style posture: the synthetic P4-G anchor runtime can still drive ordinary P4-H checkpoint get/put operations, but it receives no implicit local lifecycle authority. Migration, backup snapshot, and restore fail closed rather than falling back to the inherited compatibility anchor SQLite path.
- P4-D migration: explicit, re-encrypts checkpoint payloads and pending writes, recomputes integrity chains and local anchors, and verifies current heads after the transaction. Under P4-I the default runtime reaches that local migration only through the bound local lifecycle provider.
- P4-E backup package: two local SQLite snapshots plus an authenticated manifest binding their SHA-256 digests, checkpoint heads, serialization policy, integrity provider id, key-lifecycle policy, and active encryption key id.
- P4-E backup authentication: creation and verification can use an operation-bearing backup-authentication provider instead of requiring the manager to retain raw HMAC material. The default provider remains local synthetic.
- P4-E recovery authority: authenticated and monotonic-boundary-validated restore calls an injected recovery-authority provider before installing target state. Denial fails closed before replacement.
- P4-I pair snapshot/restore: the local lifecycle provider owns the local SQLite pair-snapshot and attached-SQLite restore mechanics. These mechanics are no longer inferred from a compatibility path for operation-provider savers.
- P4-F explicit checkpoint trust surfaces: encryption-key custody, integrity-key custody, monotonic anchor state, backup authentication, and recovery authority.
- P4-F local synthetic profile: accepted for the lab and explicitly ineligible for a production checkpoint trust claim.
- P4-F production-required profile: requires external providers in independent failure domains; key-bearing surfaces require external key custody, the anchor requires rollback-resistant external state, and recovery requires an external recovery authority.
- P4-F default API behavior remains fail closed: the inherited local trust manifest is validated before operation-provider checkpoint composition is constructed. `production_external_required` still rejects the local synthetic runtime.
- P4-G operation-bearing contract doubles: synthetic external-style encryption, integrity authentication, monotonic anchor, backup authentication, and recovery authorization adapters.
- P4-H runtime contract coverage: the actual saver can exercise the P4-G integrity operation contract and a P4-G monotonic-anchor bridge for checkpoint get/put integrity and rollback checks; backup authentication and recovery authority are also exercised through P4-G operation-bearing doubles.
- P4-H P4-G anchor bridge: pending-write heads remain a synthetic in-process extension because P4-G originally modeled checkpoint-head compare-and-advance only. It is not an external anchor implementation.
- P4-H/P4-I default API composition: `OperationProviderKeyLifecycleCheckpointer` remains a subclass of the existing P4-D saver so P4-A through P4-H compatibility is retained while core integrity, anchor, and lifecycle operations are provider-routed.
- Compatibility local anchor artifact: the inherited saver setup can still initialize the configured local anchor SQLite path when a synthetic external-style anchor is injected for a harness. P4-I does not treat that compatibility file as lifecycle authority and therefore does not silently use it for migration, snapshot, or restore.
- Plaintext storage that remains by design: structural SQLite identifiers/type tags, minimized LangGraph control metadata, and the P4-E backup manifest. Dynamic checkpoint and pending-write payloads remain ciphertext in backup snapshots.
- Real external operations introduced by P4-I: none.
- Production external checkpoint or lifecycle adapter implementation included: none.
- Production confidentiality, durability, key-management, backup, recovery, disaster-recovery, lifecycle-atomicity, or external-trust claim: none.

The default API injects an `OperationProviderKeyLifecycleCheckpointer` with explicit operation providers. P4-A still constrains deserialization to the exact application type allowlist. P4-C encrypts serialized checkpoint payloads and pending writes before storage, P4-D controls active/decrypt-only/revoked encryption-key lifecycle state, P4-H routes P4-B authentication and monotonic-head operations through injected providers, and P4-I routes migration/snapshot/restore through an anchor-bound lifecycle capability provider. The default implementations remain deterministic local synthetic providers.

P4-F still supplies the deployment trust manifest used before checkpoint composition. P4-H's `LocalSyntheticCheckpointOperationProviderFactory` subclasses the existing local factory so the same local manifest and fail-closed production-required policy remain in force. P4-I extends that factory with a local lifecycle provider and the API injects it using the same local anchor-provider instance. The inherited compatibility material methods still exist and are not a production secret-management interface.

P4-G's synthetic external-style contracts can be used by the actual checkpoint runtime for the operations they model. P4-H verifies checkpoint tamper and database rollback fail closed and exercises P4-G backup authentication and recovery authorization through the P4-E manager. P4-I deliberately does not reinterpret those contracts as lifecycle capability: an external-style anchor without a lifecycle provider can continue ordinary checkpoint operations, but migration, backup snapshot, and restore are rejected before lifecycle state change.

The P3-F high-impact execution-control-plane trust boundary remains separate. It covers authorization signing, protected execution checkpoints, signed checkpoint receipts, and receipt witnesses. P4-F through P4-I cover LangGraph agent checkpoint storage and recovery. Both use the same deployment-profile vocabulary but do not treat one domain's trust provider as satisfying the other domain.

A P4-E restore still accepts a fresh target or a backup that extends the target's current authenticated history. For every current namespace, the backup must contain at least the current generation and the checkpoint digest at that generation must match the target's current monotonic anchor. A valid older backup is rejected rather than being allowed to replace a newer current head, and a valid backup from a forked history is also rejected. P4-H adds recovery authorization after these authentication and monotonic checks but before installation; P4-I requires restore capability before that installation path can be reached.

P4-E intentionally requires backup checkpoint and pending-write ciphertext to use the provider's active encryption key. Decrypt-only legacy ciphertext must first pass through the explicit P4-D migration path; backup and restore do not create a second legacy-key fallback. P4-I changes how lifecycle operations are authorized by capability and bound to an anchor provider, not the checkpoint ciphertext format or active-key requirement.

The current P4-I lifecycle implementation remains local SQLite and single-process. Saver and local-anchor locks coordinate the local provider, but this is not distributed snapshot atomicity, multiprocess fencing, or an operational external lifecycle service. A provider that claims external anchor semantics must supply its own explicit lifecycle capabilities; the repository does not infer them from a database path.

The next hardening target should add a synthetic external-style lifecycle capability contract harness for migration, pair snapshot, and restore. P4-J should verify that external-style lifecycle providers can satisfy the P4-I operation contracts without exposing or depending on a local SQLite anchor path, while remaining in-process, zero-network, synthetic-only, and explicitly ineligible for a production lifecycle claim.
