# Phase 4 hardening progress

Phase 4 hardens the default LangGraph checkpoint path after the Phase 3 integration gaps were closed. P4-A through P4-E established strict checkpoint deserialization, local durable integrity, local authenticated encryption, key lifecycle/migration, and authenticated local backup/restore. P4-F made five checkpoint deployment trust dependencies explicit. P4-G through P4-J moved the runtime toward operation-bearing providers, explicit lifecycle capabilities, and a synthetic external-style lifecycle harness. P4-K extended deployment trust to the lifecycle coordinator itself while preserving the original five-surface P4-F v1 policy. P4-L adds deterministic failure and fencing semantics around the synthetic external-style lifecycle coordinator.

Current posture after P4-L:

- Phase 3 integration gaps: 0 open.
- P4-A checkpoint type policy: implemented and evaluated.
- P4-B durable checkpoint integrity: implemented and evaluated.
- P4-C checkpoint confidentiality and structural secret minimization: implemented and evaluated.
- P4-D checkpoint encryption-key lifecycle and migration: implemented and evaluated.
- P4-E authenticated encrypted checkpoint backup/restore: implemented and evaluated.
- P4-F checkpoint deployment trust-provider boundary: implemented and evaluated.
- P4-G synthetic external checkpoint adapter contract harness: implemented and evaluated.
- P4-H checkpoint runtime operation-provider seam: implemented and evaluated.
- P4-I checkpoint lifecycle capability-provider boundary: implemented and evaluated.
- P4-J synthetic external-style lifecycle capability contract harness: implemented and evaluated.
- P4-K checkpoint lifecycle deployment trust-provider boundary: implemented and evaluated.
- P4-L synthetic lifecycle failure and fencing semantics harness: implemented and evaluated.

## Default checkpoint runtime

The default API still injects `OperationProviderKeyLifecycleCheckpointer`. P4-A constrains deserialization to four exact AegisDesk application types; pickle fallback and custom JSON constructor revival remain disabled. Dynamic checkpoint and pending-write payloads are encrypted with local AES-256-GCM before SQLite persistence. The default active checkpoint encryption key remains local synthetic v2, with the previous v1 key decrypt-only during the explicit P4-D migration window; revoked keys are rejected.

Checkpoint and pending-write integrity is produced and verified through an injected operation provider. The default provider remains local synthetic HMAC material hidden behind an operation interface. Monotonic checkpoint and pending-write heads are routed through an injected anchor operation provider; the default provider still owns a local SQLite anchor file. These are lab abstractions, not external custody or production durability.

P4-L does not replace the default local runtime with the synthetic external-style coordinator. The new fencing coordinator is an explicit lab harness layered around a P4-I/P4-J lifecycle provider for deterministic failure testing.

## Lifecycle capabilities and external-style coordination

P4-I makes `checkpoint_encryption_migration`, `checkpoint_backup_snapshot`, and `checkpoint_backup_restore` explicit lifecycle-provider capabilities. The default provider is `local-sqlite-agent-checkpoint-lifecycle`, bound to the exact local anchor-provider identity used by the saver. Missing providers, missing callables, missing advertised capabilities, or anchor-provider mismatches fail closed before the requested lifecycle operation changes checkpoint state. Backup creation checks snapshot capability before creating the backup directory.

P4-J adds `synthetic-external-contract-checkpoint-lifecycle`, bound to the synthetic P4-G/P4-H external-style anchor bridge. It exercises migration, pair snapshot, and pair restore without consulting the inherited compatibility anchor SQLite path after construction. The backup anchor artifact is generated from exported provider state for P4-E package compatibility; it is not copied from a live local anchor database.

P4-J remains synthetic in-process and not production-runtime eligible. Its migration exercise still uses local synthetic P4-D key custody. The bridge keeps provider head state in process, and checkpoint/provider coordination uses compensating one-process logic rather than distributed atomicity or crash-consistent cross-service recovery.

## P4-L failure and fencing semantics

`SyntheticFencedCheckpointLifecycleCoordinator` wraps a lifecycle operation provider with an in-memory command gate. A command binds its command id, lifecycle operation, monotonic fence token, expected anchor-state fingerprint, and logical resource id. The coordinator records a successful command receipt and advances its fence only after the lifecycle provider returns successfully.

P4-L exercises five deterministic failure classes:

1. ambiguous response after a lifecycle operation has committed;
2. provider unavailability before mutation;
3. stale fencing tokens and conflicting reuse of a committed command id;
4. concurrent anchor progression after command issuance but before execution;
5. injected partial anchor-state progression before failure.

For an ambiguous-after-commit fault, the receipt is recorded before the synthetic ambiguous error is returned. Retrying the exact command returns the recorded receipt without reinvoking the lifecycle provider. Reusing the command id with changed command fields is rejected. Commands at or below the highest committed fence are rejected unless they are exact receipt replays.

The command's expected anchor fingerprint is checked immediately before lifecycle invocation. If another writer changes the synthetic anchor after issuance, the command fails closed before the lifecycle provider is called. Provider-unavailable faults also fail before lifecycle invocation. The partial-progress fault mutates only synthetic anchor-provider state and then restores the pre-command provider snapshot before surfacing a typed reconciled failure; the same command can then be retried.

These semantics are intentionally a harness. Fence state and receipts are not durable across process restart, and the synthetic anchor bridge is not a remote authoritative service. The reconciliation path is compensating in-process logic, not a distributed transaction or exactly-once guarantee.

## Deployment trust

P4-F v1 retains exactly five checkpoint trust surfaces: encryption-key custody, integrity-key custody, monotonic anchor state, backup authentication, and recovery authority. The local synthetic profile is accepted for the lab and cannot make a production checkpoint trust claim. `production_external_required` requires external providers in independent failure domains; key-bearing surfaces require external key custody, the anchor requires rollback-resistant state, and recovery requires an external recovery authority.

P4-K deliberately does not mutate the P4-F surface enum or P4-F policy version. `LifecycleAwareCheckpointTrustManifest` wraps the unchanged P4-F manifest used by the default operation-provider factory so `assert_allowed()` evaluates both the original P4-F requirements and the P4-K lifecycle-provider descriptor.

The default lifecycle descriptor remains local synthetic, bound to `local-sqlite-agent-checkpoint-anchor`, synthetic in process, operationally non-external, and not production-runtime eligible. A complete external descriptor fixture can pass policy shape only. The included P4-J provider and P4-L coordinator cannot satisfy P4-K production trust because they remain synthetic and non-operationally-external.

## Backup and restore properties

P4-E backup packages remain a checkpoint SQLite snapshot, a structural anchor-state SQLite snapshot, and an authenticated manifest binding their SHA-256 digests, checkpoint heads, serialization policy, integrity provider id, key-lifecycle policy, and active encryption key id. Dynamic checkpoint and pending-write payloads remain ciphertext in the snapshot; structural SQLite identifiers/type tags, minimized LangGraph control metadata, the P4-E manifest, and structural head rows remain plaintext by design.

Backup authentication can use an operation-bearing provider, and restore invokes an injected recovery-authority provider after authentication and monotonic-history validation but before installation. Restore accepts a fresh target or a backup extending the target's current authenticated history. Older rollback candidates and forked histories are rejected. P4-I requires restore capability before the installation path can be reached; P4-J changes the provider used to install synthetic external-style anchor state, not the acceptance rules. P4-L does not weaken those P4-E acceptance rules.

P4-E still requires backup checkpoint and pending-write ciphertext to use the active encryption key. Decrypt-only legacy ciphertext must first pass through explicit P4-D migration; backup/restore does not introduce a legacy-key fallback.

## Evidence and claims

The P4-L deterministic dataset hash is `764c524b860b07c7551e2d98f2afbabd10be66b2045525ee5ab2499c19d454f0`. Its fixed acceptance criteria require implicit unfenced-lifecycle baseline ASR 5/5, hardened ASR 0/5, hardened FPR 0/3, and hardened SafeTaskRate 3/3. The evaluation additionally requires exact replay idempotency after an ambiguous commit, fail-before-mutation provider unavailability, stale/conflicting replay rejection, concurrent anchor-fence mismatch rejection, partial-anchor reconciliation, zero network operations, and no real external trust operation or production lifecycle claim.

P4-L introduces no real external operation, credential, provider SDK, or network call. Production external checkpoint adapter implementation: none. Production external lifecycle-provider implementation: none. Durable distributed fencing: false. Exactly-once execution: not claimed. Distributed transaction or consensus: not claimed. Production confidentiality, durability, key-management, backup, recovery, disaster-recovery, lifecycle-atomicity, or external-trust claim: none.

The P3-F high-impact execution-control-plane trust boundary remains separate. It covers authorization signing, protected execution checkpoints, signed checkpoint receipts, and receipt witnesses. P4-F through P4-L cover LangGraph agent checkpoint storage, recovery, lifecycle coordination, deployment trust, and synthetic lifecycle failure semantics. One domain's provider does not satisfy the other domain's trust requirements.

## Next target

P4-M should make the P4-L lifecycle command journal and fencing generation durable and restart-verifiable in a local synthetic store, then exercise crash/reopen cases around receipt persistence and fence advancement. The target should remain local and synthetic with no real credentials, network services, distributed-consensus claim, or production claim.
