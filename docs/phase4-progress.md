# Phase 4 hardening progress

Phase 4 hardens the default LangGraph checkpoint path after the Phase 3 integration gaps were closed. P4-A through P4-E established strict checkpoint deserialization, local durable integrity, local authenticated encryption, key lifecycle/migration, and authenticated local backup/restore. P4-F made five checkpoint deployment trust dependencies explicit. P4-G through P4-J moved the runtime toward operation-bearing providers, explicit lifecycle capabilities, and a synthetic external-style lifecycle harness. P4-K extended deployment trust to the lifecycle coordinator itself while preserving the original five-surface P4-F v1 policy. P4-L added deterministic failure and in-process fencing semantics. P4-M added a local authenticated SQLite command journal so command identity, fence generations, lifecycle state, and committed receipts survive process restart. P4-N added a separate local synthetic witness that can detect rollback of the P4-M journal, including rollback of the journal together with its own P4-M HMAC key, while the witness remains newer. P4-O adds a provider-owned authenticated outcome ledger so caller-side ambiguous lifecycle results can be reconciled from exact provider command identity and durable outcome evidence without blindly re-running the provider.

Current posture after P4-O:

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
- P4-M durable local lifecycle command journal and restart reconciliation harness: implemented and evaluated.
- P4-N independent local synthetic lifecycle-journal witness/rollback-detection harness: implemented and evaluated.
- P4-O provider-owned authenticated lifecycle outcome-receipt/idempotency harness: implemented and evaluated.

## Default checkpoint runtime

The default API still injects `OperationProviderKeyLifecycleCheckpointer`. P4-A constrains deserialization to four exact AegisDesk application types; pickle fallback and custom JSON constructor revival remain disabled. Dynamic checkpoint and pending-write payloads are encrypted with local AES-256-GCM before SQLite persistence. The default active checkpoint encryption key remains local synthetic v2, with the previous v1 key decrypt-only during the explicit P4-D migration window; revoked keys are rejected.

Checkpoint and pending-write integrity is produced and verified through an injected operation provider. The default provider remains local synthetic HMAC material hidden behind an operation interface. Monotonic checkpoint and pending-write heads are routed through an injected anchor operation provider; the default provider still owns a local SQLite anchor file. These are lab abstractions, not external custody or production durability.

P4-M through P4-O do not replace the default local runtime. `DurableSyntheticCheckpointLifecycleCoordinator`, `WitnessedDurableSyntheticCheckpointLifecycleCoordinator`, `ProviderOutcomeRecoveringLifecycleCoordinator`, and the provider-owned outcome store are explicit lab harnesses layered around a P4-I/P4-J lifecycle provider. Their journal, witness, provider-outcome, and HMAC key files are supplied to the harness and are not part of the default API request path.

## Lifecycle capabilities and external-style coordination

P4-I makes `checkpoint_encryption_migration`, `checkpoint_backup_snapshot`, and `checkpoint_backup_restore` explicit lifecycle-provider capabilities. The default provider is `local-sqlite-agent-checkpoint-lifecycle`, bound to the exact local anchor-provider identity used by the saver. Missing providers, missing callables, missing advertised capabilities, or anchor-provider mismatches fail closed before the requested lifecycle operation changes checkpoint state. Backup creation checks snapshot capability before creating the backup directory.

P4-J adds `synthetic-external-contract-checkpoint-lifecycle`, bound to the synthetic P4-G/P4-H external-style anchor bridge. It exercises migration, pair snapshot, and pair restore without consulting the inherited compatibility anchor SQLite path after construction. The backup anchor artifact is generated from exported provider state for P4-E package compatibility; it is not copied from a live local anchor database.

P4-J remains synthetic in-process and not production-runtime eligible. Its migration exercise still uses local synthetic P4-D key custody. The bridge keeps provider head state in process, and checkpoint/provider coordination uses compensating one-process logic rather than distributed atomicity or crash-consistent cross-service recovery.

## P4-L failure and fencing semantics

`SyntheticFencedCheckpointLifecycleCoordinator` wraps a lifecycle operation provider with an in-memory command gate. A command binds its command id, lifecycle operation, monotonic fence token, expected anchor-state fingerprint, and logical resource id. The coordinator records a successful command receipt and advances its fence only after the lifecycle provider returns successfully.

P4-L exercises ambiguous response after commit, provider unavailability, stale or conflicting command replay, concurrent anchor progression, and injected partial anchor progression. Exact replay of a committed command is idempotent only while the P4-L coordinator process remains alive. P4-L does not persist receipts or fence state across restart.

## P4-M durable command journal and restart reconciliation

`DurableSyntheticCheckpointLifecycleCoordinator` introduces a separate local SQLite lifecycle journal plus a separate local 32-byte HMAC key file. The journal stores the command envelope, durable issued fence generation, durable highest committed fence, provider identity, pre-operation observation, lifecycle state, and committed receipt fields. Each command row and the singleton fence metadata row are authenticated before use. A modified command row, invalid metadata tag, missing HMAC key for an existing journal, or inconsistent journal state fails closed.

The durable state machine distinguishes `prepared`, `provider_started`, `reconciliation_required`, and `committed`. A fresh coordinator converts any surviving `provider_started` record into `reconciliation_required`, preventing a restart from blindly re-executing an operation whose provider outcome may be ambiguous.

P4-M exercises crashes after `prepared` but before provider invocation, after provider return but before durable `committed`, and after durable `committed` but before the caller receives the response. A pre-provider crash can be safely retried when the fence and anchor precondition remain valid. A post-commit crash replays the durable receipt without provider reinvocation. The ambiguous middle window remains blocked until reconciliation.

For the synthetic migration operation only, P4-M can reconcile a provider-completed/local-commit-missing window when local observations prove one safe committed outcome. Snapshot and restore ambiguity remain fail closed in P4-M itself.

## P4-N independent local journal witness

`WitnessedDurableSyntheticCheckpointLifecycleCoordinator` wraps P4-M with a second local artifact and separate 32-byte HMAC key. The witness records a monotonic witness generation, highest issued and committed fences, command and committed counts, a digest of the authenticated P4-M journal structure, and per-fence command-digest/lifecycle-state summaries. It does not duplicate checkpoint payloads, lifecycle arguments, encryption keys, or raw P4-M pre-operation observations.

P4-N first relies on P4-M to authenticate every journal row and metadata record. It then derives the witness attestation from that authenticated state. On reopen it rejects lower fence generations, fewer commands or receipts, disappearance of a witnessed command, lifecycle-state regression, reuse of a witnessed fence with another command digest, witness HMAC tampering, and a missing witness when lifecycle history already exists.

The journal and witness are separate files and cannot be updated atomically. P4-N therefore models a crash after a P4-M journal mutation but before witness update. A fresh coordinator may advance a stale witness only when the authenticated journal is provably monotonic-forward from every previously witnessed command. This allows a durable committed receipt to survive that crash window without provider reinvocation.

P4-N preserves P4-M's fail-closed ambiguous-outcome reconciliation. It witnesses the `provider_started -> reconciliation_required -> committed` transitions but does not invent a new proof for snapshot or restore.

## P4-O provider-owned outcome receipts

`SyntheticIdempotentOutcomeReceiptLifecycleProvider` wraps the synthetic P4-J lifecycle provider with a separate local SQLite outcome ledger and separate local 32-byte HMAC key. Provider receipts bind the exact command digest, operation, fence token, resource id, expected pre-operation anchor fingerprint, provider identity, and observed post-operation anchor fingerprint. Raw checkpoint state, backup paths, ciphertext, credentials, and key material are not stored in the outcome receipt.

An exact command replay returns the authenticated stored provider receipt without invoking the underlying lifecycle operation again. Reuse of the same command id with a different digest fails closed before provider execution. Receipt-row modification or a missing/invalid integrity key for an existing provider store fails closed on reopen.

`ProviderOutcomeRecoveringLifecycleCoordinator` extends the P4-M caller journal. If the caller journal reopens in `reconciliation_required`, it requires an authenticated provider receipt for that exact command, verifies the receipt provider identity, and requires the receipt's post-operation anchor fingerprint to equal the current anchor state before the local journal can become `committed`. The deterministic evaluation exercises migration, snapshot, and restore with a synthetic crash after the provider has persisted its result but before the caller journal commits; all three recover without provider re-execution.

P4-O is intentionally not an exactly-once mechanism. The underlying lifecycle mutation and the provider-owned outcome receipt are still separate local durability events. A provider-internal crash after the lifecycle mutation commits but before the provider receipt commits remains ambiguous and must fail closed. The outcome database and its HMAC key are local synthetic artifacts and do not create an independent failure domain or production provider. P4-N remains a separate caller-journal rollback control.

## Deployment trust

P4-F v1 retains exactly five checkpoint trust surfaces: encryption-key custody, integrity-key custody, monotonic anchor state, backup authentication, and recovery authority. P4-K deliberately does not mutate the P4-F surface enum or P4-F policy version; it adds a separate lifecycle-provider descriptor and policy boundary.

The default lifecycle descriptor remains local synthetic, synthetic in process, operationally non-external, and not production-runtime eligible. A complete external descriptor fixture can pass policy shape only. The included P4-J provider and P4-L through P4-O harnesses cannot satisfy P4-K production trust because they remain synthetic and operationally non-external.

## Backup and restore properties

P4-E backup packages remain a checkpoint SQLite snapshot, a structural anchor-state SQLite snapshot, and an authenticated manifest binding their SHA-256 digests, checkpoint heads, serialization policy, integrity provider id, key-lifecycle policy, and active encryption key id. Dynamic checkpoint and pending-write payloads remain ciphertext in the snapshot; structural SQLite identifiers/type tags, minimized LangGraph control metadata, the P4-E manifest, and structural head rows remain plaintext by design.

Restore accepts a fresh target or a backup extending the target's current authenticated history. Older rollback candidates and forked histories are rejected. P4-I requires restore capability before installation; P4-J changes the provider used to install synthetic external-style anchor state, not P4-E acceptance rules. P4-L through P4-O do not weaken those rules.

## Evidence and claims

The P4-O deterministic dataset hash is `478bd6c74e8ad1326002f90ff466fe574a1f805fbfe98b483481038aaeae08e3`. Its fixed acceptance criteria require outcome-blind baseline ASR 2/2, hardened ASR 0/2, hardened FPR 0/3, and hardened SafeTaskRate 3/3. The evaluation additionally requires migration, snapshot, and restore caller-side ambiguity to reconcile from authenticated provider-owned receipts without provider re-execution, provider receipt integrity tampering to fail closed, P4-K production rejection to remain in force, zero network operations, no exactly-once claim, and no production lifecycle-provider claim.

P4-O introduces no real external operation, credential, provider SDK, or network call. Production external checkpoint adapter implementation: none. Production external lifecycle-provider implementation: none. Durable same-filesystem lifecycle journal: true. Separate local synthetic journal witness: true. Separate local synthetic provider outcome ledger: true. Provider-owned exact-command idempotency evidence in the lab: true. Provider-internal operation/receipt atomicity: false. Independent failure domain: false. Production rollback-resistance claim: false. Distributed fencing: false. Exactly-once execution: not claimed. Distributed transaction or consensus: not claimed. Production confidentiality, durability, key-management, backup, recovery, disaster-recovery, lifecycle-atomicity, or external-trust claim: none.

The P3-F high-impact execution-control-plane trust boundary remains separate. It covers authorization signing, protected execution checkpoints, signed checkpoint receipts, and receipt witnesses. P4-F through P4-O cover LangGraph agent checkpoint storage, recovery, lifecycle coordination, deployment trust, failure semantics, restart-verifiable lifecycle state, local rollback detection, and provider-owned outcome evidence. One domain's provider does not satisfy the other domain's trust requirements.

## Next target

P4-P should close P4-O's provider-internal ambiguity by adding a synthetic crash-safe provider command state machine around lifecycle mutation and outcome-receipt persistence. It should model deterministic crashes after provider prepare, after lifecycle mutation but before receipt commit, and after receipt commit before response; recover idempotently from provider-owned command identity and observable state; remain credential-free and network-free; preserve P4-K production rejection; and still make no distributed exactly-once or production-provider claim.
