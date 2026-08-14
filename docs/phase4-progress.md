# Phase 4 hardening progress

Phase 4 hardens the default LangGraph checkpoint path after the Phase 3 integration gaps were closed. P4-A through P4-E established strict checkpoint deserialization, local durable integrity, local authenticated encryption, key lifecycle/migration, and authenticated local backup/restore. P4-F made five checkpoint deployment trust dependencies explicit. P4-G through P4-J then moved the runtime toward operation-bearing providers, explicit lifecycle capabilities, and a synthetic external-style lifecycle harness. P4-K extends deployment trust to the lifecycle coordinator itself while preserving the original five-surface P4-F v1 policy and deterministic evidence.

Current posture after P4-K:

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

## Default checkpoint runtime

The default API still injects `OperationProviderKeyLifecycleCheckpointer`. P4-A constrains deserialization to four exact AegisDesk application types; pickle fallback and custom JSON constructor revival remain disabled. Dynamic checkpoint and pending-write payloads are encrypted with local AES-256-GCM before SQLite persistence. The default active checkpoint encryption key remains local synthetic v2, with the previous v1 key decrypt-only during the explicit P4-D migration window; revoked keys are rejected.

Checkpoint and pending-write integrity is produced and verified through an injected operation provider. The default provider remains local synthetic HMAC material hidden behind an operation interface. Monotonic checkpoint and pending-write heads are routed through an injected anchor operation provider; the default provider still owns a local SQLite anchor file. These are lab abstractions, not external custody or production durability.

## Lifecycle capabilities

P4-I makes `checkpoint_encryption_migration`, `checkpoint_backup_snapshot`, and `checkpoint_backup_restore` explicit lifecycle-provider capabilities. The default provider is `local-sqlite-agent-checkpoint-lifecycle`, bound to the exact local anchor-provider identity used by the saver. Missing providers, missing callables, missing advertised capabilities, or anchor-provider mismatches fail closed before the requested lifecycle operation changes checkpoint state. Backup creation checks snapshot capability before creating the backup directory.

P4-J adds `synthetic-external-contract-checkpoint-lifecycle`, bound to the synthetic P4-G/P4-H external-style anchor bridge. It exercises migration, pair snapshot, and pair restore without consulting the inherited compatibility anchor SQLite path after construction. Deterministic tests poison that compatibility path and still observe `compatibility_anchor_path_accesses=0`. The backup anchor artifact is generated from exported provider state for P4-E package compatibility; it is not copied from a live local anchor database.

P4-J remains synthetic in-process and not production-runtime eligible. Its migration exercise still uses local synthetic P4-D key custody. The bridge keeps provider head state in process, and checkpoint/provider coordination uses compensating one-process logic rather than distributed atomicity, multiprocess fencing, or crash-consistent cross-service recovery.

## Deployment trust

P4-F v1 retains exactly five checkpoint trust surfaces:

1. encryption-key custody;
2. integrity-key custody;
3. monotonic anchor state;
4. backup authentication;
5. recovery authority.

The local synthetic profile is accepted for the lab and cannot make a production checkpoint trust claim. `production_external_required` requires external providers in independent failure domains; key-bearing surfaces require external key custody, the anchor requires rollback-resistant state, and recovery requires an external recovery authority.

P4-K deliberately does not mutate the P4-F surface enum or P4-F policy version. Instead, `LifecycleAwareCheckpointTrustManifest` wraps the unchanged P4-F manifest used by the default operation-provider factory. Existing callers still read the same P4-F `providers` tuple and P4-F policy version, while `assert_allowed()` now evaluates both the original P4-F trust requirements and the P4-K lifecycle-provider descriptor.

The default P4-K lifecycle descriptor is:

- provider id: `local-sqlite-agent-checkpoint-lifecycle`;
- anchor provider id: `local-sqlite-agent-checkpoint-anchor`;
- kind: `local_synthetic`;
- independent failure domain: false;
- capabilities: migration, snapshot, restore;
- synthetic in process: true;
- operationally external: false;
- production-runtime eligible: false.

This descriptor is valid only for the local lab profile. The default dependency graph still validates trust before checkpoint persistence composition is created; the included local P4-F providers already cause `production_external_required` to fail closed, and the lifecycle coordinator is now explicitly part of the same deployment-trust assertion rather than an unmodeled follow-on dependency.

For a production-shaped checkpoint manifest, P4-K additionally rejects a lifecycle coordinator that is local, shares the checkpoint failure domain, is synthetic in-process, is not operationally external, is not production-runtime eligible, is bound to a different monotonic-anchor provider identity, or omits any of the three lifecycle capabilities.

The deterministic P4-K evaluation also includes a complete external lifecycle descriptor bound to the P4-G external-style anchor descriptor. That descriptor passes policy shape only. No operational external lifecycle provider is implemented, and passing descriptor validation is not evidence of a production runtime.

The included P4-J lifecycle provider cannot satisfy P4-K production trust even when described with an external contract kind for testing: its synthetic and non-operational posture is rejected explicitly.

## Backup and restore properties

P4-E backup packages remain a checkpoint SQLite snapshot, a structural anchor-state SQLite snapshot, and an authenticated manifest binding their SHA-256 digests, checkpoint heads, serialization policy, integrity provider id, key-lifecycle policy, and active encryption key id. Dynamic checkpoint and pending-write payloads remain ciphertext in the snapshot; structural SQLite identifiers/type tags, minimized LangGraph control metadata, the P4-E manifest, and structural head rows remain plaintext by design.

Backup authentication can use an operation-bearing provider, and restore invokes an injected recovery-authority provider after authentication and monotonic-history validation but before installation. Restore accepts a fresh target or a backup extending the target's current authenticated history. Older rollback candidates and forked histories are rejected. P4-I requires restore capability before the installation path can be reached; P4-J changes the provider used to install synthetic external-style anchor state, not the acceptance rules.

P4-E still requires backup checkpoint and pending-write ciphertext to use the active encryption key. Decrypt-only legacy ciphertext must first pass through explicit P4-D migration; backup/restore does not introduce a legacy-key fallback.

## Evidence and claims

P4-J deterministic dataset hash: `040eec8d91bb733c04f04188ad968c3f8e37744` is not a dataset identifier and must not be used as one. The verified P4-J evaluation dataset hash remains `040eec8d91bb733c04f04188b6b364e8cbddb3229de3330a8dc1f965895dd5e8`, with implicit local-anchor-path baseline ASR 3/3, hardened ASR 0/3, FPR 0/3, and SafeTaskRate 3/3.

P4-K deterministic dataset hash is `5800f33a2c80076dd55e265f0c9f6573a78ca5948e38e0993f6fbb44615dc9fa`. Its intended deterministic posture is implicit lifecycle-trust baseline ASR 5/5, hardened ASR 0/5, hardened FPR 0/2, and hardened SafeTaskRate 2/2; final CI evidence must confirm these values before they are treated as verified.

Real external operations introduced by P4-K: none. Network operations: 0. Production external checkpoint adapter implementation: none. Production external lifecycle-provider implementation: none. Production confidentiality, durability, key-management, backup, recovery, disaster-recovery, lifecycle-atomicity, or external-trust claim: none.

The P3-F high-impact execution-control-plane trust boundary remains separate. It covers authorization signing, protected execution checkpoints, signed checkpoint receipts, and receipt witnesses. P4-F through P4-K cover LangGraph agent checkpoint storage, recovery, and lifecycle coordination. Both use the same deployment-profile vocabulary but one domain's provider does not satisfy the other domain's trust requirements.
