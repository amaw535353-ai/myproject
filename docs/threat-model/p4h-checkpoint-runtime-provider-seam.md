# P4-H checkpoint runtime operation-provider seam

## Scope

P4-H moves the LangGraph agent checkpoint runtime from direct raw local integrity/backup key use and direct checkpoint-head SQL in the default composition to operation-bearing provider contracts. It covers checkpoint/write authentication, monotonic checkpoint and write-set heads, backup-manifest authentication, and restore authorization. Checkpoint encryption remains the P4-D provider boundary.

This repository still supplies only synthetic in-process implementations. P4-H is an adapter seam and fail-closed composition exercise, not an external KMS, HSM, rollback-resistant store, backup service, or recovery-control implementation.

## Security properties

The default `OperationProviderKeyLifecycleCheckpointer` authenticates checkpoint rows and pending writes by calling an injected integrity provider's `authenticate` and `verify` operations. It reads and advances current checkpoint heads and pending-write aggregate heads through an injected anchor provider. The default saver discards the superclass compatibility HMAC value after initialization and does not retain the P4-B raw integrity key as its runtime authenticator.

The P4-E manager can authenticate backup manifests through an injected backup-authentication provider. Restore verifies the package and monotonic recovery boundary first, then calls an injected recovery-authority provider before installing checkpoint or anchor state. A recovery-authority denial therefore fails closed before the attached-SQLite replacement.

The local operation-provider factory inherits the existing P4-F local trust manifest. The manifest is still checked before default checkpoint composition. A `production_external_required` profile therefore continues to reject the local synthetic providers rather than silently treating operation-bearing local doubles as production trust.

P4-H also demonstrates that the actual checkpoint saver can use the P4-G integrity operation contract and P4-G checkpoint-head compare-and-advance contract. The P4-G anchor bridge adds only synthetic in-process pending-write-head storage needed by the real saver. This is contract interoperability evidence, not evidence of an operationally external provider.

## Threats exercised

The deterministic P4-H evaluation covers persisted checkpoint tampering when integrity decisions are delegated to an operation provider, checkpoint-database rollback while a provider-owned monotonic head remains newer, authenticated-backup manifest tampering, and restore attempts by an unauthorized synthetic recovery operator. Benign cases exercise actual saver round-trip through P4-G-style integrity and anchor operations, authenticated and authorized restore, and the default local operation-provider checkpoint/write path.

## Trust and compatibility limitations

The local providers hold fixture key material inside the same Python process. Moving default composition from raw material to operations reduces key propagation and establishes a substitutable contract, but does not create external custody or an independent failure domain. A process compromise can still invoke the local providers. The inherited `LocalSyntheticCheckpointTrustProviderFactory` also retains legacy raw-material compatibility helpers; P4-H stops the default API from calling them but does not remove those compatibility APIs globally.

`OperationProviderKeyLifecycleCheckpointer` subclasses the P4-D saver to preserve P4-A through P4-G behavior. Its superclass setup still creates the configured local anchor SQLite schema. With the default local anchor provider, that is the provider-owned anchor database itself. With the synthetic P4-G external-style anchor harness, the compatibility SQLite file may exist even though core P4-H head operations do not consult it. P4-H therefore does not claim complete removal of local anchor artifacts.

P4-D re-encryption migration remains implemented with attached local SQLite anchor semantics. It is coherent for the default P4-H local anchor provider because that provider owns the same configured SQLite path, but P4-H does not claim migration support when an anchor provider is operationally external or lacks the same local database representation.

P4-E backup/restore likewise remains a local snapshot-capable recovery implementation. Provider-aware backup creation can snapshot an anchor provider that exposes the local snapshot capability. Restore can install state only when the provider exposes a local database path compatible with the attached-SQLite transaction. Providers without those capabilities are not treated as supported external recovery implementations. No fallback copies state into an unrelated local anchor and calls that equivalent external recovery.

The P4-G backup and recovery doubles can drive P4-E authentication and authorization operations, but P4-H does not claim that the P4-G in-memory anchor can be backed up, restored, migrated, or coordinated atomically with checkpoint SQLite state.

## Evidence hygiene and non-claims

All keys, operators, checkpoint contents, and databases used in tests/evaluations are synthetic and local. No network operation, real secret, real external trust operation, cloud resource, IAM change, or production recovery operation is introduced. Reports expose provider identifiers, typed rejection reasons, counts, and boolean posture fields rather than raw key bytes or checkpoint state.

P4-H makes no production confidentiality, durability, key-management, rollback-resistance, backup, recovery, disaster-recovery, or external-trust claim. A real deployment would additionally require externally custodied keys, independent rollback-resistant state, authenticated operational identity, provider availability/error semantics, distributed concurrency controls, externally coordinated migration and snapshot/restore, auditability, and recovery runbooks.

## Next boundary

P4-I should make migration, snapshot, and restore capabilities explicit operation-provider contracts so unsupported provider combinations fail closed before lifecycle or recovery work begins, without assuming a local SQLite anchor representation.
