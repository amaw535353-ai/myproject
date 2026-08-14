# P4-J synthetic external checkpoint lifecycle contract harness

## Security boundary

P4-J exercises the three P4-I checkpoint lifecycle capabilities through an external-style, operation-bearing provider without treating the saver compatibility SQLite anchor path as lifecycle authority. The capabilities remain `checkpoint_encryption_migration`, `checkpoint_backup_snapshot`, and `checkpoint_backup_restore`, and the lifecycle provider must be bound to the exact anchor-provider instance and provider identity used by the checkpoint runtime.

The implementation is intentionally a synthetic in-process contract harness. `SyntheticExternalStyleCheckpointLifecycleProvider` is marked `synthetic_in_process=true`, `operationally_external=false`, `production_runtime_eligible=false`, `local_anchor_path_dependency=false`, and `local_anchor_path_exposed=false`. Those fields describe the exercised boundary; they are not evidence of an operational external provider.

## External-style anchor state transfer

P4-J extends the existing P4-G/P4-H synthetic anchor runtime bridge with explicit checkpoint-head and pending-write-head export/import operations. Lifecycle snapshot and restore use those operations rather than reading or writing `saver.anchor_database_path`.

The bridge accesses the synthetic P4-G delegate's in-memory head map directly. That is acceptable only for this deterministic in-process harness. It is not a network protocol, durable external-anchor API, provider SDK, or production storage implementation.

The inherited saver constructor may still initialize a compatibility anchor SQLite artifact because the P4-H saver remains a subclass of the earlier local checkpointer. P4-J does not claim to remove that artifact. Instead, the deterministic evaluation deletes the file after construction and replaces the same path with a directory. Any attempted SQLite use of the compatibility anchor path during migration, snapshot, or restore would then fail. All three P4-J lifecycle operations complete with `compatibility_anchor_path_accesses=0`.

## Migration

The P4-J migration provider validates current checkpoint state through the normal operation-provider saver, then rewrites checkpoint and pending-write ciphertext under the active P4-D encryption key, recomputes checkpoint integrity chains and pending-write authenticators, and publishes the resulting checkpoint/write heads to the bound external-style anchor provider. It does not attach or update the compatibility anchor SQLite database.

The migration evaluation deliberately stages a checkpoint and pending write under the local synthetic P4-D v1 key and migrates both to the local synthetic v2 active key. This proves the lifecycle operation contract and anchor decoupling only. Encryption-key custody remains local synthetic in this scenario; P4-J makes no external key-custody claim.

The checkpoint database transaction and external-style anchor replacement are coordinated only inside one process. If the database operation fails after provider state replacement, the harness restores the previous provider state. This compensation is not a distributed transaction, two-phase commit protocol, fencing mechanism, or crash-consistent guarantee across independent services.

## Pair snapshot

P4-J snapshots the encrypted checkpoint SQLite database and separately exports authoritative head state from the injected anchor provider. To preserve the existing P4-E backup package and validation format, exported provider state is materialized into an `anchors.sqlite3` artifact containing only `checkpoint_heads` and `write_heads` tables.

That SQLite artifact is generated from provider state; it is not copied from the live compatibility anchor path and does not imply that an operational external provider stores its state in SQLite. Dynamic checkpoint and pending-write payloads remain in the encrypted checkpoint snapshot as before. The P4-E authenticated manifest continues to bind both snapshot hashes and checkpoint heads.

## Pair restore

P4-E authentication, active-key validation, candidate checkpoint validation, monotonic rollback/fork checks, and recovery authorization still run before installation. P4-J then loads the provider-state snapshot artifact, replaces the target checkpoint database rows, and imports the checkpoint/write heads into the bound external-style anchor provider. The compatibility anchor path is not used as restore authority.

The restore path retains the existing P4-E fresh-target and authenticated-ancestor semantics. P4-J changes the lifecycle operation boundary, not the backup authentication model, recovery authorization semantics, active-key requirement, or monotonic-history rule.

## Deterministic evaluation

The P4-J dataset contains three local-anchor-path coupling attacks and three matching benign lifecycle tasks:

- migration while the compatibility anchor path is intentionally unusable;
- pair snapshot while the compatibility anchor path is intentionally unusable;
- pair restore while the compatibility anchor path is intentionally unusable.

The implicit local-anchor-path baseline scores ASR 3/3. The external-style lifecycle contract scores ASR 0/3, FPR 0/3, and SafeTaskRate 3/3. The deterministic dataset hash is `040eec8d91bb733c04f04188b6b364e8cbddb3229de3330a8dc1f965895dd5e8`.

Evidence hygiene remains explicit: zero network operations, no real external trust operations, no production external lifecycle provider, no production lifecycle claim, and no external encryption-key custody in the migration exercise.

## Residual risk and non-goals

P4-J does not provide an operational external lifecycle coordinator, independent failure domain, remote rollback-resistant ledger, KMS/HSM integration, external key custody, remote backup storage, multiprocess fencing, distributed snapshot atomicity, distributed restore atomicity, retention policy, disaster-recovery orchestration, or active API cutover.

The saver still uses a local SQLite checkpoint database. The synthetic anchor bridge is in-memory and shares a process with the saver. Lifecycle operations are serialized by the saver lock only; independent processes sharing the same checkpoint database are not coordinated. A process crash between local database and synthetic provider-state changes is outside the guarantees of this harness.

P4-F currently models five agent-checkpoint deployment trust surfaces: encryption-key custody, integrity-key custody, monotonic anchor, backup authentication, and recovery authority. P4-I/P4-J introduce a separate lifecycle coordinator/capability provider but that provider is not yet represented as its own production-required trust surface. The next milestone should close that deployment-trust modeling gap rather than treating the synthetic P4-J provider as production-ready.
