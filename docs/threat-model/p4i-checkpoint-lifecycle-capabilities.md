# P4-I checkpoint lifecycle capability-provider boundary

## Scope

P4-I narrows the P4-D migration and P4-E backup/restore assumptions for the LangGraph agent-checkpoint domain. The default checkpoint runtime now binds those lifecycle operations to an explicit provider associated with the configured monotonic-anchor provider. The repository still uses only synthetic, local implementations; this milestone does not add an operationally external provider or a production recovery claim.

The P3-F protected execution-checkpoint trust domain remains separate. P4-I applies only to the P4-A through P4-H LangGraph checkpoint persistence and recovery path.

## Security property

A checkpoint runtime must not infer migration, pair-snapshot, or pair-restore capability merely because a compatibility SQLite path exists. Before a lifecycle operation begins, the runtime requires a provider that explicitly advertises the requested capability and is bound to the same anchor-provider identity. Missing capability or an anchor-provider mismatch fails closed before the lifecycle operation changes checkpoint state.

The explicit P4-I capabilities are:

- `checkpoint_encryption_migration`
- `checkpoint_backup_snapshot`
- `checkpoint_backup_restore`

The default local provider is `local-sqlite-agent-checkpoint-lifecycle`, bound to the default `local-sqlite-agent-checkpoint-anchor`. The API composition injects that provider explicitly. A local SQLite anchor supplied directly to the P4-H saver also receives the same local capability provider for backward-compatible lab composition. A synthetic external-style P4-G anchor does not receive an implicit local lifecycle provider.

## Local operation semantics

The local migration capability delegates the existing P4-D re-encryption migration only after the lifecycle provider verifies that the saver is bound to the same local anchor object and database path. P4-H integrity operations therefore remain provider-routed while the P4-D local attached-SQLite migration transaction remains the implementation used by this synthetic provider.

The local snapshot capability takes the checkpoint and anchor SQLite snapshots while the saver lock is held. The local restore capability performs the existing attached-SQLite replacement transaction only after package authentication, internal checkpoint verification, monotonic restore-boundary validation, and P4-H recovery authorization have succeeded. P4-E backup creation checks snapshot capability before creating the backup directory, and P4-E restore checks restore capability before attempting installation.

These semantics are a single-process local-lab coordination boundary. They do not prove atomic snapshot or cutover across independently writing processes, distributed stores, cloud backup systems, or external anchor services.

## Fail-closed cases

P4-I rejects:

- migration when no lifecycle provider advertises migration;
- backup snapshot when no lifecycle provider advertises snapshot;
- restore when no lifecycle provider advertises restore;
- a lifecycle provider whose declared anchor-provider identity differs from the runtime anchor provider;
- a locally bound lifecycle provider attached to a different anchor-provider object or database path.

The core P4-H checkpoint get/put path can still operate with the synthetic P4-G external-style anchor contract. P4-I deliberately blocks only lifecycle operations that the injected provider cannot supply. It does not silently fall back to the saver's compatibility local anchor file.

## Trust and evidence limits

All P4-I operations remain local and synthetic. The local lifecycle provider uses local SQLite files and in-process locks, has no independent failure domain, performs no network operations, and introduces no real credentials. The existing compatibility anchor artifact may still be initialized by the inherited saver when a synthetic external-style anchor is used, but P4-I does not treat that artifact as authority for migration, snapshot, or restore.

P4-I does not provide KMS/HSM custody, an external rollback-resistant lifecycle coordinator, distributed locking, multiprocess snapshot atomicity, cross-region backup, secure deletion, production key migration, disaster-recovery orchestration, or active runtime cutover. An operational external anchor would need an operational lifecycle provider with explicit semantics for the required operation before this repository could make a stronger claim.
