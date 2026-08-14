# P4-K checkpoint lifecycle deployment trust boundary

## Scope

P4-K extends the checkpoint deployment trust model to the coordinator that performs P4-I encryption migration, pair snapshot, and pair restore. It does not replace the five-surface P4-F policy. Instead, production checkpoint composition must satisfy both the unchanged P4-F v1 manifest and a P4-K lifecycle-provider descriptor.

This separation preserves the deterministic P4-F evidence and makes the new trust dependency explicit without retroactively redefining the original five storage/recovery surfaces.

## Security property

A checkpoint deployment must not infer lifecycle authority merely because an anchor, backup authenticator, recovery authority, or lifecycle-shaped object exists. The lifecycle coordinator must be explicitly described, bound to the configured monotonic-anchor provider identity, and advertise all three lifecycle capabilities.

For `local_synthetic`, the existing local provider remains permitted. For `production_external_required`, the lifecycle provider descriptor must additionally be external, independently operated, non-synthetic, operationally external, and production-runtime eligible.

The required lifecycle capabilities are:

- `checkpoint_encryption_migration`
- `checkpoint_backup_snapshot`
- `checkpoint_backup_restore`

## Composition boundary

`LifecycleAwareCheckpointTrustManifest` wraps the existing P4-F manifest used by the default operation-provider factory. It preserves the original P4-F `providers` tuple and P4-F policy version while routing `assert_allowed()` through the combined P4-F + P4-K deployment check.

The default API therefore continues to call the same trust-manifest assertion before creating checkpoint persistence state, but that assertion now covers the explicit local lifecycle descriptor as well as the five P4-F trust surfaces.

The default lifecycle descriptor is:

- provider: `local-sqlite-agent-checkpoint-lifecycle`
- anchor provider: `local-sqlite-agent-checkpoint-anchor`
- kind: local synthetic
- independent failure domain: false
- synthetic in process: true
- operationally external: false
- production-runtime eligible: false
- capabilities: migration, snapshot, restore

It remains valid for the lab profile and cannot make a production lifecycle trust claim.

## Synthetic external-style P4-J provider

P4-J proves lifecycle operations can be routed through an external-style anchor bridge without depending on the compatibility SQLite anchor path. P4-K deliberately does not reinterpret that harness as external deployment trust.

When the P4-J lifecycle provider is described with an external contract kind for posture testing, it is still rejected under `production_external_required` because the implementation is synthetic in-process, not operationally external, and not production-runtime eligible.

## Contract-shape fixture

The deterministic P4-K evaluation also includes a complete external lifecycle descriptor bound to the P4-G external-style anchor descriptor. That fixture passes the production policy shape only. It is metadata used to exercise validation logic; there is no operational lifecycle service behind it.

Passing the descriptor policy therefore does not establish external custody, service independence, distributed atomicity, crash consistency, multiprocess fencing, disaster-recovery readiness, or production eligibility for the repository runtime.

## Adversarial cases

P4-K evaluates five deployment-trust failures:

1. a local lifecycle coordinator paired with production-shaped checkpoint trust;
2. the synthetic P4-J external-style lifecycle provider presented as an external contract;
3. a lifecycle coordinator bound to the wrong monotonic-anchor provider identity;
4. a lifecycle coordinator missing restore capability;
5. an otherwise external-shaped lifecycle coordinator sharing the checkpoint failure domain.

Each fails closed before the lifecycle descriptor is accepted as production deployment trust.

## Residual risk

P4-K is policy and composition hardening, not a production provider implementation. The default lifecycle provider still coordinates local SQLite checkpoint and anchor state in one process. The P4-J provider still combines a local checkpoint database with an in-memory synthetic anchor bridge and compensating state replacement.

No real KMS/HSM, remote anchor ledger, external backup service, recovery quorum, lifecycle orchestration service, network protocol, distributed transaction, or crash-safe cross-service commit is introduced. The repository therefore makes no production checkpoint confidentiality, durability, key-management, backup, recovery, lifecycle-atomicity, disaster-recovery, or external-trust claim.
