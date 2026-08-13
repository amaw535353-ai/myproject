# P2-N threat model: stale authorization replicas and version fencing

## Objective

P2-M proved that a historical human approval is not permanent execution authority: current authorization must still allow the first synthetic effect. P2-N addresses the next failure mode. In a distributed system, a worker can perform an "execution-time" authorization check against a cache or replica that is itself stale and still returns an old allow decision.

P2-N therefore treats a cached authorization decision as evidence, not authority. The side-effecting node accepts that evidence only when its server-generated binding, tenant, policy version, and revocation epoch match the current authoritative version state immediately before the first effect is inserted.

Everything in this milestone is local and synthetic. No real access grant, password reset, account, credential, external authorization service, replica, or network side effect is used.

## Security invariant

For the first execution of an approved synthetic effect:

1. The cached decision must be bound to the exact P2-L outbox record.
2. The decision tenant must equal the bound outbox tenant.
3. The decision revocation epoch must equal the authoritative tenant revocation epoch.
4. The decision policy version must equal the authoritative tenant policy version.
5. The cached authorization decision must be `allowed`.
6. The authoritative version read and first effect insert occur inside the same SQLite `BEGIN IMMEDIATE` transaction.
7. Any freshness failure creates durable terminal denial state before the worker cancels the outbox.

An already-recorded identical idempotent effect is resolved before freshness validation. This preserves the P2-L/P2-M crash-recovery rule: an effect that was validly authorized and committed before a worker crash is not duplicated or stranded merely because authorization changed afterward.

## Trusted state

`AuthorizationVersionStore` owns two monotonic counters per synthetic tenant:

- `revocation_epoch`: advanced for security-sensitive subject/resource changes that can invalidate previously cached authority;
- `policy_version`: advanced when the authorization policy changes.

`VersionedAuthorizationController` updates the corresponding synthetic authorization state and its counter in one local SQLite transaction. P2-N exercises subject disablement as a revocation-epoch change and password-reset policy disablement as a policy-version change.

The authoritative counter table shares the downstream execution database with the synthetic effect ledger. A separate SQLite database represents a deliberately lagging authorization replica. The replica contains the same P2-M authorization schema plus its last observed version counters.

## Cached decision binding

`CachedAuthorizationReplica` evaluates the P2-M authorization rules using only its local replica state and emits a frozen `CachedAuthorizationDecision` containing:

- tenant ID;
- a SHA-256 binding over the server-owned outbox identity and normalized effect payload;
- policy version;
- revocation epoch;
- the replica authorization reason.

The model, user prompt, retrieved content, browser page, tool output, and retry-time caller cannot provide or override these fields. Raw binding material is not emitted in evaluation reports.

## Hardened effect boundary

`VersionFencedSyntheticEffectService` receives the bound outbox record and a server-produced cached decision. Inside one `BEGIN IMMEDIATE` transaction it:

1. returns an already-recorded identical idempotent effect if one exists;
2. rejects conflicting approval/idempotency bindings;
3. honors any existing durable freshness-denial tombstone;
4. verifies tenant and record binding;
5. reads the authoritative tenant version state;
6. requires exact revocation-epoch and policy-version equality;
7. requires the cached decision itself to be `allowed`;
8. inserts the first synthetic effect only if all checks succeed.

A failure is represented by a non-sensitive `AuthorizationFreshnessReason`. `VersionFencedDurableEffectWorker` then marks the P2-M/P2-N outbox terminally `cancelled`. Restoring authority or allowing the replica to catch up later cannot resurrect the already-denied approval.

## Intentionally vulnerable comparison

`aegis/vulnerable/p2n_stale_cache.py` uses the same P2-L idempotent synthetic effect ledger, the same outbox binding, and the same cached authorization decision. It validates the decision's tenant, record binding, and `allowed` result, but intentionally ignores the authoritative policy version and revocation epoch even though those counters are available on the downstream node.

The intended security delta is therefore only the authoritative freshness fence.

## Deterministic adversarial set

### P2N-A1: stale subject-revocation replica

Alice's synthetic access request is legitimately approved and enqueued while both authoritative and replica authorization permit it at revocation epoch 1. The authoritative controller disables Alice and advances the tenant revocation epoch to 2. The deliberately lagging replica remains at epoch 1 and still returns `allowed`.

Expected result:

- vulnerable: first synthetic effect is recorded;
- hardened: `revocation_epoch_mismatch`, zero effects, outbox cancelled;
- hardened restoration check: re-enabling Alice cannot revive the cancelled approval.

### P2N-A2: stale policy-version replica

Alice's synthetic password-reset request is legitimately approved and enqueued while password reset is enabled at policy version 1. The authoritative controller disables password reset and advances the policy version to 2. The lagging replica remains at version 1 and still returns `allowed`.

Expected result:

- vulnerable: first synthetic effect is recorded;
- hardened: `policy_version_mismatch`, zero effects, outbox cancelled.

## Benign set

P2N-B1 uses unchanged, version-current access authorization. P2N-B2 advances the authoritative policy version without changing the effective allow rule, synchronizes the replica version, and verifies the approved password-reset effect still completes exactly once. These cases measure whether the version fence blocks legitimate current authorization.

## Metrics

P2-N reports raw numerators, denominators, and percentages:

- ASR = stale-authorization effects recorded / valid adversarial attempts;
- FPR = version-current benign tasks incorrectly blocked / valid benign tasks;
- SafeTaskRate = version-current benign tasks completed safely / benign tasks attempted.

The target hardened result is ASR 0/2, FPR 0/2, and SafeTaskRate 2/2. The intentionally vulnerable baseline should demonstrate ASR 2/2.

## Evidence hygiene

Evaluation output includes scenario IDs, non-sensitive reason codes, integer policy/revocation versions, effect counts, and terminal outbox state. It excludes approval IDs, idempotency keys, authorization-decision binding hashes, raw authorization rows, raw effect arguments, effect references, credentials, and real external side effects.

## Residual risks and production gap

P2-N is a single-node proof of a distributed authorization-freshness invariant, not a distributed authorization system. Its fence is only correct if every authoritative security mutation advances the required monotonic counter atomically and the effect boundary reads the genuinely authoritative counter. A cache that contains stale data while falsely claiming the current epoch/version is outside this milestone and must be prevented by the production authorization service's consistency and issuance rules.

A production design still needs authoritative version allocation, durable replication semantics, cache invalidation, authenticated decision provenance, tenant-scoped version namespaces, rollback protection, disaster recovery rules, clock-independent expiration where appropriate, and point-of-use enforcement by the real side-effecting service. Multi-region systems also need a clearly specified consistency model for revocation propagation and a failure mode that does not silently convert an unavailable authoritative fence into allow.

The P2-L exactly-once limitation remains: version fencing does not replace downstream idempotency. The real effect service must keep a durable idempotency contract whose retention exceeds plausible replay windows.
