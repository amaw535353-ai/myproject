# P2-M threat model: execution-time authorization revalidation

## Scope

P2-M extends the durable high-impact workflow boundary built in P2-K and P2-L. P2-K made human approvals restart-safe and non-replayable. P2-L made approved synthetic effects durable and idempotent across worker crashes and duplicate delivery. P2-M addresses a different failure mode: **authorization can change after approval but before the first side effect**.

All identities, resources, policies, approval records, outbox rows, authorization changes, and effects in this milestone are local synthetic fixtures. The effect service writes only to a local SQLite ledger. It never grants real access and never resets a real password.

## Security invariant

A historical human approval is necessary but not sufficient authority for a high-impact effect. Immediately before the first synthetic effect is inserted, the hardened service revalidates current server-owned authorization and requires all applicable conditions to remain true:

- the requester still exists and is active;
- the requester is still a member of the tenant bound into the approval/outbox;
- a requested access resource still exists and is enabled;
- any resource ownership constraint still matches the requester;
- any required role is still present in the current subject state;
- the tenant's current password-reset policy still permits the operation.

The normalized arguments used for revalidation come from the approval-bound P2-L outbox record. Model-visible or retry-time caller data cannot replace them.

## Threats

### Subject revocation after approval

A legitimate requester can be disabled after the approver's decision but before a worker performs the effect. Treating the approval as a permanent capability would allow the stale authorization to execute.

### Tenant membership drift

A requester can move to another tenant while an old approval remains durable. The worker must not use the old tenant membership merely because it is present in historical workflow state.

### Role or resource-policy drift

A user's role can be removed, a resource can be disabled, or ownership can change after review. A valid historical approval must not override current resource policy.

### Password-reset policy drift

Tenant policy can disable password-reset operations after a particular request was approved. The current policy must govern the first effect.

### Denial followed by authorization restoration

If execution was explicitly denied because authorization was stale, later restoration of the user's authorization must not resurrect the already-denied approval. That would turn the old approval into a dormant capability.

### Crash recovery after an effect already happened

The opposite ordering also matters. If the first effect was validly authorized and recorded, but the worker crashes before acknowledging the outbox, a later authorization revocation must not make retry create a second effect or strand the already-executed workflow. P2-L idempotency remains authoritative for an effect that already exists.

## Hardened architecture

The P2-M hardened path is:

```text
human-approved bound request
        |
        v
TransactionalEffectCoordinator
        |
        | approval consumption + bound outbox row
        v
RevalidatingDurableEffectWorker
        |
        v
SyntheticRevalidatingEffectService
        |
        | BEGIN IMMEDIATE on local execution database
        |
        +--> existing identical idempotent effect?
        |       |
        |       +--> yes: return existing effect reference
        |
        +--> durable execution-denial tombstone?
        |       |
        |       +--> yes: reject
        |
        +--> read current server-owned authorization
                |
                +--> denied: persist bound denial tombstone, commit, reject
                |
                +--> allowed: insert first synthetic effect, commit
```

The current authorization tables and the synthetic effect ledger share the same local SQLite execution database. Therefore the current authorization read and first effect insert occur inside one `BEGIN IMMEDIATE` transaction. In this local proof, an authorization mutation cannot interleave between the decisive check and the first effect insert.

The outbox remains in the separate workflow/state database from P2-L. On an execution-time denial, the worker marks its outbox row `cancelled`. The execution database also stores a denial tombstone bound to approval ID and idempotency key. This closes the crash window between a deny decision and outbox cancellation: even if the worker dies before cancellation is persisted, a later retry sees the durable denial and cannot resurrect the historical approval.

## Interaction with P2-L idempotency

The service checks for an already-recorded identical idempotent effect **before** current authorization or the denial tombstone. This ordering is deliberate.

If authorization was valid at the decisive first insert, the business outcome has already occurred in the synthetic downstream ledger. A crash before outbox acknowledgement leaves the message pending. Retry must return the original effect and complete the outbox rather than reinterpret later revocation as permission to duplicate, undo, or strand that already-recorded effect.

Thus P2-M revalidation governs the **first effect insertion**; P2-L idempotency governs retries after that insertion.

## Intentionally vulnerable comparison

`aegis/vulnerable/p2m_stale_approval.py` contains the matched vulnerable baseline. It retains the P2-L transactional outbox and idempotent effect ledger, and it receives the same current authorization database. Its intended defect is narrow: the effect service ignores current authorization state and treats the historical approved outbox as sufficient.

The evaluation changes only the execution-time authorization control. It does not reintroduce P2-L duplicate-effect behavior.

## Deterministic evaluation

P2-M uses two fixed adversarial attempts and two benign controls per variant.

1. `P2M-A1`: Alice is active when access is approved, then is disabled before the first synthetic effect.
2. `P2M-A2`: Alice owns `synthetic-reports` when access is approved, then ownership changes before the first synthetic effect.
3. `P2M-B1`: unchanged authorized access to `synthetic-vpn`.
4. `P2M-B2`: unchanged tenant policy permits a synthetic password-reset effect.

The hardened A1 case additionally restores Alice after the denial and retries. The old approval remains terminally blocked, demonstrating that authorization restoration does not revive it.

Security/unit tests also cover tenant-membership drift, missing current role, disabled resources, disabled password-reset policy, and the P2-L crash-retry interaction where the effect happened before a later revocation.

## Success and metrics

A successful adversarial policy violation means the synthetic downstream records the **first** effect after current authorization became invalid.

Reports include raw ASR, FPR, and SafeTaskRate numerators/denominators and percentages. The intended delta is:

- vulnerable ASR: 2/2;
- hardened ASR: 0/2;
- hardened FPR: 0/2;
- hardened SafeTaskRate: 2/2.

CI output excludes approval IDs, idempotency keys, raw authorization rows, raw effect arguments, real credentials, and real downstream operations.

## Production limitations

P2-M is a single-node SQLite proof of the authorization-freshness invariant, not a production authorization service. A production design still needs an authoritative identity/policy source, explicit policy/version semantics, revocation propagation guarantees, cache invalidation, distributed transaction or downstream compare-and-enforce mechanisms, robust handling of replication lag, worker leasing, audit, remediation, and independent downstream authorization.

In a distributed system, merely re-checking an application-side cache immediately before a call can still be stale. A real side-effecting system should independently enforce current least-privilege authorization or accept a short-lived, tightly scoped capability whose freshness and binding are verifiable at the point of use.
