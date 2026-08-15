# P8-H threat model — agent state-machine, concurrency, and race-condition security

## Scope

P8-H models security failures that appear only when individually authorized agent operations race, retry, replay, or consume stale state. It treats state version, state digest, idempotency, leases, approval-to-use binding, tool-side-effect evidence, cancellation, and rollback ordering as security evidence.

The milestone is deterministic and synthetic. It does not open a database transaction, acquire a production distributed lock, execute a real tool twice, or claim exactly-once delivery.

## Security objective

An agent transition must not become safe merely because its message, approval, and tool observation were independently authorized. The transition must also be valid against the exact state at use time and against competing transitions that can compose into lost updates, duplicate irreversible actions, cancellation races, or TOCTOU failures.

## Canonical fixture

The fixture contains:

- state objects: **6**;
- lease records: **1**;
- state transitions: **8**.

The state objects model a tenant ticket, model-release slot, telemetry configuration, authorization policy, task lifecycle, and tenant memory metadata. The clean sequence contains two ordered ticket updates, one idempotency-protected irreversible release commit, one lease-protected telemetry update, one serializable policy update, one memory update, a task read, and a later task cancellation.

Clean final versions are:

- ticket: **10 → 12**;
- release: **42 → 43**;
- telemetry: **7 → 8**;
- policy: **12 → 13**;
- task: **3 → 4**;
- memory: **5 → 6**.

## Hardened properties

`AgentStateMachineSecurityAnalyzer` enforces:

- exact state-transition graph ID/version/SHA-256 and freshness;
- exact P8-D tool-observation, P8-F approval, and P8-G inter-agent message evidence digests and verification flags;
- exact object/lease/transition coverage and trusted evidence owners;
- policy-pinned initial object type, tenant, version, and state SHA-256;
- policy-pinned transition intents and concurrency-control modes per object;
- exact message safety and actor/tenant continuity at transition use time;
- exact P8-F approval state for approval-required objects;
- approval-to-use binding to the current state version and state digest, detecting state changes after approval;
- exact P8-D tool-observation safety for objects whose mutations have side effects;
- duplicate reuse of one side-effect observation across multiple transitions;
- expected-version and expected-state checks before every mutating transition;
- monotonic version transitions;
- concurrent-writer detection when multiple transitions target the same object version;
- stale-write and lost-update derivation;
- idempotency-key replay detection and same-key/different-request rejection;
- mandatory idempotency evidence for irreversible state transitions;
- lease presence, object binding, owner binding, and expiry at commit time;
- cancellation winning over later execution unless the later action is an explicit rollback;
- forward/rollback conflicts against the same state version;
- deterministic application of only allowed transitions to derived final state; and
- rejection of caller-declared denied transitions, risks, or final versions that disagree with derived evidence.

## Threats addressed

### Duplicate execution and denial of exactly-once assumptions

An idempotency key is bound to the semantic transition request. Replaying the same transition is surfaced as duplicate execution; reusing the same key for different semantics is a stronger mismatch. Irreversible replays are classified separately.

### Lost update / stale compare-and-swap

A transition cannot write against a version or state digest that is no longer current. Multiple writers targeting the same expected version are surfaced as a concurrency conflict even when each writer is independently authorized.

### Approval-to-use TOCTOU

Human approval is not treated as timeless authorization. For approval-required objects the transition binds the approval to the object version and state digest used at execution. If state changes after approval, the transition is denied as an approval-to-use race.

### Lease expiry and ownership races

Lease-protected transitions require a lease for the exact object, owned by the acting agent and valid at commit time. A syntactically valid but expired, mis-owned, or object-mismatched lease is not accepted.

### Cancellation and execution race

Once a task cancellation transition has been safely applied, a later ordinary execution/mutation cannot revive the task. Rollback remains explicit and separately race-checked.

### Duplicate side effects

A single P8-D observation cannot be used as evidence for multiple mutating transitions. This prevents a retry from claiming that an already-observed side effect proves a second commit is safe.

## Intentionally vulnerable baseline

`VulnerableDeclaredStateSafety` trusts caller-owned declarations that execution happened once, state was fresh, no race existed, and conflict count is zero. It does not derive current state, check expected versions, bind approval to state-at-use, validate leases, inspect idempotency semantics, or correlate tool side effects.

## Deterministic evidence

A local isolated P8-H harness exercising the standalone analyzer/fixture/evaluator/test design passed **15 tests** and completed **104 adversarial cases**:

- vulnerable ASR: **104/104**;
- hardened ASR: **0/104**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- state-transition graph SHA-256: `6c6c6a3666e178b92d2ee9a28a1e55cb69f42c7eed5b828cc9efd7a10f1f3ee0`;
- adversarial dataset SHA-256: `e796e8104400697c37c82614ea36ffe00810ef9cfd84b23d59d965b125b188e1`;
- fixture SHA-256: `e659799632a94f7028d9b0a8d20b8ade5c283e1cbe1806bd0df328498ae4a01b`;
- clean assessment SHA-256: `43aa4d80e2b9d7aa885b4650e5669712c70c7b0858e2322c413c25a8afb4e9e0`.

The analyzer, vulnerable baseline, and fixture Git blobs were checked against the locally exercised files. The evaluator/tests use the same API-compatible logic, but this is still isolated validation rather than a full-repository pytest claim.

## Free/open-source integration paths

P8-H adds no runtime dependency. The following free/open-source systems were reviewed as optional future enforcement points:

- **etcd (Apache-2.0):** its v3 API provides atomic `Txn` compare/success/failure operations and leases. etcd documentation also warns that lease expiry alone is not sufficient for mutual exclusion when old holders may still run, which aligns with P8-H's explicit version/state validation in addition to lease checks.
- **PostgreSQL (PostgreSQL License):** Serializable isolation is designed so committed concurrent transactions have an effect consistent with some serial order, and PostgreSQL exposes row-level locking when explicit conflict coordination is appropriate. It is a strong candidate for authoritative state transitions that can live in one transactional database.
- **Valkey (BSD-3-Clause):** `MULTI`/`EXEC` transactions serialize queued commands, while `WATCH` provides optimistic check-and-set behavior that aborts if watched keys change before `EXEC`. This maps well to P8-H expected-version/CAS semantics for lightweight state.
- **Temporal Server (MIT):** an open-source durable-execution engine suitable for future workflow-level retry/cancellation/idempotency integration. P8-H would still keep security-specific state, approval, side-effect, and authorization checks explicit rather than assuming durable execution alone prevents unsafe retries.

These are optional integration paths only. None is added as a dependency or treated as executed evidence in P8-H.

## Claim boundary

P8-H can claim deterministic synthetic state-transition/concurrency analysis with expected-version/state checks, idempotency semantics, lease checks, cancellation/rollback races, approval-to-use TOCTOU reasoning, duplicate-side-effect detection, and exact P8-D/P8-F/P8-G evidence binding.

P8-H does **not** claim production database transaction enforcement, production distributed locks, exactly-once execution, real serializability across services, real CPU/thread/process scheduling behavior, production lease safety, real rollback correctness, formal serializability proof, exhaustive race-condition coverage, or networked remediation.
