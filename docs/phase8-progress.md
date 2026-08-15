# Phase 8 progress — agentic trust, authority, state, execution, autonomy, communications, and concurrency integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A through P8-G established delegation/authority propagation, memory/context boundaries, goal/plan integrity, tool-result/environment integrity, execution-budget security, human approval/autonomy boundaries, and inter-agent message/protocol security. P8-H now addresses state-machine concurrency and race-condition security.

## P8-A through P8-G

P8-A through P8-G are complete for the current deterministic synthetic-lab scope. Their evidence establishes original-principal authority, state provenance, instruction/goal integrity, exact tool-result binding, bounded resource consumption, evidence-bound human approval, and provenance-preserving inter-agent messaging.

## P8-H — agent state-machine, concurrency, and race-condition security

Status: **implemented and deterministically exercised in an isolated P8-H harness; hosted runner execution pending infrastructure**.

P8-H adds `AgentStateMachineSecurityAnalyzer`. The analyzer treats concurrency state as security evidence: expected versions, expected state hashes, idempotency keys, lease ownership/expiry, approval state at use time, tool-side-effect observations, cancellation ordering, rollback conflicts, and the derived final state all matter even when each individual message or approval is authorized.

The canonical fixture contains **6 state objects, 1 lease, and 8 state transitions**. It models a tenant ticket, release slot, telemetry config, authorization policy, task lifecycle, and memory metadata. The clean path includes two ordered ticket writes, an idempotency-protected irreversible release commit, a lease-protected telemetry mutation, a serializable policy mutation, a memory update, a task read, and task cancellation.

The hardened boundary enforces:

- exact graph ID/version/SHA-256 and freshness;
- exact P8-D tool-observation, P8-F human-approval, and P8-G message evidence binding;
- exact state-object, lease, and transition coverage;
- policy-pinned initial object type, tenant, version, and state digest;
- allowed transition intents and concurrency-control modes per object;
- message actor/tenant safety at transition use time;
- approval-to-use binding against the actual current object version/state digest;
- tool-observation safety for side-effecting objects;
- duplicate side-effect evidence detection;
- expected-version and expected-state compare-and-swap checks;
- monotonic versioning and lost-update detection;
- competing writers against one expected version;
- idempotency-key replay and same-key/different-request detection;
- mandatory idempotency evidence for irreversible objects;
- exact lease object/owner/expiry checks;
- cancellation vs. later execution races;
- forward vs. rollback races; and
- rejection of caller-provided denied/risk/final-version summaries that disagree with the derived state machine.

### Deterministic evidence

A local isolated P8-H harness passed **15 tests** and completed **104 adversarial cases**:

- vulnerable ASR: **104/104**;
- hardened ASR: **0/104**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- state-transition graph SHA-256: `6c6c6a3666e178b92d2ee9a28a1e55cb69f42c7eed5b828cc9efd7a10f1f3ee0`;
- adversarial dataset SHA-256: `e796e8104400697c37c82614ea36ffe00810ef9cfd84b23d59d965b125b188e1`;
- fixture SHA-256: `e659799632a94f7028d9b0a8d20b8ade5c283e1cbe1806bd0df328498ae4a01b`;
- clean assessment SHA-256: `43aa4d80e2b9d7aa885b4650e5669712c70c7b0858e2322c413c25a8afb4e9e0`.

The analyzer, vulnerable baseline, and fixture Git blobs were checked against the locally exercised files. Evaluator/test behavior was exercised in the isolated harness; this is not a claim that full-repository pytest ran locally or that production database/locking systems were exercised.

### Free/open-source implementation path

No new runtime dependency was added. P8-H documents optional free/open-source integration paths:

- **etcd (Apache-2.0):** atomic transactions with compare/success/failure semantics plus leases; useful for version-checked distributed coordination. etcd's concurrency guidance reinforces that lease expiry alone is not enough if an old holder can still run, so P8-H keeps explicit version/state checks.
- **PostgreSQL (PostgreSQL License):** Serializable transactions and explicit row locking provide strong options when the authoritative state can live in one transactional database.
- **Valkey (BSD-3-Clause):** `MULTI`/`EXEC` plus `WATCH` optimistic locking map directly to expected-version/CAS-style state updates.
- **Temporal Server (MIT):** durable workflow execution is a useful future substrate for retry/cancellation/idempotency mechanics, while P8-H retains security-specific approval, state, and side-effect checks.

These are optional integration paths, not dependencies or executed evidence sources.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: complete for current deterministic synthetic scope.
- P8-D: complete for current deterministic synthetic scope.
- P8-E: complete for current deterministic synthetic scope.
- P8-F: complete for current deterministic synthetic scope.
- P8-G: complete for current deterministic synthetic scope.
- P8-H: implemented with isolated deterministic evidence; hosted execution remains infrastructure-blocked.

## Next direction

P8-I should broaden into **agent artifact, workspace, and generated-code integrity**: provenance and trust of generated files/patches, path/scope confinement, symlink/archive traversal, build-context poisoning, dependency-manifest mutation, executable artifact approval, and preventing an agent from turning a permitted write into code execution or supply-chain persistence.
