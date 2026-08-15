# Phase 8 progress — agentic trust, delegation, state, goal, and observation integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A established delegation and authority propagation, P8-B added stateful memory/context boundaries, P8-C protected goal/plan/instruction integrity, and P8-D now protects the evidence boundary between a tool invocation, its result, the resulting environment state, and the observation admitted back into the agent loop.

## P8-A — multi-agent delegation and authority propagation

Status: **complete for the current deterministic synthetic-lab scope**.

P8-A binds multi-agent delegation to original-principal authority, tenant/provenance continuity, capability non-amplification, P7-B privilege evidence, P7-H control-plane routes, and P7-I invariants. Repository evaluator evidence: vulnerable ASR 90/90, hardened ASR 0/90, FPR 0/3, SafeTaskRate 3/3.

## P8-B — agent memory and context-boundary security

Status: **complete for the current deterministic synthetic-lab scope**.

P8-B models session, tenant, and system memory as explicit security boundaries with delegated writes, provenance, trust/classification transitions, poisoning persistence, retrieval-time trust derivation, tenant/session isolation, and revocation/expiry/supersession. Repository evaluator evidence: vulnerable ASR 126/126, hardened ASR 0/126, FPR 0/3, SafeTaskRate 3/3.

## P8-C — agent goal, plan, and instruction-integrity security

Status: **complete for the current deterministic synthetic-lab scope**.

P8-C protects trusted goal provenance, instruction precedence, delegated-goal continuity, plan-step and mutation authorization, memory/tool instruction laundering, termination boundaries, rollback requirements, and P8-A/P8-B/P7-I evidence binding. Repository evaluator evidence: vulnerable ASR 133/133, hardened ASR 0/133, FPR 0/3, SafeTaskRate 3/3.

## P8-D — agent tool-result, observation, and environment-integrity security

Status: **implemented and deterministically exercised in an isolated API-compatible harness; hosted runner execution pending infrastructure**.

P8-D adds `AgentToolObservationIntegrityAnalyzer`. A successful tool call is not treated as proof that the result is fresh, belongs to the current invocation, reflects the real environment, or is authoritative enough to steer future agent state.

The canonical fixture contains:

- tool contracts: **4**;
- environment snapshots: **6**;
- invocations: **4**;
- results: **4**;
- admitted observations: **4**.

The fixture covers tenant search, tenant ticket mutation, irreversible release deployment, and security telemetry mutation.

The hardened boundary enforces:

- exact tool-observation graph ID/version/SHA-256 and freshness;
- exact P8-A delegation, P8-C goal/plan, and P7-I invariant evidence digests and verification flags;
- exact contract/snapshot/invocation/result/observation coverage;
- trusted owners for every evidence object;
- policy-pinned tool tenant scope, effect class, authoritative-result flag, result lifetime, side-effect acknowledgement requirement, and required P7-I invariants;
- policy-pinned environment snapshot tenant, version, and SHA-256 state digest;
- exact invocation → result binding by invocation ID, tool ID, and argument digest;
- original-principal, tenant, task, goal, and plan-step continuity through the final observation;
- result production/expiry timing and tool-specific freshness bounds;
- result-nonce replay detection;
- no environment-version regression below the invocation pre-state;
- exact observed environment version/state agreement across result, snapshot, and observation;
- acknowledgement integrity for mutating and irreversible actions;
- denial when the related P8-A delegation, P8-C step, or required P7-I invariant is unsafe;
- `VERIFIED` observation trust only when the tool contract permits authoritative results, an allowlisted attestation digest is present, and no other integrity risk exists; and
- rejection of caller-declared denial/risk maps that disagree with evidence-derived results.

### Deterministic evidence

The clean fixture produces **4/4 allowed observations** and no integrity risks.

The repository evaluator contains **208 adversarial cases** plus three truthful benign/denial contexts. An isolated API-compatible harness compiled the standalone P8-D implementation/evaluator/test files, passed **18 P8-D pytest tests**, and completed the deterministic evaluator:

- vulnerable ASR: **208/208**;
- hardened ASR: **0/208**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- tool-observation graph SHA-256: `1542df3c4f06744f5cb1ad26024e5e4bdac1b4a0d31379944c207ee3e3020ada`;
- adversarial dataset SHA-256: `24a0f4c3c864f95dbba2faaec65015fc5b6868165bcd43b930bcc58d4b32c1f6`;
- fixture SHA-256: `1f9b05b6f02d2ec640c2630debc28de45602714992ec58aad63a2d5c93600abb`;
- clean assessment SHA-256: `add8a12a1fb6c4d3aa3d23b0159c81135dda418a35cfeb9d18dc886f26eddd31`.

Representative truthful unsafe states include duplicate result nonces (`REPLAY_RESULT`), expired tool output (`STALE_RESULT`), missing mutation acknowledgement (`SIDE_EFFECT_UNACKNOWLEDGED`), spoofed environment state (`ENVIRONMENT_STATE_SPOOF`), an upstream denied plan step (`UPSTREAM_PLAN_UNSAFE`), and an unattested search observation attempting to become `VERIFIED` authority (`OBSERVATION_LAUNDERING`).

The isolated harness uses API-compatible P8-A/P8-C/P7-I evidence interfaces. This is not a claim that full-repository pytest ran locally or that production tool runtimes were exercised.

P8-D does not claim production tool-runtime interception, production environment attestation, cryptographic verification of external tool results, semantic proof that tool output is truthful/safe, distributed transaction correctness, real rollback execution, exhaustive environment-state coverage, live tenant data isolation, or networked enforcement.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: complete for current deterministic synthetic scope.
- P8-D: implemented with deterministic local evidence; hosted workflow execution remains subject to the existing GitHub account runner-provisioning condition.

## Next direction

P8-E should broaden into **agent budget, resource, and runaway-execution security**: bounded tool/model call budgets, recursion and fan-out limits, cost/latency ceilings, delegated-budget non-amplification, retry-storm and loop detection, irreversible-action rate limits, and protection against an attacker converting valid goals into resource-exhaustion or denial-of-wallet behavior without violating nominal tool permissions.
