# Phase 8 progress — agentic trust, delegation, state, and goal integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A established delegation and authority propagation. P8-B added stateful memory/context boundaries. P8-C now addresses goal and plan integrity: preserving what was actually authorized after memory, tool output, delegation, and plan mutation begin influencing agent behavior.

## P8-A — multi-agent delegation and authority propagation

Status: **complete for the current deterministic synthetic-lab scope**.

P8-A binds multi-agent delegation to original-principal authority, tenant/provenance continuity, capability non-amplification, P7-B privilege evidence, P7-H control-plane routes, and P7-I invariants. Its repository evaluator contains 90 adversarial cases with the established 90/90 vulnerable ASR, 0/90 hardened ASR, 0/3 FPR, and 3/3 SafeTaskRate evidence.

## P8-B — agent memory and context-boundary security

Status: **complete for the current deterministic synthetic-lab scope**.

P8-B models session, tenant, and system memory as explicit security boundaries with trusted writers/readers, tenant/session isolation, delegated writes, provenance chains, trust/classification transitions, sanitization evidence, poisoning persistence, retrieval-time trust derivation, and revocation/expiry/supersession. Its repository evaluator contains 126 adversarial cases and the established 126/126 vulnerable ASR, 0/126 hardened ASR, 0/3 FPR, and 3/3 SafeTaskRate evidence.

## P8-C — agent goal, plan, and instruction-integrity security

Status: **implemented and deterministically exercised in an isolated API-compatible harness; hosted runner execution pending infrastructure**.

P8-C adds `AgentGoalPlanIntegrityAnalyzer`. It treats the goal and plan themselves as security-sensitive state rather than assuming that tool-level authorization is enough.

The canonical fixture contains:

- goals: **5**;
- instructions: **9**;
- plan steps: **7**;
- plan mutations: **2**.

The fixture spans tenant retrieval, delegated tool access, release inspection/deployment with rollback, and telemetry administration with rollback.

The hardened boundary enforces:

- exact goal/plan graph ID/version/SHA-256 and freshness;
- exact P8-A, P8-B, and P7-I evidence digests and verification flags;
- exact instruction/goal/step/mutation coverage;
- policy-pinned instruction source, directive, trust, precedence, and allowed actions;
- acyclic instruction provenance with chained SHA-256 evidence;
- allowlisted evidence before an instruction may gain trust or precedence;
- policy-pinned goal root instruction, original principal, tenant/session, delegation, action scope, and step bound;
- delegated-goal continuity against the exact P8-A delegation decision/principal/tenant/capabilities;
- plan-step action scope constrained by the root goal rather than low-authority memory/tool context;
- exact action-to-capability and action-to-P7-I-invariant requirements;
- referenced P8-B memory retrievals must remain allowed and in the same tenant/session context;
- memory/tool/external instructions cannot launder themselves into higher-authority plan changes;
- plan mutations require trusted actors and source instructions at least as authoritative as the root goal;
- contiguous bounded plan sequences;
- policy-owned irreversible action classification;
- mandatory later rollback steps for irreversible actions;
- high-precedence termination instructions block later plan execution; and
- caller-declared denied steps/mutations, unsafe goals, and maximum risk cannot override evidence-derived results.

### Deterministic evidence

The clean fixture produces:

- safe goals: **5/5**;
- allowed steps: **7/7**;
- allowed plan mutations: **2/2**;
- maximum integrity risk: **0**.

The repository evaluator contains **133 adversarial cases** plus three truthful benign/denial contexts. An isolated API-compatible harness compiled the exact standalone P8-C implementation/evaluator/test files, passed **18 P8-C pytest tests**, and completed the deterministic evaluator:

- vulnerable ASR: **133/133**;
- hardened ASR: **0/133**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- goal/plan graph SHA-256: `4ffef28407a47d9a7d2ba3a6cdba49b96f6222e8fcfb0f4e7fa995dc979907de`;
- adversarial dataset SHA-256: `cc53112d1512ede5ee2c347b789f41931d91a6f923fc1a1befc1d3d0e15f97c5`;
- fixture SHA-256: `ba57043fa13a50eb38222e8a52625ecb6622df68a8d171a7e7fafd89348f7079`.

The harness uses API-compatible P8-A/P8-B/P7-I evidence interfaces. This is not a claim that full-repository pytest ran locally or that production agent runtimes executed these controls.

Representative truthful states include a release action moved beyond a system termination boundary (one denied step, risk 96) and a tool action whose required P7-I invariant is violated (one denied step, risk 76). Memory-derived context remains usable for an already-authorized retrieval action, but cannot expand that root goal into a privileged tool action.

P8-C does not claim production agent-runtime enforcement, production prompt interception, semantic proof of intent, arbitrary-agent behavioral guarantees, exhaustive goal-hijack coverage, formal plan correctness, real rollback execution, or networked enforcement.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: implemented with deterministic local evidence; hosted workflow execution remains subject to the existing GitHub account runner-provisioning condition.

## Next direction

P8-D should broaden into **agent tool-result, observation, and environment-integrity security**: bind tool outputs to the exact invocation/request, authenticate observation origin, detect replay/stale results, constrain side-effect acknowledgements, prevent environment-state spoofing, preserve tenant/task provenance across observations, and stop malicious tool output from becoming authoritative state simply because execution succeeded.
