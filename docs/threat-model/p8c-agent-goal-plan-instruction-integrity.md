# P8-C threat model — agent goal, plan, and instruction-integrity security

## Scope

P8-C models goal integrity after an agent has already been authorized to act. It focuses on a failure mode that ordinary tool-permission checks do not prevent: a plan may remain inside nominally permitted tools while its objective, instruction precedence, delegated scope, mutation path, or termination/rollback behavior has been hijacked.

The analysis is deterministic and synthetic. It does not execute agents or tools, intercept production prompts, or claim semantic proof of an agent's real intent.

## Security objective

A caller must not be able to turn unsafe goal or plan state into a green result by declaring that the objective was preserved, instruction precedence remained intact, or no plan steps/mutations should be denied.

The hardened analyzer therefore binds a canonical goal/plan graph to exact P8-A delegation evidence, P8-B memory/retrieval evidence, and P7-I architecture invariants, then derives step and mutation authorization from evidence rather than caller summaries.

## Modeled instruction sources

P8-C distinguishes:

- system policy;
- user goals;
- delegated goals;
- agent-derived instructions;
- memory-derived context;
- tool outputs; and
- external content.

Each instruction carries a policy-pinned source, directive, trust level, precedence, tenant/session/original-principal context, content digest, provenance digest, optional parent instruction, optional P8-B memory retrieval, optional tool-output digest, allowed action classes, and optional approved sanitization evidence.

Low-authority context is allowed to inform a plan but cannot silently become authority. Memory, tool output, or external content therefore cannot expand a root goal's action scope, authorize privileged plan mutations, or acquire stronger trust/precedence without an explicit policy-approved transformation.

## Goal and plan boundaries

Every goal is policy-pinned to:

- a root instruction;
- original principal;
- tenant and session;
- optional P8-A delegation;
- allowed action classes; and
- a maximum plan-step count.

Every plan step is checked against the root goal, exact P8-A delegated capabilities, referenced P8-B memory retrievals, required P7-I invariants, plan sequence, termination state, and rollback requirements.

The canonical fixture contains **5 goals**, **9 instructions**, **7 plan steps**, and **2 plan mutations** spanning tenant retrieval, delegated tool access, release inspection/deployment, and telemetry administration.

## Threats addressed

### Goal hijacking within nominal permissions

A step is denied when its action class exceeds the root goal even if an untrusted memory item or tool output recommends the operation and the downstream agent technically possesses a matching tool capability.

### Instruction laundering

Memory/tool/external context cannot become a higher-precedence instruction merely because another agent rewrites it. Parent instruction provenance is acyclic and digest-bound. Trust or precedence uplift requires allowlisted sanitization evidence.

### Delegated-goal discontinuity

Goals bound to P8-A delegation require the upstream delegation to remain allowed and preserve the original principal, tenant, and delegated capability scope.

### Memory-to-authority escalation

P8-B retrievals may supply contextual information, but a denied, cross-tenant, or cross-session retrieval cannot authorize dependent plan state. Memory-derived instructions remain contextual unless a policy-approved transformation explicitly changes their trust boundary.

### Plan mutation abuse

Plan mutations require trusted mutation agents and a source instruction at least as authoritative as the root goal. Low-authority memory/tool content cannot append, replace, terminate, roll back, or otherwise rewrite a plan as if it were user/system authority.

### Termination bypass

A policy-pinned high-precedence termination instruction blocks later plan execution. Moving a previously valid action after that boundary is explicitly derived as `TERMINATION_BYPASS`.

### Rollback bypass

Irreversible action classes are policy-owned rather than caller-declared. Each such action requires the expected later rollback action. An attacker cannot erase the rollback obligation by flipping a per-step `irreversible` flag.

### Architecture-state dependency

Action classes bind to exact P7-I invariants. A plan step or mutation is denied when a required cross-layer invariant is degraded or violated.

## Intentionally vulnerable baseline

`VulnerableDeclaredGoalPlanSafety` trusts caller declarations that the goal was preserved, instruction precedence is intact, denied step/mutation counts are zero, and maximum risk is zero. It does not bind those claims to instruction provenance, delegation, memory, plan sequence, rollback, termination, or architecture-invariant evidence.

## Deterministic security evidence

The repository evaluator contains **133 adversarial cases** plus three truthful benign/denial contexts. An isolated API-compatible harness compiled the exact standalone P8-C implementation/evaluator/test files, passed **18 P8-C pytest tests**, and completed the deterministic evaluator:

- vulnerable ASR: **133/133**;
- hardened ASR: **0/133**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- goal/plan graph SHA-256: `4ffef28407a47d9a7d2ba3a6cdba49b96f6222e8fcfb0f4e7fa995dc979907de`;
- adversarial dataset SHA-256: `cc53112d1512ede5ee2c347b789f41931d91a6f923fc1a1befc1d3d0e15f97c5`;
- fixture SHA-256: `ba57043fa13a50eb38222e8a52625ecb6622df68a8d171a7e7fafd89348f7079`.

The harness used API-compatible P8-A `VerifiedAgentDelegationAssessment`, P8-B `VerifiedAgentMemoryAssessment`, and P7-I `VerifiedInvariantBlastRadiusAssessment` evidence interfaces. This is not a claim that full-repository pytest ran locally or that production agent runtimes executed these controls.

Representative truthful evidence states include:

- clean canonical plan: **5/5 goals safe**, **7/7 steps allowed**, **2/2 mutations allowed**, maximum risk **0**;
- release step moved beyond a high-precedence stop instruction: one denied step with `TERMINATION_BYPASS`, maximum risk **96**;
- required privileged-tool architecture invariant violated: one denied tool step, maximum risk **76**; and
- memory-derived instruction used to expand the user's root goal: `INSTRUCTION_LAUNDERING`, `MEMORY_INSTRUCTION_ESCALATION`, `GOAL_SCOPE_EXPANSION`, and capability-scope mismatch remain visible as separate evidence.

## Claim boundary

P8-C can claim deterministic synthetic evidence for instruction precedence, goal provenance, delegated-goal continuity, plan-step and mutation authorization, scope non-amplification, memory/tool-output instruction-laundering detection, termination boundaries, rollback boundaries, and exact P8-A/P8-B/P7-I evidence binding.

P8-C does **not** claim production agent-runtime enforcement, production prompt/instruction interception, semantic proof of intent, safety of arbitrary tool outputs, exhaustive goal-hijack coverage, formal plan correctness, real-time rollback execution, or networked enforcement.
