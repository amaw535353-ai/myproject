# Phase 8 progress — agentic trust, delegation, and authority security

Phase 8 broadens AegisDesk beyond architecture reporting into security properties specific to cooperating autonomous agents. P8-A established delegation and authority propagation. P8-B adds stateful memory/context boundaries so persisted and retrieved context cannot silently acquire stronger trust, cross tenants/sessions, or survive revocation simply because another agent rewrites or retrieves it.

## P8-A — multi-agent delegation and authority propagation

Status: **complete for the current deterministic synthetic-lab scope**.

P8-A adds `MultiAgentDelegationSecurityAnalyzer` under `aegis.agentic`. The analyzer binds a canonical multi-agent delegation graph to exact P7-B privilege evidence, P7-H control-plane evidence, and P7-I cross-layer invariant evidence.

The canonical fixture contains **9 agents**, **10 capabilities**, and **7 delegation records** across tenant-runtime, release-control, and security-control trust domains. It enforces original-principal authorization, tenant/provenance continuity, delegator/delegatee authority bounds, confused-deputy protection, capability-laundering detection, bounded delegation depth, and fail-closed binding to upstream evidence.

P8-A repository evaluator evidence:

- adversarial cases: **90**;
- vulnerable ASR: **90/90**;
- hardened ASR: **0/90**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- delegation graph SHA-256: `874a38e5df60b79c2a04ba451e6785b3712afe1e353951d3f0572f074f157b71`;
- dataset SHA-256: `a389f31f79d1b2754a0689aa6acb0ea7ed125fe42679ddc0dd51ecaae87e1d11`;
- fixture SHA-256: `9a095c128f9f24a2df963bdcd6077c72e2ab7953792f8183f4436d620c8e7e07`.

P8-A does not claim production agent identity attestation, real agent-to-agent protocol enforcement, production IAM/RBAC, cryptographic delegation tokens, live tool-execution interception, arbitrary-agent behavioral guarantees, exhaustive agent-behavior coverage, formal delegation proof, or networked enforcement.

## P8-B — agent memory and context-boundary security

Status: **implemented and deterministically exercised in an isolated harness; hosted runner execution pending infrastructure**.

P8-B adds `AgentMemoryContextSecurityAnalyzer` and an explicit security model for session memory, durable tenant memory, and system/security memory. Every memory object is bound to tenant/session scope, trust, classification, content/source digests, creating agent, original principal, optional P8-A delegation, parent-memory provenance, P7-C data paths, sanitization evidence, retention, revocation, and supersession state.

The canonical fixture contains:

- memory stores: **3**;
- memory records: **6**;
- write events: **6**;
- retrieval events: **4**.

The hardened boundary enforces:

- exact memory-graph ID/version/SHA-256 and freshness;
- exact P8-A, P7-C, and P7-I evidence digests and key verification flags;
- exact store/memory/write/retrieval coverage;
- trusted store/record/event owners;
- policy-pinned store scope, tenant, reader/writer sets, classification ceiling, trust floor, retention, and P7-I invariants;
- original-principal tenant continuity;
- exact session binding for session memory;
- no session injection into system memory;
- writer authorization and policy-pinned writer maximum trust;
- exact memory/write provenance continuity;
- delegated-memory writes only when the bound P8-A delegation is allowed and matches writer/principal/tenant;
- acyclic parent-memory provenance;
- no silent trust upgrade or classification downgrade across parent/supersession transitions without allowlisted sanitization evidence;
- explicit `UNTRUSTED_PERSISTENCE`, `POISON_PERSISTENCE`, and `MEMORY_LAUNDERING` derivation for unsafe durable writes;
- P7-C exposure and P7-I invariant state as active memory-operation dependencies;
- retrieval-time trust/classification labels derived from canonical records rather than caller assertions;
- fail-closed retrieval of revoked, expired, or superseded memory; and
- rejection of caller-declared write/retrieval decisions and risk maps that disagree with derived evidence.

### Deterministic evidence

The clean canonical graph produces:

- writes allowed: **6/6**;
- retrievals allowed: **4/4**;
- denied writes: **0**;
- denied retrievals: **0**.

Representative truthful unsafe states include:

- a rewritten tool-derived memory that attempts to become `VERIFIED_SYSTEM` and less classified without sanitization → one denied write with `MEMORY_LAUNDERING`, `TRUST_UPGRADE`, and `CLASSIFICATION_DOWNGRADE`;
- a revoked current profile → one denied retrieval with `REVOKED_MEMORY`;
- a superseded profile → one denied retrieval with `SUPERSEDED_MEMORY`;
- sibling-session retrieval → denied by `CROSS_SESSION`;
- denied P8-A delegation, exposed P7-C path, or unsafe P7-I invariant → dependent memory operations denied.

The P8-B repository evaluator contains **126 adversarial cases** plus three truthful benign/denial contexts. An isolated local harness executed the standalone P8-B implementation/evaluator/test files, passed **16 P8-B pytest tests**, and completed the deterministic evaluator:

- vulnerable ASR: **126/126**;
- hardened ASR: **0/126**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- memory graph SHA-256: `7bb96cd8d40a57419bd2ec4bf31fcbdd38db05d512f2eadff410f522886b54ff`;
- adversarial dataset SHA-256: `f047bce2916ff0d745c0258b61db9205597afbfae80416a4f4bd01dc80b983fb`;
- fixture SHA-256: `a151395b84d35ff3ac40755372478bbfbcfb9a1a7e2754a0db3966104a930d9b`.

The isolated harness uses API-compatible P8-A/P7-C/P7-I evidence objects. This is not a claim that full-repository pytest ran locally or that production memory integrations were exercised.

P8-B does not claim production vector-database enforcement, production memory-provider integration, live cache invalidation, cryptographic memory attestation, semantic proof that sanitized content is safe, formal noninterference, exhaustive poisoning coverage, production data-retention compliance, or networked enforcement.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: implemented with deterministic local evidence; hosted workflow execution remains subject to the existing GitHub account runner-provisioning condition.

## Next direction

P8-C should broaden into **agent goal, plan, and instruction-integrity security**: trusted goal provenance, plan-step authorization, instruction precedence across system/user/tool/agent messages, delegated-goal continuity, prevention of instruction laundering across agents, plan mutation controls, termination/rollback boundaries, and detection of goal hijacking that remains within nominal tool permissions.
