# Phase 8 progress — agentic trust, delegation, and authority security

Phase 8 broadens AegisDesk beyond architecture reporting into security properties specific to cooperating autonomous agents. The phase starts with delegation and authority propagation: who originally authorized a task, which capabilities can move across agent handoffs, whether identity and tenant provenance remain intact, and whether a powerful downstream agent is acting as a confused deputy.

## P8-A — multi-agent delegation and authority propagation

Status: **implemented with deterministic fixture/evaluator/test coverage; hosted runner execution pending infrastructure**.

P8-A adds `MultiAgentDelegationSecurityAnalyzer` under `aegis.agentic`. The analyzer binds a canonical multi-agent delegation graph to exact P7-B privilege evidence, P7-H control-plane evidence, and P7-I cross-layer invariant evidence.

The canonical fixture contains **9 agents**, **10 capabilities**, and **7 delegation records** across tenant-runtime, release-control, and security-control trust domains. It includes a safe two-hop tool delegation chain plus retrieval, release-inspection, model-deployment, telemetry-configuration, and authorization-policy delegations.

The hardened boundary enforces:

- exact graph ID/version/SHA-256 and freshness;
- exact P7-B/P7-H/P7-I evidence digests and key verification flags;
- exact agent, capability, and delegation coverage;
- trusted agent/delegation owners and trust domains;
- policy-pinned roles, tenants, maximum capabilities, privilege paths, administrative routes, delegation flags, and depth bounds;
- exact capability family/privilege level/tenant scope/privileged classification;
- exact P7-H and P7-I requirements for sensitive capabilities;
- original-principal tenant, allowed task classes, and maximum authority by capability family;
- acyclic parent chains with unique delegation IDs;
- original-principal, tenant, request-digest, and time-window continuity across parent/child handoffs;
- parent delegatee → child delegator continuity;
- original-principal confused-deputy protection;
- delegatee maximum-authority bounds;
- delegator effective-authority bounds;
- capability-laundering detection using family-level privilege levels across chained delegation;
- bounded chain depth and non-expired delegation;
- denial when required P7-B paths, P7-H routes, or P7-I invariants are unsafe; and
- rejection of caller-declared denied/risk summaries that do not match derived evidence.

### Deterministic evidence

The repository evaluator encodes **90 adversarial cases** plus three truthful benign/denial states and targets:

- vulnerable ASR: **90/90**;
- hardened ASR: **0/90**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**.

A small isolated core harness reconstructed the canonical graph serialization and core delegation-risk derivation and passed **11 focused checks**. Those checks covered the clean graph, cross-tenant denial, capability laundering, exposed P7-B authority, exposed P7-H administrative routes, unsafe P7-I invariants, chain-depth enforcement, delegation expiry, and the exact deterministic hashes below. This is not a claim that full-repository pytest ran locally or that the GitHub-hosted P8-A files executed byte-for-byte in that harness.

Exact hashes:

- delegation graph SHA-256: `874a38e5df60b79c2a04ba451e6785b3712afe1e353951d3f0572f074f157b71`;
- adversarial dataset SHA-256: `a389f31f79d1b2754a0689aa6acb0ea7ed125fe42679ddc0dd51ecaae87e1d11`;
- fixture SHA-256: `9a095c128f9f24a2df963bdcd6077c72e2ab7953792f8183f4436d620c8e7e07`.

### Claim boundary

P8-A is deterministic synthetic delegation evidence. It does not claim production agent identity attestation, real multi-agent protocol enforcement, production IAM/RBAC, cryptographic delegation tokens, live tool-execution interception, arbitrary-agent behavioral guarantees, exhaustive agent-behavior coverage, formal delegation proof, or networked enforcement.

## Next direction

P8-B should broaden into **agent memory and context-boundary security**: memory provenance, tenant/session isolation, write authorization, poisoned-memory persistence, delegated-memory writes, retrieval-time trust labeling, and prevention of cross-agent/cross-tenant memory laundering.
