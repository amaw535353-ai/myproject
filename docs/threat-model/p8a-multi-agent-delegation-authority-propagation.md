# P8-A threat model — multi-agent delegation and authority propagation

## Scope

P8-A begins Phase 8 by modeling delegation security across cooperating AI agents, tools, tenants, release agents, and security-control agents. The goal is to prevent a lower-authority caller or intermediate agent from obtaining more authority merely because a downstream agent is more privileged.

The analysis is deterministic and synthetic. It does not send agent-to-agent messages or execute tools. It binds a canonical delegation graph to P7-B identity/capability evidence, P7-H administrative control-plane evidence, and P7-I end-to-end architecture invariants.

## Security objective

A caller must not be able to convert an unsafe multi-agent handoff into an allowed result by declaring that delegation was authorized, tenant identity was preserved, or escalation count was zero.

For every delegation chain, authority must be bounded by all of the following:

1. the original principal's task and authority policy;
2. the current delegator's effective authority;
3. the delegatee agent's policy-pinned maximum authority;
4. tenant and original-principal identity continuity;
5. exact task provenance across parent/child delegation records;
6. a bounded delegation depth;
7. current P7-B privilege-path evidence;
8. required P7-H administrative routes for control-plane capabilities; and
9. required P7-I invariants for privileged or security-sensitive capabilities.

## Modeled agent identities

The canonical fixture contains nine agents across tenant-runtime, release-control, and security-control trust domains:

- tenant orchestrator;
- tenant retrieval agent;
- tenant tool broker;
- tenant tool executor;
- release orchestrator;
- release execution agent;
- security orchestration agent;
- observability agent; and
- authorization-policy controller.

Every agent is policy-pinned to a role, tenant, trust domain, trusted owner, maximum capability set, P7-B privilege paths, P7-H control-plane routes, delegation acceptance flag, and maximum chain depth.

## Capability model

Ten capabilities cover search, retrieval, tool operation, model release, telemetry, and policy administration. Capabilities carry a semantic family and privilege level in addition to their identifier. This lets the analyzer detect capability laundering where an intermediate agent attempts to turn a lower-level capability into a differently named higher-level capability in the same family.

Capabilities also specify tenant scope, whether they are privileged, and any P7-H/P7-I evidence required before they may be delegated.

## Original-principal authority

The fixture contains explicit authority policies for:

- tenant user `user-a`;
- lower-authority tenant user `user-limited`;
- `release-admin`; and
- `security-admin`.

Each principal has an exact tenant, allowed task classes, and maximum privilege level per capability family. A powerful downstream agent therefore cannot act as a confused deputy: the original principal must independently authorize the requested task and privilege level.

## Delegation-chain rules

The hardened analyzer requires:

- exact graph ID/version/SHA-256 and freshness;
- exact P7-B/P7-H/P7-I evidence digests and verification flags;
- exact agent/capability/delegation coverage;
- unique delegation IDs and an acyclic parent graph;
- trusted owners and trust domains;
- exact original-principal identity on every chain hop;
- parent delegatee → child delegator continuity;
- exact original-request SHA-256 continuity;
- child issuance/expiry contained within the parent delegation window;
- no expired delegation;
- task authorization by the original principal;
- requested privilege no higher than the original principal's family-level authority;
- requested authority no higher than the delegator's effective authority;
- requested authority within the delegatee's maximum capability set;
- no privilege-level increase within a family across chained delegation;
- bounded chain depth for both delegator and delegatee;
- current P7-B paths for both agents;
- exact P7-H routes required by delegated control-plane capabilities; and
- required P7-I invariants remaining safe.

## Threats addressed

### Confused deputy

A lower-authority principal cannot induce a more powerful downstream agent to perform an operation outside the original principal's authority. The downstream agent's own privileges are not sufficient evidence of authorization.

### Capability laundering

A child delegation cannot increase privilege within a capability family merely by changing capability names or moving through an intermediate agent. The child is bounded by the effective capabilities of the parent delegation.

### Cross-tenant authority transfer

Delegation tenant identity is bound to the original principal and to agent tenancy. Tenant-bound delegations cannot silently move to another tenant or through system/shared agents as if tenant identity had disappeared.

### Identity/provenance discontinuity

A child delegation must preserve original-principal ID, tenant, original-request digest, and time containment. Parent delegatee and child delegator must be the same agent.

### Privileged downstream dependency

Even a syntactically valid delegation is denied when required P7-B privilege paths are exposed, required P7-H control-plane routes are exposed, or required P7-I architecture invariants are degraded/violated.

## Intentionally vulnerable baseline

`VulnerableDeclaredDelegationAuthorization` trusts caller declarations that delegation is authorized, identity/tenant continuity hold, denied count is zero, and escalation count is zero. It does not bind those claims to original-principal authority, agent identity, chain provenance, P7-B paths, P7-H routes, or P7-I invariants.

## Deterministic fixture and evaluator

The canonical graph contains:

- agents: **9**;
- capabilities: **10**;
- delegation records: **7**;
- safe chained handoff depth: **2**.

The repository evaluator encodes **90 adversarial cases** plus three truthful benign/denial states. It targets vulnerable ASR **90/90**, hardened ASR **0/90**, hardened FPR **0/3**, and SafeTaskRate **3/3**.

A small isolated core harness independently reconstructed the canonical graph serialization and delegation-risk derivation and passed **11 focused checks** covering baseline authorization, cross-tenant denial, capability laundering, P7-B/P7-H/P7-I unsafe evidence, chain depth, expiry, and exact deterministic hashes. This is not a claim that the GitHub-hosted P8-A Python files executed byte-for-byte or that full-repository pytest ran locally.

Exact hashes:

- delegation graph SHA-256: `874a38e5df60b79c2a04ba451e6785b3712afe1e353951d3f0572f074f157b71`;
- adversarial dataset SHA-256: `a389f31f79d1b2754a0689aa6acb0ea7ed125fe42679ddc0dd51ecaae87e1d11`;
- fixture SHA-256: `9a095c128f9f24a2df963bdcd6077c72e2ab7953792f8183f4436d620c8e7e07`.

## Claim boundary

P8-A can claim deterministic synthetic multi-agent delegation security evidence with original-principal authorization, tenant/identity/provenance continuity, authority non-amplification, confused-deputy and capability-laundering detection, and exact P7-B/P7-H/P7-I evidence binding.

P8-A does **not** claim production agent identity attestation, real agent-to-agent protocol enforcement, production IAM/RBAC, cryptographic delegation tokens, live tool execution interception, behavioral guarantees for arbitrary agents, exhaustive agent-behavior coverage, formal delegation proof, or networked enforcement.
