# P7-B threat model — identity, privilege, and capability escalation paths

## Objective

P7-B overlays identity and authorization semantics on the P7-A architecture graph. It models principals, privilege tiers/scopes, capabilities, delegation transitions, exact P7-A routes, and P6-D control posture, then derives which sensitive capabilities are reachable through legitimate delegation chains and which of those chains remain exposed because a mapped control is exceptioned or not evaluated.

The boundary is deterministic and synthetic. It does not enumerate a real IAM tenant, impersonate identities, test credentials, or prove exploitability.

## Security boundary

Inputs are:

- a P7-A `ArchitectureManifest`;
- a P7-A `VerifiedAttackPathAssessment` bound to that architecture;
- a P6-D `VerifiedSecurityPosture` bound to the same control catalog;
- a versioned `IdentityCapabilityManifest`;
- policy-owned entry principals and target capabilities; and
- a request that binds all evidence digests and the caller-declared exposure summary.

Output is inert `VerifiedPrivilegeEscalationAssessment`. No authentication, delegation, secret access, model admission, IAM mutation, or network operation occurs.

## Identity graph

The synthetic graph distinguishes:

- external and tenant user principals;
- server-owned service identities;
- privileged tool identities;
- a security-scoped synthetic secret broker;
- model publisher/registry identities;
- model runtime identities; and
- security telemetry identities.

Each principal has a policy-pinned home asset, type, privilege tier, privilege scope, and native capability set. Each capability has a policy-pinned target asset plus minimum sensitivity and privilege-tier requirements.

Delegation transitions represent authenticated sessions, server principal injection, tool authorization, credential brokering, model release admission, runtime invocation, and telemetry delegation.

## Strong properties

The hardened analyzer requires:

1. exact policy/request binding to the identity graph ID, version, SHA-256, and P7-A architecture SHA-256;
2. freshness and bounded future skew for identity evidence;
3. exact P7-A assessment evidence binding with intact P7-A verification flags;
4. exact P6-D posture/control-catalog binding with intact P6-D verification flags;
5. unique principals, capabilities, and delegation transitions;
6. trusted owners for principals, capabilities, and transitions;
7. policy-required principals, capabilities, and transitions so routes cannot disappear by deletion;
8. exact principal home-asset, type, tier, scope, and native-capability pins;
9. capability target, minimum-sensitivity, and minimum-tier floors;
10. validation that native capabilities exist and are compatible with the principal tier;
11. exact transition source/target, P7-A route, required-control, and granted-capability pins;
12. validation that each transition route is contiguous in the P7-A architecture from the source principal's home asset to the target principal's home asset;
13. validation that every transition control exists in P6-D evidence and is mapped to the exact P7-A route used by the transition;
14. validation that granted capabilities exist and the target principal has sufficient privilege tier;
15. policy-owned entry principals and sensitive target capabilities;
16. bounded deterministic simple-path enumeration with fail-closed hop/path truncation;
17. acquisition tracking so a target capability is recorded when first gained rather than repeatedly counted downstream;
18. derived privilege-tier and privilege-scope amplification across each path;
19. satisfied controls retained as mitigating counterevidence;
20. exceptioned/not-evaluated controls surfaced as explicit exposure reasons; and
21. rejection when caller-declared exposed paths or maximum risk differ from the evidence-derived result.

## Exposure semantics

A legitimate delegation chain is not automatically treated as an exploit. P7-B first derives capability acquisition through the modeled identity graph. A path is marked exposed only when it reaches a sensitive/amplified capability state and at least one required route control is exceptioned or not evaluated.

This keeps legitimate least-privilege delegation visible while preserving evidence of control gaps. An all-satisfied control posture retains the delegation paths but marks them controlled rather than pretending the identity edges do not exist.

## Deterministic fixture

The fixture models two policy target-capability paths:

1. `external-user-principal` → tenant session → agent service → privileged tool service → security-scoped secret broker, acquiring `cap-read-synthetic-secret`;
2. `registry-publisher-principal` → model runtime, acquiring `cap-load-model-release`.

The external agent-to-runtime path remains present in the graph but does not acquire a policy target capability and is therefore not counted as a target-capability path.

With only `CTRL-TOOL-AUTH` exceptioned, the synthetic result is:

- target-capability topology paths: **2**;
- exposed paths: **1**;
- controlled paths: **1**;
- critical exposed paths: **1**;
- maximum exposed-path synthetic risk score: **139**.

When all mapped controls are satisfied, both target-capability paths remain visible and controlled. When `CTRL-TOOL-AUTH` is `not_evaluated`, the secret-capability path remains visibly exposed with a synthetic maximum risk score of **134**.

## Modeled attacks

The deterministic evaluation covers:

- identity graph digest/schema/time/architecture substitution;
- principal deletion, duplication, owner, asset, type, tier, scope, native-capability, and enum substitution;
- capability deletion, duplication, owner, target, sensitivity, tier, and enum substitution;
- transition deletion, duplication, owner, endpoint, self-loop, route, control, capability-grant, duplicate-control, enum, unknown-flow, and unknown-control substitution;
- degraded or substituted P7-A evidence;
- degraded or substituted P6-D posture/control evidence;
- missing/duplicate/invalid control assessments and aggregate-status inconsistency;
- omission of a route control from posture evidence;
- entry-principal and target-capability scope substitution;
- request architecture/P7-A evidence substitution;
- caller omission of an exposed privilege path or forged maximum risk;
- path-hop and path-count truncation; and
- incomplete policy pins for required principals or transition grants.

## Counterevidence and prioritization

Each path retains satisfied required controls as `mitigating_control_ids`. Exceptioned and not-evaluated controls are listed separately. The synthetic risk score combines capability sensitivity, privilege-tier amplification, privilege-scope amplification, control gaps, and path length. It is a deterministic ordering device, not CVSS, exploit probability, or a calibrated production-loss estimate.

## Explicit non-claims

P7-B does **not** claim:

- production IAM/RBAC/ABAC discovery;
- live cloud identity or entitlement enumeration;
- real credential testing, token replay, or impersonation;
- secret retrieval or credential brokerage against a real system;
- production exploitability assessment;
- formal authorization or non-interference proof;
- automatic remediation or IAM mutation;
- complete privilege-escalation coverage for adaptive attackers;
- external red-team evidence;
- complete MITRE ATT&CK/ATLAS mapping;
- production identity-governance integration; or
- compliance certification.

## Residual risk

The analysis is only as accurate as the policy-pinned identity graph, P7-A routes, and P6-D control evidence. A trusted policy administrator can encode incorrect privilege assumptions, omit an unmodeled real-world identity path, or overstate a control as satisfied upstream. P7-B integrity-binds those assumptions and exposes their consequences; it does not independently prove the production IAM state is complete or correct.
