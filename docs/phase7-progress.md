# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance into explicit security-architecture analysis. The sequence covers trust-boundary attack paths, privilege/capability escalation, tenant-aware data exfiltration, secrets and trust-root blast radius, external dependency/service-egress trust, security-preserving graceful degradation, telemetry/audit blind spots, and security control-plane administrative change paths. Every milestone remains deterministic and synthetic and binds analysis to prior evidence rather than trusting caller summaries.

## P7-A through P7-G

P7-A through P7-G are complete for the current synthetic-lab scope. Their hardened analyzers cover trust-boundary graph analysis, privileged identity paths, data exfiltration, secret exposure, third-party dependency trust, dependency-failure security, and telemetry integrity/detection blind spots. Earlier deterministic evidence and claim boundaries remain unchanged.

## P7-H — security control-plane and administrative change paths

Status: **implemented and deterministically exercised in an isolated API-compatible harness; hosted runner execution pending infrastructure**.

P7-H adds `SecurityControlPlaneChangeAnalyzer`. It models who and what can mutate authorization policy, model deployment/security gates, telemetry configuration, egress/fallback rules, trust stores, and assurance settings instead of accepting a caller-owned “admin approved” summary.

The hardened boundary requires:

- exact control-plane ID/version/SHA-256 and freshness;
- exact P7-B, P7-E, P7-F, P7-G, and P6-D evidence digests;
- verified upstream evidence flags and exact referenced upstream object IDs;
- exact principal/resource/route coverage;
- trusted resource, principal, and route owners;
- policy-pinned administrative principal types and exact P7-B privilege paths;
- policy-pinned resource type, minimum sensitivity, upstream evidence bindings, controls, change telemetry, separation-of-duties, and break-glass semantics;
- policy-pinned route principal/resource/operation, trusted execution identity, exact independent approvers, controls, telemetry, target version, and break-glass mode;
- resource-required controls and telemetry as a mandatory subset of each change route;
- fresh route verification, non-empty change references, and exact SHA-256 target-state digests; and
- deterministic rejection of caller-declared exposed-route and maximum-risk summaries that differ from evidence.

Structurally valid routes remain exposed when the acting admin's P7-B path is exposed, the target resource is bound to exposed upstream evidence, administrative controls are exceptioned/not evaluated, required change telemetry has a P7-G blind spot, an administrator can rewrite the exact authorization path that grants its own authority, telemetry configuration can rewrite its own audit requirement, or a critical resource is subject to a destructive disable/delete route.

### Deterministic fixture

The canonical fixture contains:

- administrative principals: **6**;
- security control-plane resources: **7**;
- administrative change routes: **8**;
- policy-constrained break-glass routes: **1**.

With all modeled controls satisfied, all referenced upstream evidence controlled, and change telemetry intact:

- controlled routes: **8/8**;
- exposed routes: **0**;
- maximum exposed risk: **0**.

Representative truthful degraded states exercised locally include:

- exposed release-admin P7-B path → only `route-release-promote` exposed, risk **113**;
- `req-control-change` P7-G blind spot → all **8** routes exposed, maximum risk **111**;
- `CTRL-CHANGE-APPROVAL` exceptioned → all **8** routes exposed, maximum risk **103**;
- coherent self-authorization mutation → authorization route exposed because the admin can rewrite its own authority path;
- coherent self-audit mutation → telemetry route exposed because it can rewrite the same P7-G requirement used to audit the change; and
- coherent critical delete operation → egress-policy route exposed as a destructive critical-resource change.

### Deterministic security evidence

The repository evaluator contains **92 adversarial cases** plus three benign evidence states. An isolated API-compatible harness executed the exact P7-H implementation/evaluator/test files against synthetic upstream objects, passed **14 pytest tests**, and completed the evaluator:

- vulnerable ASR: **92/92**;
- hardened ASR: **0/92**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- control-plane manifest SHA-256: `c7a3e96a0227eabe57ae56326047d583af46e95decf49a8d8a958cd3e76f9525`;
- adversarial dataset SHA-256: `96a007b13658518dfe5d0b507114b71111300ecef30bbdabf8d91493daac177d`;
- fixture SHA-256: `b0c8732204c57e29f517ac69fa55e9168d999d8b8a96897a30f1165f200a82f0`.

This isolated run is not a claim that full-repository pytest ran locally. GitHub-hosted workflow execution remains subject to the existing account billing/spending-limit runner-provisioning condition.

P7-H does not claim production IAM/RBAC enforcement, real administrative API interception, live ticket validation, cryptographic human approval, production configuration deployment, rollback-resistant history, formal authorization proof, or compliance certification.

## Next direction

P7-I should add **security architecture invariant synthesis and cross-layer blast-radius reporting**: derive a compact set of end-to-end invariants from P7-A through P7-H, identify which identities/resources/dependencies/control-plane paths can violate each invariant, quantify cross-layer blast radius, and bind the result back to Phase 6 assurance evidence without turning the project into another approval chain.
