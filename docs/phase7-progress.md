# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance into explicit security-architecture analysis. The sequence now spans trust-boundary attack paths, privilege/capability escalation, tenant-aware data exfiltration, secrets/trust-root blast radius, third-party dependency trust, security-preserving graceful degradation, telemetry/audit blind spots, administrative control-plane mutation, and end-to-end invariant/blast-radius synthesis. Every milestone remains deterministic and synthetic and binds analysis to prior evidence rather than trusting caller summaries.

## P7-A through P7-H

P7-A through P7-H are complete for the current synthetic-lab scope. Their hardened analyzers cover trust-boundary graph analysis, privileged identity paths, data exfiltration, secret exposure, third-party dependency trust, dependency-failure security, telemetry integrity/detection blind spots, and control-plane administrative change paths. Earlier deterministic evidence and claim boundaries remain unchanged.

## P7-I — security architecture invariant synthesis and cross-layer blast radius

Status: **implemented and deterministically exercised in an isolated API-compatible harness; hosted runner execution pending infrastructure**.

P7-I adds `SecurityArchitectureInvariantAnalyzer`. It synthesizes compact end-to-end security invariants from exact P7-A through P7-H evidence and binds those invariants back to P6-D control posture. It reports which higher-level security properties hold, degrade, or fail when a modeled path, dependency, failure mode, telemetry requirement, control-plane route, or P6-D control becomes unsafe.

The canonical catalog defines eight invariants:

- privileged tool execution remains authorized and observable;
- tenant-sensitive data remains confined to approved tenant/egress boundaries;
- secrets and trust roots remain confined from untrusted surfaces/providers;
- model release integrity retains provenance, signing, and assurance gates;
- dependency failover cannot silently weaken authorization/data/secret controls;
- critical security telemetry remains observable across normal and failure paths;
- administrative identities cannot self-authorize or disable their own security evidence; and
- release assurance cannot be bypassed through cross-layer control-plane mutation.

The hardened boundary requires:

- exact invariant-catalog ID/version/SHA-256 and freshness;
- exact P7-A/P7-B/P7-C/P7-D/P7-E/P7-F/P7-G/P7-H and P6-D evidence digests;
- verified upstream evidence flags and non-duplicate object inventories;
- exact invariant ID coverage and trusted invariant ownership;
- policy-pinned minimum severity for every invariant;
- policy-pinned exact cross-layer evidence bindings;
- policy-pinned protected assets, affected identities, dependencies, control-plane routes, and required P6-D controls;
- a minimum distinct-layer coverage floor for every invariant;
- exact validation that each referenced upstream object/control exists;
- explicit `HOLDS`, `DEGRADED`, and `VIOLATED` states derived from evidence;
- deduplicated global blast radius across assets, identities, dependencies, and control-plane routes;
- deterministic risk prioritization; and
- rejection of caller-declared invariant state, zero-blast-radius, or maximum-risk summaries that disagree with evidence.

A non-control P7-A through P7-H exposure/blind spot makes the relevant invariant `VIOLATED`. A required P6-D control that is exceptioned or not evaluated makes the invariant `DEGRADED` when no non-control path is exposed. Satisfied evidence is retained separately as counterevidence instead of being used to erase a violation.

### Deterministic fixture

With all modeled upstream evidence controlled and all required P6-D controls satisfied:

- invariants: **8**;
- holding: **8/8**;
- degraded: **0**;
- violated: **0**;
- global cross-layer blast radius: **0**;
- maximum blast-radius score: **0**.

Representative truthful degraded/violated states include:

- exposed `p7c:data-tenant-egress` → only `INV-TENANT-DATA-CONFINEMENT` violated, blast radius **6**, maximum score **125**;
- exceptioned `CTRL-TELEMETRY` → **4** invariants degraded, global blast radius **21**, maximum score **116**; and
- a four-layer privileged-tool chain across P7-A/P7-B/P7-D/P7-E → exact exposed layers retained in the violated privileged-tool invariant while remaining satisfied bindings stay visible as counterevidence.

### Deterministic security evidence

The repository evaluator contains **98 adversarial cases** plus three truthful benign/degraded evidence states. An isolated API-compatible harness executed the exact P7-I implementation/evaluator/test files, passed **14 P7-I pytest tests**, and completed the evaluator:

- vulnerable ASR: **98/98**;
- hardened ASR: **0/98**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- invariant catalog SHA-256: `999edcda89df9c878bbc01b3cf6cd1ee3ea2895929892f8e5f2057db9a02f530`;
- adversarial dataset SHA-256: `aeef85e381df1d6ad37356d01ad9bff62400ce1796daf4874a9c8d2d7fae6691`;
- fixture SHA-256: `fe8734dd7398df94a7d437810f1090dfc81f452f8a50762d7b58d83fb6737d07`.

This isolated run is not a claim that full-repository pytest ran locally. GitHub-hosted workflow execution remains subject to the existing account billing/spending-limit runner-provisioning condition.

P7-I does not claim exhaustive attack coverage, formal end-to-end security proof, production asset/dependency discovery, real-time blast-radius discovery, production control-plane enforcement, probabilistic loss estimation, business-impact quantification, or compliance certification.

## Phase 7 status

**P7-A through P7-I are complete for the current deterministic synthetic-lab scope.**

## Next direction

Phase 8 should broaden into **agentic trust and delegation security** rather than adding more architecture reporting layers. P8-A should model multi-agent delegation, authority propagation, task handoff, identity continuity, and confused-deputy/capability-laundering paths across cooperating agents, tools, and tenants, with a matched caller-trusting vulnerable baseline and deterministic cross-agent evidence.
