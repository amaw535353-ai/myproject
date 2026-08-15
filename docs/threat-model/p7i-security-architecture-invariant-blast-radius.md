# P7-I threat model — security architecture invariant synthesis and cross-layer blast radius

## Scope

P7-I synthesizes end-to-end security invariants from the evidence produced by P7-A through P7-H and binds those invariants back to P6-D control posture. It answers a different question from the individual architecture analyzers: if one already-verified path, control, dependency, failure mode, telemetry requirement, or administrative route becomes unsafe, which higher-level security properties stop holding and how far can the modeled impact spread?

The analysis is deterministic and synthetic. It performs no discovery, exploitation, production control-plane mutation, or network operation.

## Security objective

A caller must not be able to hide a cross-layer architecture failure by declaring that all invariants hold, that blast radius is zero, or that compensating controls make the system globally safe. The analyzer must use a policy-pinned invariant catalog, exact upstream evidence digests, exact referenced object IDs, and current P6-D control status to derive invariant state and blast radius.

## Canonical invariant set

The fixture defines eight end-to-end invariants:

1. `INV-PRIVILEGED-TOOL-AUTHZ` — privileged tool execution remains authorized and observable.
2. `INV-TENANT-DATA-CONFINEMENT` — tenant-sensitive data cannot cross isolation or approved egress boundaries.
3. `INV-SECRET-TRUST-CONFINEMENT` — secrets and trust roots cannot traverse untrusted surfaces or providers.
4. `INV-MODEL-RELEASE-INTEGRITY` — model releases retain provenance, signing, and assurance gates.
5. `INV-FAILOVER-NON-WEAKENING` — dependency failover cannot silently weaken authorization, data, or secret controls.
6. `INV-SECURITY-TELEMETRY-CONTINUITY` — critical security activity remains observable across normal and failure paths.
7. `INV-ADMIN-NON-SELF-BYPASS` — administrative identities cannot self-authorize or disable their own security evidence.
8. `INV-ASSURANCE-GATE-NON-BYPASS` — release assurance cannot be bypassed by cross-layer control-plane mutation.

Each invariant is policy-pinned to exact evidence bindings using identifiers of the form `p7a:<path>`, `p7b:<path>`, `p7c:<path>`, `p7d:<path>`, `p7e:<path>`, `p7f:<scenario>`, `p7g:<requirement>`, `p7h:<route>`, and `p6d:<control>`.

## Trust assumptions

P7-I accepts previously verified P7-A through P7-H assessment objects and P6-D posture evidence as inputs. It rechecks the expected evidence digest and key verification flags for every upstream phase. It does not recreate each upstream canonical digest from its raw source manifest.

The invariant catalog and policy are trusted configuration. Policy maps pin the complete invariant set, minimum severity, exact evidence bindings, blast-radius entity sets, required P6-D controls, and a minimum number of distinct evidence layers.

## Invariant states

`HOLDS` means all policy-required cross-layer bindings are currently non-exposed and all invariant-required P6-D controls are satisfied.

`DEGRADED` means no non-control path is exposed, but one or more invariant-required P6-D controls are exceptioned or not evaluated. A degraded invariant is not silently treated as holding.

`VIOLATED` means one or more required non-control P7-A through P7-H evidence objects are exposed or blind. A critical violation cannot be hidden by other satisfied bindings; the satisfied evidence is retained separately as counterevidence.

## Blast-radius model

For each non-holding invariant, the analyzer reports:

- exact violating evidence bindings;
- degraded P6-D controls;
- distinct exposed layers;
- protected assets;
- affected identities;
- affected dependencies;
- affected P7-H control-plane routes;
- per-invariant blast-radius units;
- deterministic blast-radius score; and
- exact mitigating bindings that remain satisfied.

The global cross-layer blast radius is the deduplicated union of modeled asset, identity, dependency, and control-plane-route entities associated with all degraded or violated invariants. This is a deterministic architecture measure, not a probability of compromise or an estimate of real-world loss.

## Fail-closed validation

The analyzer rejects:

- request/catalog ID, version, digest, or scope substitution;
- stale or future-dated invariant catalogs;
- P7-A through P7-H or P6-D evidence digest substitution;
- missing upstream verification flags;
- malformed or duplicate upstream object inventories;
- inconsistent P6-D control summaries;
- missing, duplicate, substituted, or untrusted invariants;
- invariant severity downgrade;
- invariant evidence-binding omission, duplication, unknown objects, or unsupported layers;
- weakened cross-layer layer-coverage floors;
- protected asset, identity, dependency, control-plane route, or control-set drift;
- unknown P6-D controls; and
- caller-declared invariant state, blast-radius, or maximum-risk summaries that disagree with derived evidence.

## Intentionally vulnerable baseline

`VulnerableDeclaredArchitectureSafety` accepts caller-owned aggregate statements that all invariants hold, blast radius is zero, and cross-layer risk is zero. It does not bind those claims to any P7 or P6-D evidence.

## Deterministic fixture and evaluation

The canonical fixture contains eight invariants spanning P7-A through P7-H and nine P6-D controls. A clean fixture produces 8/8 holding invariants, zero degraded or violated invariants, and zero blast radius.

Representative truthful degraded states include:

- exposed `p7c:data-tenant-egress` → only `INV-TENANT-DATA-CONFINEMENT` violated, cross-layer blast radius **6**, maximum score **125**;
- exceptioned `CTRL-TELEMETRY` → four invariants degraded, global blast radius **21**, maximum score **116**; and
- a four-layer privileged-tool chain (`p7a`, `p7b`, `p7d`, `p7e`) → the privileged-tool invariant is violated with the exact four exposed layers retained in evidence.

The repository evaluator contains **98 adversarial cases** plus three truthful benign/degraded evidence states. An isolated API-compatible harness executed the exact P7-I module/evaluator/test files and passed **14 P7-I pytest tests**. The deterministic evaluator produced:

- vulnerable ASR: **98/98**;
- hardened ASR: **0/98**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- invariant catalog SHA-256: `999edcda89df9c878bbc01b3cf6cd1ee3ea2895929892f8e5f2057db9a02f530`;
- adversarial dataset SHA-256: `aeef85e381df1d6ad37356d01ad9bff62400ce1796daf4874a9c8d2d7fae6691`;
- fixture SHA-256: `fe8734dd7398df94a7d437810f1090dfc81f452f8a50762d7b58d83fb6737d07`.

This is not a claim that full-repository pytest ran locally.

## Claim boundary

P7-I can claim deterministic synthetic cross-layer invariant synthesis, exact evidence binding, modeled violation/degradation derivation, deduplicated architecture blast-radius reporting, and preservation of mitigating counterevidence.

P7-I does **not** claim exhaustive attack coverage, a formal end-to-end security proof, production asset or dependency inventory, real-time blast-radius discovery, production control-plane enforcement, probabilistic risk estimation, business-impact quantification, regulatory compliance, or certification.
