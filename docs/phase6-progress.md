# Phase 6 progress — continuous AI security assurance

Phase 6 moves AegisDesk from adding individual security boundaries to continuously checking whether those boundaries remain effective across releases, and whether exceptions to failed invariants remain explicit, scoped, reviewable, and temporary.

## P6-A — versioned cross-boundary attack corpus and deterministic regression evidence

Status: **implemented and deterministically evaluated**.

P6-A introduces `aegis.assurance` and a release assurance gate with:

- a versioned cross-boundary corpus;
- canonical SHA-256 binding of the entire corpus;
- canonical SHA-256 binding of every case definition;
- exact policy-required boundary coverage;
- exact one-to-one case result coverage;
- duplicate and unknown case rejection;
- policy-pinned baseline release/commit/package-version identity;
- exact candidate release/commit/package-version identity;
- trusted deterministic runner IDs;
- rejection of insecure baselines;
- zero-tolerance attack-regression policy by default;
- zero-tolerance benign safe-task regression policy by default;
- an inert `VerifiedAssuranceEvidence` release artifact with explicit non-claims.

The corpus fixture contains **18 cases across nine Phase 5 boundaries**: 15 attack-blocking expectations and 3 benign safe-task expectations.

Deterministic evaluation evidence:

- adversarial assurance-layer cases: **17**;
- vulnerable ASR: **17/17**;
- hardened ASR: **0/17**;
- hardened FPR: **0/3**;
- hardened SafeTaskRate: **3/3**;
- corpus SHA-256: `8d4a161ae662246c2d49b5457f2b9a69684033a8494fb44b273e57b362e34738`;
- dataset SHA-256: `eefe9b1b9bab0332de4fbb0039644e02dabdc52fbd27a7407e100806aa7ce9a1`;
- fixture SHA-256: `90ff835b2d646937ed955c1a4a912f8e9003f47cf2890e0491c1f4ff334e3f42`.

An isolated local harness compiled the standalone P6-A implementation/evaluation/test logic, passed **24 P6-A security-test outcomes**, and completed the deterministic evaluation with the metrics above. This is not a claim that full-repository pytest ran locally or that a GitHub-hosted runner executed the branch.

P6-A does **not** claim formal verification, exhaustive red-team coverage, production CI attestation, trusted-runner hardware identity, real attack execution, or proof against unseen attacks.

## P6-B — security invariant drift and waiver governance

Status: **implemented and deterministically evaluated**.

P6-B adds an explicit governance layer for exceptions to P6-A security regressions. The hardened `SecurityInvariantWaiverGovernanceGate` requires:

- exact P6-A corpus SHA-256 binding;
- a separate versioned invariant registry with exact case coverage;
- immutable P6-A case-definition and severity binding inside the registry;
- one policy-pinned invariant owner for every corpus case;
- an exact invariant-registry SHA-256 policy pin;
- exact candidate P6-A evidence coverage and trusted deterministic runner identity;
- exact candidate release/commit/package-version and evidence-digest binding;
- one unique waiver for every waivable security regression and no waiver for non-regressions;
- no conversion of benign safe-task regressions into security waivers;
- exact waiver binding to case definition, owner, severity, candidate identity, corpus, and candidate evidence;
- explicit reason and tracking reference;
- deterministic issuance and expiry checks;
- severity-specific maximum waiver durations;
- exact severity preservation so a high/critical regression cannot be relabeled to easier waiver policy;
- severity-specific required approval roles;
- exact invariant-owner approval plus trusted role-specific approvers;
- critical-waiver denial in the deterministic fixture;
- high-severity waivers requiring both invariant-owner and trusted security-lead approval.

The 25 adversarial cases cover corpus/registry substitution, invariant definition/severity/owner drift, untrusted runner evidence, candidate evidence substitution, non-regression and duplicate waivers, scope substitution, stale/future/overlong waivers, severity downgrades, attempted critical waiver, missing or untrusted approvers, owner-approval substitution, unwaived high regressions, and attempted safe-task masking.

Deterministic evaluation evidence:

- adversarial governance-layer cases: **25**;
- vulnerable ASR: **25/25**;
- hardened ASR: **0/25**;
- hardened FPR: **0/3**;
- hardened SafeTaskRate: **3/3**;
- invariant-registry SHA-256: `3d3fa27fd95991e573f49a16552605a92f4c4830f3c3c7cf2ebd18caabc6c239`;
- dataset SHA-256: `86585ee5f547dde5131fcc0c94f03564ce38609f477a6cf298b50a5e2d42bfba`;
- fixture SHA-256: `88ac65ecbd0373008e395e1e218783cb5eeaafd49c2769bef1c93dcbe1e62343`.

An isolated local harness compiled the exact P6-B implementation/evaluation/test files, passed **31 P6-B security-test outcomes**, and completed the deterministic evaluation with the metrics above. The harness used API-compatible P6-A assurance corpus/evidence interfaces; this is not a claim that full-repository pytest ran locally.

P6-B is deterministic synthetic governance evidence. It does **not** claim production IAM/RBAC, external ticket validation, cryptographic human-approval attestation, rollback-resistant waiver storage, distributed clock integrity, automated production revocation, formal verification, or audit-framework compliance.

## Next direction

P6-C should add **assurance corpus evolution and coverage-drift governance**: explicit add/modify/deprecate change records, boundary and severity coverage floors, tombstones for removed cases, and deterministic release evidence proving that attack coverage cannot silently shrink during corpus upgrades.
