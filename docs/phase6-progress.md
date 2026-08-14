# Phase 6 progress — continuous AI security assurance

Phase 6 moves AegisDesk from adding individual security boundaries to continuously checking whether those boundaries remain effective across releases.

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

## Next direction

P6-B should add **security invariant drift and waiver governance**: versioned invariant ownership, explicit expiry-bound waivers, severity-aware exception policy, and release evidence proving that no critical/high regression was silently converted into an untracked exception.
