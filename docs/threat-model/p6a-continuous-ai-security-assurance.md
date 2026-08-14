# P6-A threat model — continuous AI security assurance and adversarial regression operations

## Security objective

P6-A prevents a candidate release from being declared secure from an aggregate score, partial run, stale corpus, mutated case definition, or substituted baseline. The release must be evaluated against one policy-pinned, versioned cross-boundary corpus with exact one-to-one result coverage. Every result is bound to the canonical SHA-256 of its case definition and to the exact candidate release/commit/package version. The pinned baseline must itself satisfy every corpus expectation before it can serve as a regression reference.

The hardened gate therefore treats **security assurance as release evidence**, not as a dashboard percentage.

## Protected assets

- integrity of the versioned cross-boundary attack/safe-task corpus;
- immutability of individual case definitions and expected outcomes;
- exact baseline release identity;
- exact candidate release identity;
- complete per-case result coverage;
- preservation of attack-blocking behavior across releases;
- preservation of benign safe-task behavior across releases;
- deterministic evidence that can be compared release to release.

## Trust boundary

The gate trusts only policy-selected deterministic runner IDs and a policy-pinned corpus SHA-256. It does not attest the underlying runner machine. The caller supplies baseline and candidate evidence, but the hardened gate independently checks release identity, corpus identity, result coverage, case-definition digests, baseline security, and candidate regressions.

## Cross-boundary corpus

The P6-A fixture contains 18 versioned cases spanning nine Phase 5 boundaries:

1. P5-A model-artifact provenance;
2. P5-B package/adapter provenance;
3. P5-C immutable registry acquisition;
4. P5-D signing-key lifecycle;
5. P5-E runtime isolation;
6. P5-F poisoning/backdoor indicators;
7. P5-G model privacy/extraction controls;
8. P5-H deployment attestation;
9. P5-I serving-abuse response.

Fifteen cases are attack-blocking expectations and three are benign `ALLOW` expectations used to catch security changes that unnecessarily break safe tasks.

## Modeled attacks against the assurance layer

The deterministic evaluation covers 17 assurance-layer attacks:

1. corpus digest substitution;
2. corpus case-definition mutation;
3. missing policy-required boundary;
4. untrusted runner substitution;
5. candidate case omission;
6. duplicate candidate case;
7. unknown case substitution;
8. case-definition digest substitution;
9. baseline release substitution;
10. insecure baseline result;
11. candidate release substitution;
12. candidate commit substitution;
13. stale/wrong corpus evidence;
14. attack-blocking regression;
15. benign safe-task regression;
16. request/candidate commit substitution;
17. aggregate-score masking of one critical regression.

## Strong property

A candidate cannot pass P6-A by claiming a high aggregate score or zero regressions. Acceptance requires the exact policy-pinned corpus, all required boundaries, one and only one result for every immutable case definition, a secure policy-pinned baseline, exact candidate identity, and no attack or safe-task regressions beyond policy budgets.

## Vulnerable baseline

`VulnerableAggregateAssuranceGate` accepts caller-declared pass rate and regression count. It does not inspect the corpus, case definitions, baseline identity, per-case outcomes, or candidate evidence completeness. It models the common failure mode where a dashboard percentage replaces release-specific security evidence.

## Claim boundary / non-claims

P6-A does **not** claim:

- formal verification;
- exhaustive attack coverage;
- proof that unseen attacks are prevented;
- real attack execution by this module;
- production CI runner attestation;
- cryptographically signed assurance reports;
- hardware-backed runner identity;
- protection from a compromised trusted runner that fabricates results;
- automatic corpus quality or completeness assessment;
- production release blocking outside this lab;
- statistical confidence for nondeterministic model behavior.

The current milestone is a deterministic evidence and regression-policy lab. Its purpose is to make coverage drift and release-to-release security regressions explicit and fail-closed.
