# P6-B threat model — security invariant drift and waiver governance

## Objective

P6-B governs explicit exceptions after P6-A identifies release regressions. The security objective is to prevent a failed security invariant from disappearing through definition drift, owner substitution, severity downgrades, stale waivers, broad release-independent exceptions, or untracked approval shortcuts.

A release may carry a waiver only when the waiver is bound to the exact P6-A corpus, exact immutable case definition, exact policy-pinned invariant owner, exact candidate release/commit/package version, and exact candidate assurance-evidence SHA-256. Waivers must remain within a severity-specific lifetime and satisfy severity-specific approval roles.

## Protected assets

- the P6-A cross-boundary assurance corpus and each immutable case definition;
- invariant ownership and severity metadata;
- candidate P6-A release-assurance evidence;
- waiver scope, reason, tracking reference, issuance time, and expiry;
- trusted approver-role mappings;
- the release decision that distinguishes an explicitly governed exception from an unwaived regression.

## Trust boundaries

P6-B consumes deterministic P6-A `AssuranceCorpus` and `ReleaseAssuranceEvidence` objects. It does not execute attacks itself. A configured waiver policy pins the exact corpus digest, exact invariant-registry digest, one expected owner for every case, trusted deterministic runner IDs, trusted approvers per role, required approval roles per severity, maximum waiver durations, and the set of severities that may be waived.

The invariant registry is separate from the P6-A corpus. That separation is intentional: ownership is operational governance metadata, while case definition and severity remain anchored to P6-A. P6-B verifies that registry case IDs, case-definition digests, and severities exactly match P6-A and that each owner matches the policy-pinned owner map.

## Fail-closed properties

The hardened `SecurityInvariantWaiverGovernanceGate` requires:

1. an intact P6-A corpus matching the waiver-policy SHA-256 pin;
2. an invariant registry covering the corpus exactly;
3. registry case-definition digests and severities equal to the immutable P6-A cases;
4. registry owners equal to the policy-pinned owner for each case;
5. the registry SHA-256 equal to the policy pin;
6. candidate P6-A evidence with exact corpus coverage, immutable case-definition binding, and a trusted runner ID;
7. a governance request bound to the exact candidate release ID, commit SHA, package version, corpus digest, and candidate-evidence digest;
8. no conversion of benign safe-task regressions into security waivers;
9. exactly one waiver for every security regression and no waiver for a non-regressed case;
10. exact waiver binding to case definition, owner, severity, candidate identity, corpus digest, and candidate-evidence digest;
11. non-empty reason and tracking reference;
12. deterministic issuance and expiry validation;
13. a severity-specific maximum waiver duration;
14. exact severity preservation, preventing downgrade-to-easier-policy attacks;
15. policy denial for non-waivable severities; the deterministic fixture denies critical waivers;
16. trusted approvers for every declared role;
17. exact invariant-owner approval from the policy-pinned owner;
18. all severity-required approval roles before a waiver is accepted.

High-severity fixture waivers require both the invariant owner and a trusted security lead. Critical regressions remain unwaivable in the fixture even if owner, security-lead, and risk-owner approvals are presented.

## Adversarial coverage

The deterministic evaluation covers 25 attacks: corpus and registry digest substitution; registry case omission; definition, severity, and owner drift under a repinned registry; untrusted assurance runner; candidate case omission and case-definition substitution; candidate release/evidence-digest substitution; waiver creation for a non-regression; duplicate waivers; case-definition and candidate-commit substitution inside a waiver; expired, future-issued, and overlong waivers; waiver severity downgrade; attempted critical waiver; missing high-severity security-lead approval; untrusted approver; invariant-owner approval substitution; an unwaived high regression; and attempted masking of a benign safe-task regression.

## Strong property

A regression cannot become an accepted exception merely because a caller declares it waived. P6-B recomputes the security-regression set from exact P6-A case observations and requires one valid, release-scoped, expiry-bound waiver for every waivable security regression. Critical regressions in the fixture remain fail-closed, and safe-task regressions cannot be hidden inside the security-waiver path.

## Explicit non-claims

P6-B does **not** claim:

- formal verification of the invariant set;
- completeness of the P6-A attack corpus;
- proof that a human approver actually controlled an approver identifier;
- cryptographic signatures on human approvals;
- validation that an external ticket or change record really exists;
- production IAM, RBAC, ticketing, change-management, or release-gate integration;
- rollback-resistant waiver storage;
- distributed clock integrity;
- automated waiver revocation in production;
- legal, regulatory, or audit-framework compliance;
- protection against a compromised process that can rewrite both policy and its trusted inputs before evaluation.

`VerifiedWaiverGovernance` is deterministic governance evidence for the synthetic lab. It is not a production authorization token.
