# P6-C threat model — assurance corpus evolution and coverage drift

## Security objective

P6-C governs changes to the versioned P6-A cross-boundary assurance corpus. A candidate corpus must not become trusted merely because a caller reports that coverage is unchanged or that all removals were intentional.

The hardened boundary requires exact baseline and candidate corpus identities, a canonical change manifest, one explicit change record for every added/modified/deprecated case, tombstones for every removal, non-weakening rules for existing attack cases, replacement coverage for removed high/critical attack cases, and policy-owned coverage floors.

## Protected assets

- the exact P6-A baseline corpus digest and lineage;
- individual case definitions and case IDs;
- attack expectation and severity semantics;
- boundary-level attack coverage;
- global critical and high/critical attack-case coverage;
- benign safe-task coverage;
- removal history and replacement relationships;
- deterministic evidence describing the accepted corpus transition.

## Adversary capabilities

The modeled caller may supply or mutate candidate corpus content, request metadata, change records, change owners, tombstones, replacement IDs, and aggregate coverage declarations. The caller may try to hide an addition, modification, or removal; downgrade an attack case; relabel its boundary or attack class; remove high-severity coverage without replacement; or preserve a superficially high aggregate count while shrinking a specific boundary.

The adversary does not compromise the policy object itself, the Python runtime, or the hashing primitive. P6-C does not model hostile execution of evaluation cases.

## Trust boundaries

P6-C consumes P6-A `AssuranceCorpus` case definitions and SHA-256 canonicalization. The policy pins the exact baseline corpus ID/digest, trusted change-owner IDs, boundary coverage floors, global severity floors, and the benign safe-task floor.

The change manifest is deterministic metadata, not a production change ticket. `owner_id` is a policy-controlled identifier, not proof of a human identity or an IAM assertion.

## Hardened rules

1. Baseline corpus ID and SHA-256 must exactly equal the policy pin.
2. Candidate corpus must remain in the same corpus lineage and advance its version.
3. The request binds the exact candidate corpus SHA-256 and exact change-manifest SHA-256.
4. The manifest binds exact baseline and candidate corpus SHA-256 values.
5. Baseline and candidate corpora reject duplicate or malformed cases.
6. Every added, modified, or removed case has exactly one change record; unchanged cases have none.
7. Every change record has a trusted owner and exact old/new case-definition digests for its operation.
8. Existing attack cases cannot change boundary or attack class in place; such transitions require deprecation plus a new case ID.
9. Existing `BLOCK` expectations cannot be changed to `ALLOW` under the default policy.
10. Existing attack severity cannot be downgraded under the default policy.
11. Every removal has exactly one tombstone preserving case digest, boundary, severity, expectation, candidate removal version, and replacement metadata.
12. Removed high/critical attack cases require newly added same-boundary `BLOCK` replacements of equal-or-higher severity.
13. Per-boundary attack-case floors and high/critical floors must remain satisfied.
14. Global critical, global high/critical, and benign safe-task floors must remain satisfied.
15. Accepted output is inert `VerifiedCorpusEvolution` evidence; the gate performs no network operations and executes no attacks.

## Vulnerable baseline

`VulnerableSelfReportedCorpusEvolutionGate` accepts caller-declared `coverage_ok=True` and `declared_untracked_changes=0`. It does not inspect corpus digests, case definitions, change records, tombstones, replacements, or coverage floors.

## Deterministic evaluation

The P6-C fixture keeps the exact P6-A baseline corpus SHA-256:

`8d4a161ae662246c2d49b5457f2b9a69684033a8494fb44b273e57b362e34738`

The evaluation contains 22 adversarial governance cases and three benign corpus transitions. It covers baseline/candidate/manifest substitution, silent add/modify/remove operations, duplicate and untrusted change metadata, case-definition substitution, expectation/severity weakening, boundary/attack-class reclassification, tombstone omission/substitution, missing or invalid replacement coverage, boundary and safe-task coverage shrink, and duplicate candidate case IDs.

Deterministic results:

- vulnerable ASR: **22/22**;
- hardened ASR: **0/22**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- dataset SHA-256: `623e5eaf40beaab1f0af141652319cab35cd1344d9526109605716a8360ff2c3`;
- fixture SHA-256: `6b1ff5de5ab5bd07d83de010509a08ae531cf5e8ee633fddff83c84124a838a3`.

## Claim boundary

P6-C can claim deterministic version-to-version corpus diff binding, explicit change coverage, non-weakening in-place modification rules, removal tombstones, modeled replacement requirements, and deterministic coverage floors.

P6-C does **not** claim:

- exhaustive red-team or attack coverage;
- proof that the chosen coverage floors are sufficient;
- formal verification;
- real execution of the underlying P5 attack cases;
- production change-management or ticket validation;
- cryptographic human approval or IAM identity;
- rollback-resistant corpus history or transparency logging;
- distributed consensus on corpus versions;
- secure timestamping;
- protection against a compromised policy administrator;
- audit-framework or regulatory compliance.
