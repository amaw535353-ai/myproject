# Phase 6 progress — continuous AI security assurance

Phase 6 moves AegisDesk from adding individual security boundaries to continuously checking whether those boundaries remain effective across releases, whether exceptions remain explicit and temporary, whether the assurance corpus can evolve without silently losing coverage, whether release security posture is derived from exact evidence instead of caller-supplied status labels, and whether adversarial findings can close only after exact retest evidence passes.

## P6-A — versioned cross-boundary attack corpus and deterministic regression evidence

Status: **implemented and deterministically evaluated**.

P6-A introduced the versioned cross-boundary corpus and exact release-regression evidence gate. Its deterministic fixture contains 18 cases across P5-A through P5-I: 15 attack-blocking expectations and 3 benign safe-task expectations.

Deterministic evidence:

- vulnerable ASR: **17/17**;
- hardened ASR: **0/17**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- corpus SHA-256: `8d4a161ae662246c2d49b5457f2b9a69684033a8494fb44b273e57b362e34738`;
- dataset SHA-256: `eefe9b1b9bab0332de4fbb0039644e02dabdc52fbd27a7407e100806aa7ce9a1`;
- fixture SHA-256: `90ff835b2d646937ed955c1a4a912f8e9003f47cf2890e0491c1f4ff334e3f42`.

P6-A does not claim formal verification, exhaustive red-team coverage, production CI attestation, real attack execution, or proof against unseen attacks.

## P6-B — security invariant drift and waiver governance

Status: **implemented and deterministically evaluated**.

P6-B added explicit governance for exceptions to P6-A regressions: exact corpus and invariant-registry binding, policy-pinned invariant ownership, release/evidence-scoped waivers, expiry and severity-duration enforcement, severity preservation, trusted role-specific approvals, critical-waiver denial, and high-severity owner + security-lead approval.

Deterministic evidence:

- vulnerable ASR: **25/25**;
- hardened ASR: **0/25**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- invariant-registry SHA-256: `3d3fa27fd95991e573f49a16552605a92f4c4830f3c3c7cf2ebd18caabc6c239`;
- dataset SHA-256: `86585ee5f547dde5131fcc0c94f03564ce38609f477a6cf298b50a5e2d42bfba`;
- fixture SHA-256: `88ac65ecbd0373008e395e1e218783cb5eeaafd49c2769bef1c93dcbe1e62343`.

P6-B is deterministic synthetic governance evidence. It does not claim production IAM/RBAC, external ticket validation, cryptographic human approval, rollback-resistant waiver storage, distributed clock integrity, formal verification, or audit-framework compliance.

## P6-C — assurance corpus evolution and coverage-drift governance

Status: **implemented and deterministically evaluated**.

P6-C adds `AssuranceCorpusEvolutionGate` so a corpus upgrade cannot pass from aggregate self-reported coverage. The gate requires exact baseline/candidate corpus binding, explicit trusted-owner add/modify/deprecate records, non-weakening in-place changes, removal tombstones, equal-or-higher severity replacements for removed high/critical cases, per-boundary and global severity floors, and a benign safe-task coverage floor.

Deterministic evaluation evidence:

- adversarial governance-layer cases: **22**;
- vulnerable ASR: **22/22**;
- hardened ASR: **0/22**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- exact P6-A baseline corpus SHA-256: `8d4a161ae662246c2d49b5457f2b9a69684033a8494fb44b273e57b362e34738`;
- dataset SHA-256: `623e5eaf40beaab1f0af141652319cab35cd1344d9526109605716a8360ff2c3`;
- fixture SHA-256: `6b1ff5de5ab5bd07d83de010509a08ae531cf5e8ee633fddff83c84124a838a3`.

An isolated local harness exercised the standalone P6-C implementation/evaluation/test logic, passed **29 P6-C security-test outcomes**, and completed the deterministic evaluation with the metrics above against an API-compatible P6-A corpus interface. This is not a claim that full-repository pytest ran locally or that the GitHub-hosted branch files were executed by that harness byte-for-byte.

P6-C does not claim exhaustive attack coverage, proof that its coverage floors are sufficient, formal verification, production change-management integration, cryptographic human approval, rollback-resistant corpus history, or protection against a compromised policy administrator.

## P6-D — AI security posture and control-coverage reporting

Status: **implemented and deterministically evaluated**.

P6-D adds `AISecurityPostureReporter`, a deterministic release-posture layer that maps the P6-A corpus into policy-pinned AI security control objectives and derives control status from exact P6-B/P6-C evidence instead of trusting caller-supplied posture labels.

The hardened reporter requires:

- a canonical, versioned control catalog with exact SHA-256 policy binding;
- unique controls and unique case/boundary mappings;
- all policy-required controls and risk domains;
- exact release ID, commit SHA, package version, corpus digest, control-catalog digest, P6-B governance-evidence digest, and P6-C evolution-evidence digest binding;
- intact P6-B invariant/ownership/scope/expiry/approval/severity-preservation verification flags;
- exact and internally consistent P6-B regression/waiver scope;
- intact P6-C change-coverage/tombstone/coverage-floor/non-weakening verification flags;
- P6-C candidate case and severity counts that exactly match the current assurance corpus;
- per-control evidence-derived status: `satisfied`, `exceptioned`, or `not_evaluated`;
- `red` posture for critical/non-permitted exceptions or high/critical missing evaluation under policy;
- `amber` posture for permitted non-critical exceptions or lower-severity missing evaluation;
- `green` only when every mapped control is satisfied;
- rejection when a caller-declared posture disagrees with the derived posture;
- inert `VerifiedSecurityPosture` output with explicit certification/GRC non-claims.

The matched vulnerable baseline accepts caller-declared posture and aggregate satisfied/exceptioned/not-evaluated counts without evidence binding.

Deterministic evaluation evidence:

- adversarial posture-layer cases: **26**;
- vulnerable ASR: **26/26**;
- hardened ASR: **0/26**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- control-catalog SHA-256: `33950f1ecbb2df0003007e7d3008cd1a8a182db9603f2ec5bc39a900a3511f50`;
- corpus SHA-256: `7be8f8415e821b1aeeba149e3993caaa1f8cb5dda277af1d34d8dc1ca22f38c5`;
- dataset SHA-256: `23704d729b7a22ad168e66ff81ad13d3d9923115c61430aa6242a588a81b5d0e`;
- fixture SHA-256: `2562241e0eb8c4df32726416e248ed3b82cf7994cdf3ff4e24c3a429fed46fd8`.

An isolated local harness compiled the standalone P6-D implementation/evaluation/test logic, passed **31 P6-D security-test outcomes**, and completed the deterministic evaluation with the metrics above. The harness used API-compatible P6-A corpus, P6-B waiver-governance, and P6-C corpus-evolution interfaces; this is not a claim that full-repository pytest ran locally or that GitHub-hosted branch files executed byte-for-byte in that harness.

P6-D is deterministic synthetic posture evidence. It does **not** claim regulatory certification, SOC 2/ISO/NIST/EU-AI-Act compliance, production GRC integration, external auditor evidence, production IAM enforcement, exhaustive control coverage, rollback-resistant evidence storage, formal verification, or networked control-plane actions.

## P6-E — adversarial finding lifecycle and closure evidence

Status: **implemented and deterministically evaluated**.

P6-E adds `AdversarialFindingLifecycleGate`, which turns adversarial/red-team findings into versioned, release-bound assurance records. A finding cannot become `closed` merely because a caller says remediation succeeded.

The hardened lifecycle gate requires:

- exact policy-pinned P6-A corpus and P6-B invariant-registry SHA-256 values;
- exact one-to-one invariant-registry coverage with case-definition and severity preservation;
- trusted finding owners;
- finding links only to attack-blocking P6-A cases;
- exact boundary scope and exact P6-B invariant-owner binding derived from those linked cases;
- finding severity equal to the highest linked-case severity, preventing downgrade;
- immutable finding identity, scope, discovery release, owner, title, tracking reference, and opening time;
- version increments by exactly one;
- only `open -> fix_in_progress -> ready_for_retest -> closed` transitions;
- monotonic non-future lifecycle timestamps;
- exact fix-target release/commit/package-version binding once remediation begins;
- no closure evidence before `closed`;
- exact retest binding to the finding ID, `ready_for_retest` record digest, target release, current corpus, and trusted runner;
- exact one-to-one retest case coverage with immutable case-definition digests;
- every finding-linked case passing its P6-A expectation on the target release;
- retest freshness and non-future checks;
- the closed finding record binding the exact retest SHA-256;
- inert `VerifiedFindingTransition` evidence with explicit production-integration non-claims.

The matched vulnerable baseline trusts caller-declared status and a caller-declared `retest_passed` flag.

Deterministic evaluation evidence:

- adversarial finding-lifecycle cases: **36**;
- vulnerable ASR: **36/36**;
- hardened ASR: **0/36**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- corpus SHA-256: `9a2dad3e8991d3d3fd8b20540949f4c8047a0ee2c89c58c7d393c8483528fb13`;
- invariant-registry SHA-256: `ee45ee48a60ae7de869a83ddeeb2c84734a7692327c2b05478af467435d2abc4`;
- dataset SHA-256: `246352b226efada96128546e7b99bb0a3ff1b60cf32e5ed4a5edcb9999508e77`;
- fixture SHA-256: `df3d2e081423b56d694240be38df0d8eeba2c9c0db746d4d5a241b5b5bc5af91`.

An isolated local harness compiled and exercised the standalone P6-E implementation/evaluation/test logic, passed **41 P6-E security-test outcomes**, and completed the deterministic evaluation with the metrics above. The harness used API-compatible P6-A corpus and P6-B invariant-registry interfaces; this is not a claim that full-repository pytest ran locally or that the GitHub-hosted branch files were executed byte-for-byte by that harness.

P6-E is deterministic synthetic finding-lifecycle evidence. It does **not** claim production ticket/Jira/Linear integration, real patch deployment, cryptographic human remediation approval, rollback-resistant finding storage, exhaustive vulnerability discovery, official CVE/CVSS assignment, scanner-vendor integration, vulnerability-disclosure compliance, formal verification, or networked remediation actions.

## Next direction

P6-F should add **incident-to-assurance feedback and threat-informed regression coverage**: bind verified serving-incident evidence to new or strengthened assurance cases, require explicit corpus-evolution records for incident-derived tests, and prevent a known operational failure mode from disappearing from future release assurance without an auditable replacement or tombstone.
