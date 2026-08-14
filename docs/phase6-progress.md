# Phase 6 progress — continuous AI security assurance

Phase 6 moves AegisDesk from adding individual security boundaries to continuously checking whether those boundaries remain effective across releases, whether exceptions remain explicit and temporary, and whether the assurance corpus itself can evolve without silently losing coverage.

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

P6-C adds `AssuranceCorpusEvolutionGate` so a corpus upgrade cannot pass from aggregate self-reported coverage. The gate requires:

- exact policy-pinned P6-A baseline corpus ID and SHA-256;
- same-lineage candidate corpus identity with an advanced version;
- exact request binding to candidate corpus and canonical change-manifest SHA-256 values;
- one trusted-owner change record for every added, modified, or deprecated case and no record for unchanged cases;
- exact old/new case-definition digest binding for every change operation;
- rejection of in-place boundary or attack-class reclassification;
- rejection of `BLOCK` to `ALLOW` weakening under the default policy;
- rejection of attack-severity downgrades under the default policy;
- exact one-to-one tombstones for removals;
- newly added, same-boundary, equal-or-higher severity `BLOCK` replacement coverage for removed high/critical attack cases;
- per-boundary attack-case and high/critical coverage floors;
- global critical and high/critical coverage floors;
- a benign safe-task coverage floor;
- inert `VerifiedCorpusEvolution` evidence with explicit non-claims.

The matched vulnerable baseline trusts only caller-declared `coverage_ok` and `untracked_changes` values.

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

## Next direction

P6-D should broaden Phase 6 into **AI security posture and control-coverage reporting**: deterministic mapping from P5/P6 security boundaries to risk/control objectives, release evidence showing which controls are satisfied or exceptioned, and explicit separation from claims of regulatory certification or production GRC integration.
