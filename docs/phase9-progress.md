# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 treats training data, fine-tuning admission, execution, checkpoints, evaluation, sensitive-data handling, and promotion as security-sensitive evidence.

## Completed milestones

- **P9-A:** dataset provenance and holdout isolation.
- **P9-B:** poisoning, label integrity, and contributor trust.
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding.
- **P9-D:** training execution provenance and least privilege.
- **P9-E:** checkpoint/resume integrity and rollback-safe lineage.
- **P9-F:** evaluation leakage and benchmark-contamination governance.
- **P9-G:** sensitive-data, PII, secret, and canary governance.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance — complete for current deterministic synthetic scope.

Hosted runner execution remains an external infrastructure dependency. A GitHub job that executes zero steps because runner provisioning is blocked is `REMOTE_CI_BLOCKED`, not a security-test failure and not a hosted CI pass.

## P9-H — promotion into the model supply chain

`ModelRegistryPromotionAnalyzer` consumes the exact P9-G clean assessment and binds governance/evaluation/checkpoint identity, execution/job lineage, model/base-model identity, final-checkpoint digest, the exact promoted artifact closure, an immutable registry namespace/model/version/URI, policy-owned promotion authorization, predecessor/rollback/revocation metadata, and zero modeled network operations.

The Phase 5 bridge pins the existing P5-A artifact policy/schema, P5-B package policy/schema and component roles, and P5-C registry policy/release schema plus package and release digests. It is deliberately a handoff boundary: P9-H does not claim that Phase 5 signatures, registry acquisition, scanning, deployment, or serving checks have executed.

### Focused deterministic evidence

An isolated API-compatible harness exercised the P9-H implementation/evaluator/test logic against the P9-G assessment and Phase 5 constant/role contracts:

- tests: **26 passed**;
- adversarial cases: **113**;
- vulnerable ASR: **113/113**;
- hardened ASR: **0/113**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- promotion manifest SHA-256: `8166e90e7e7c04028628c02f10b3cf6c702686bf6c986bee31583b51501fa914`;
- adversarial dataset SHA-256: `d4d0d9ed30fd2e6905427d846ca0d10b10d93a359d5049b05e152ffc1d99583a`;
- fixture/evaluator evidence SHA-256: `fb0804d3f8c320657955815e08e66e4c49b87f27cb4c5a3b09a8e8217a1b7e3a`;
- clean assessment SHA-256: `8daa403475acdf99254740ac7ba1c6384696acd4eb3fb1b57b09d98232946888`.

This is focused P9-H evidence, **not** a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9h` is the explicit focused path.

### Claim boundary

P9-H is deterministic synthetic promotion evidence. SHA-256 is integrity binding, not authenticity. It does **not** claim a registry write occurred, production registry integration, cryptographic promotion signing, deployment execution, complete key provenance, semantic model safety, representative evaluation, production privacy assurance, or propagated revocation.

No runtime dependency is added. Package version is **0.89.0**.

## Remaining Phase 9 roadmap

- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.

The next milestone is **P9-I**, composing the Phase 9 boundaries into compromise scenarios and a machine-readable exit decision without promoting synthetic evidence into production attestation.
