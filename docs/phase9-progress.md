# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 treats training data, fine-tuning admission, execution, checkpoints, evaluation, sensitive-data handling, promotion, and integrated exit evidence as security-sensitive state.

## Completed milestones

- **P9-A:** dataset provenance and holdout isolation.
- **P9-B:** poisoning, label integrity, and contributor trust.
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding.
- **P9-D:** training execution provenance and least privilege.
- **P9-E:** checkpoint/resume integrity and rollback-safe lineage.
- **P9-F:** evaluation leakage and benchmark-contamination governance.
- **P9-G:** sensitive-data, PII, secret, and canary governance.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance.
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate — complete for the current deterministic synthetic scope.

Hosted runner execution remains an external infrastructure dependency. A GitHub job that executes zero steps because runner provisioning is blocked is `REMOTE_CI_BLOCKED`, not a security-test failure and not a hosted CI pass.

## P9-I — integrated compromise exercise and Phase 9 exit gate

`Phase9IntegratedExitGate` composes the exact P9-A-through-P9-H historical evidence rather than re-implementing those analyzers. It binds each milestone's manifest SHA-256, clean-assessment SHA-256, assessment schema/mode, control-domain identity, predecessor-assessment chain, synthetic state continuity, safety outcome, caller-trust boundary, and zero modeled network operations.

The gate also binds eight policy-owned compromise exercises spanning training-data poisoning propagation, unauthorized adapter/base substitution, execution secret/capability escalation, checkpoint rollback/state substitution, benchmark contamination and score inflation, sensitive-data/canary reproduction, model-registry artifact/reference substitution, and replay of upstream assessment evidence at promotion. Each exercise must match its entry milestone, ordered propagation path, attack-input digest, detection milestone, and recovery-state digest; every compromise must be detected and promotion must fail closed.

Verification evidence distinguishes `LOCAL_FOCUSED_PASS`, `LOCAL_FULL_PASS`, `REMOTE_CI_PASS`, `REMOTE_CI_BLOCKED`, `REMOTE_CI_FAIL`, and `NOT_RUN`. A remote pass requires actual runner/step execution. A blocked run requires no runner start, zero steps, and a policy-recognized external reason. An executed remote failure produces a Phase 9 exit failure.

### Focused deterministic evidence

An isolated API-compatible harness exercised the P9-I control semantics using the exact Phase 9 schema/mode contracts and the historical P9-A-through-P9-H manifest/assessment/evaluator evidence pins:

- tests: **30 passed**;
- adversarial cases: **254**;
- vulnerable ASR: **254/254**;
- hardened ASR: **0/254**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- compromise scenarios: **8**;
- promotion fail-closed result: **verified in the deterministic exercise**;
- canonical exit decision: `PASS_WITH_EXTERNAL_CI_LIMITATION`;
- canonical remote CI status: `REMOTE_CI_BLOCKED`;
- harness Phase 9 exit manifest SHA-256: `7cffc52d53aaf254e0ff1b5e42061218d6eeb25fc0e66fcd804a938bf4e689d7`;
- adversarial dataset SHA-256: `fba0b62f391c93669e9ad3518246377e5cb9cfe19afe05b8cf1c9ef19887f337`;
- fixture/evaluator SHA-256: `f0374389835d548dae98e7a2257ef6b4169fddf3be0646a8eb390720091a0275`;
- harness clean assessment SHA-256: `e5a2c1c3819db9462f9b133c7fdb1a16be15eb3a49fbf07397b970f50810693a`.

The repository branch contains integration and source-compaction edits after that isolated harness run. These figures therefore validate the P9-I control semantics, **not** byte-for-byte execution of every final branch file and **not** a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9i` is the repository path for exact focused execution when a suitable environment is available; the default path remains reserved for an actually executed full Phase 9 repository verification.

### Machine-readable exit semantics

The report records Phase 9 implementation status, local validation state, compromise-exercise coverage, promotion fail-closed status, remote-CI execution evidence, external-CI limitation state, production-claim boundary, exit decision, and assessment evidence SHA-256. `PASS_WITH_EXTERNAL_CI_LIMITATION` does not convert a zero-step hosted runner into a CI pass.

### Claim boundary

P9-I is deterministic synthetic evidence. SHA-256 is integrity binding, not authenticity. It does **not** claim production data-platform integration, a real training runtime, scheduler/IAM/KMS enforcement, production checkpoint-store durability, hidden-benchmark service integrity, comprehensive DLP/privacy/legal compliance, a real registry write, deployment execution, cryptographic workload/hardware attestation, distributed-training correctness, or semantic model safety.

No runtime dependency is added. Package version is **0.90.0**.

## Phase 9 exit

The current deterministic synthetic Phase 9 scope is complete through **P9-I**. The machine-readable exit gate may report `PASS_WITH_EXTERNAL_CI_LIMITATION` while GitHub-hosted runner provisioning remains externally blocked; production validation remains explicitly out of scope.
