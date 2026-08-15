# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 treats training data, fine-tuning admission, training execution, checkpointing, evaluation governance, sensitive-data handling, and promotion as security-sensitive evidence.

## P9-A through P9-D

- **P9-A — dataset provenance and holdout isolation:** complete for current synthetic scope. Focused evidence: 21 tests, 157 adversarial cases, vulnerable ASR 157/157, hardened ASR 0/157, FPR 0/4, SafeTaskRate 4/4.
- **P9-B — poisoning, label integrity, contributor trust:** complete for current synthetic scope. Focused evidence: 19 tests, 112 adversarial cases, vulnerable ASR 112/112, hardened ASR 0/112, FPR 0/4, SafeTaskRate 4/4.
- **P9-C — fine-tuning/LoRA/adapter authorization:** complete for current synthetic scope. Focused evidence: 37 tests, 139 adversarial cases, vulnerable ASR 139/139, hardened ASR 0/139, FPR 0/4, SafeTaskRate 4/4.
- **P9-D — training execution provenance and least privilege:** complete for current synthetic scope. Focused evidence: 60 tests, 160 adversarial cases, vulnerable ASR 160/160, hardened ASR 0/160, FPR 0/4, SafeTaskRate 4/4.

Hosted runner execution remains an external infrastructure dependency. A GitHub job that executes zero steps because runner provisioning is blocked is classified as `REMOTE_CI_BLOCKED`, not as a security-test failure and not as a hosted CI pass.

## P9-E — checkpoint/resume integrity and rollback-safe lineage

Status: **implemented and deterministically exercised in an isolated API-compatible P9-E harness; hosted runner execution remains an external infrastructure dependency**.

P9-E adds `TrainingCheckpointIntegrityAnalyzer`. It consumes the exact P9-D clean assessment and treats checkpoint creation/resume/rollback as a distinct security boundary rather than assuming checkpoint metadata is trustworthy.

The canonical fixture binds:

- exact P9-D assessment, execution ID, and job ID;
- a deterministic three-checkpoint lineage at steps 0, 400, and 800;
- exact parent-before-child checkpoint relationships;
- exact model, optimizer, RNG, data-cursor, trainer-state, and checkpoint-artifact SHA-256 values;
- an allowlisted checkpoint serialization format and immutable local-artifact semantics;
- denial of external checkpoint references and custom deserializers;
- one active checkpoint and a policy-bound resume action with monotonic next-step semantics;
- policy-owned operation authorization bound to principal, P9-D assessment, action, source/target checkpoint, validity window, and reason; and
- an explicit allowlist of rollback targets.

The hardened boundary denies or rejects swapped P9-D evidence, cross-job/cross-execution checkpoints, missing/reordered checkpoints, non-monotonic steps, parent-chain breaks, state/artifact substitutions, unsafe formats, mutable checkpoints, external references, custom deserializers, stale/replayed requests, source/target substitution, invalid next steps, expired or mismatched operation authorizations, and rollbacks to non-allowlisted targets. Caller-declared checkpoint safety cannot override derived evidence.

The matched vulnerable baseline `VulnerableCallerDeclaredCheckpointSafety` trusts caller-declared upstream, lineage, state, authorization, and overall checkpoint-safety booleans.

### Focused deterministic evidence

An isolated API-compatible harness executed the exact P9-E implementation/evaluator/test files against the P9-D assessment dataclass contract:

- tests: **16 passed**;
- adversarial cases: **89**;
- vulnerable ASR: **89/89**;
- hardened ASR: **0/89**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- checkpoint manifest SHA-256: `f959da93204ce6f682e6313e701f73ecdd77395a24151fb50de2dfab3811d744`;
- adversarial dataset SHA-256: `94fc696771841ac912df23f7778ac5680feb4ba52a8807f001492b3d479dc24a`;
- fixture/evaluator evidence SHA-256: `1107ce8477cba094b23dfd4b1f058c2518f9d6e120e7e075248abea9d2271fe6`;
- clean assessment SHA-256: `e3464594fc8631d5a6a22fc68b5200e4f823778a0e09bfe4e3f1eb3717cc4c27`.

This is focused local P9-E evidence, **not** a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9e` is the explicit focused path. The default verification path remains reserved for a real full local repository execution.

### Claim boundary

P9-E is deterministic synthetic checkpoint-lineage evidence. It does **not** claim production checkpoint-store integration, atomic storage durability, cryptographic checkpoint signatures, remote object-store provenance, trusted timestamps, actual trainer resume/rollback execution, distributed optimizer consistency, GPU memory restoration correctness, semantic model safety, or production artifact promotion.

No runtime dependency is added.

## Phase 9 roadmap

- **P9-A:** dataset provenance and holdout isolation — complete for current synthetic scope.
- **P9-B:** data poisoning, label integrity, and contributor/trust weighting — complete for current synthetic scope.
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding — complete for current synthetic scope.
- **P9-D:** training-job identity, code/config/environment provenance, and secret/capability boundaries — complete for current synthetic scope.
- **P9-E:** training checkpoint/resume integrity and rollback-safe lineage — complete for current synthetic scope.
- **P9-F:** evaluation-set leakage and benchmark-contamination governance.
- **P9-G:** sensitive-data/PII/canary governance for training inputs and outputs.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance.
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.

The next milestone is **P9-F**, binding evaluation datasets and benchmark provenance so training, tuning, checkpoint, and evaluation evidence cannot silently contaminate holdouts or inflate benchmark claims.
