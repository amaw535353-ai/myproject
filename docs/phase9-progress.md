# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 moves AegisDesk into training-data, fine-tuning, and ML training-pipeline security. Phase 5 secured model artifacts and serving supply-chain boundaries after a model exists; Phase 9 begins earlier in the lifecycle and treats data provenance, labeling, contributor trust, fine-tuning admission, training execution, checkpointing, evaluation governance, sensitive-data handling, and promotion as security-sensitive evidence.

## P9-A — training-dataset provenance, immutable snapshots, and holdout isolation

Status: **complete for the current synthetic scope; hosted runner execution remains an external infrastructure dependency**.

`TrainingDatasetProvenanceAnalyzer` binds exact source snapshots, record/source-key digests, split membership, preprocessing-transform provenance, and the final dataset SHA-256. Focused evidence: **21 tests passed**, **157 adversarial cases**, vulnerable ASR **157/157**, hardened ASR **0/157**, hardened FPR **0/4**, SafeTaskRate **4/4**.

P9-A SHA-256 bindings are deterministic integrity evidence, not source authentication.

## P9-B — data poisoning, label integrity, and contributor/trust weighting

Status: **complete for the current synthetic scope; hosted runner execution remains an external infrastructure dependency**.

`TrainingDataPoisoningAnalyzer` consumes exact P9-A assessment evidence rather than rebuilding provenance. It binds P9-A assessment/final-dataset digests, contributor/label/review/quarantine facts, and derives the exact included training-record set. Focused evidence: **19 tests passed**, **112 adversarial cases**, vulnerable ASR **112/112**, hardened ASR **0/112**, hardened FPR **0/4**, SafeTaskRate **4/4**.

P9-B does not claim validated semantic poisoning detection, production labeling-platform integration, cryptographically authenticated human review, causal poisoning attribution, or proof that a trained model is safe.

## P9-C — fine-tuning/LoRA/adapter authorization and base-model binding

Status: **complete for the current synthetic scope; hosted runner execution remains an external infrastructure dependency**.

`FineTuningAdmissionAnalyzer` consumes exact P9-B evidence, transitively binding P9-A. It pins selected records/data digest, principal/task/grant authorization, immutable base-model identity and digests, ordered adapter configuration, safe serialization, bounded target/rank/alpha/stacking/hyperparameters, and the planned output identity. Remote/custom/native code and caller-declared safety overrides fail closed.

Focused evidence: **37 tests passed**, **139 adversarial cases**, vulnerable ASR **139/139**, hardened ASR **0/139**, hardened FPR **0/4**, SafeTaskRate **4/4**. Clean assessment SHA-256: `0c2091bc9f2e50842f2d4642c3aca39ff4e444cc15a41d639579d7b98ec77729`.

P9-C is an admission-policy proof. It does not prove that a trainer/GPU runtime executed the job or produced the planned output.

## P9-D — training-job identity, code/config/environment provenance, and secret/capability boundaries

Status: **implemented and deterministically exercised in an isolated API-compatible P9-D harness; hosted runner execution remains an external infrastructure dependency**.

P9-D adds `TrainingExecutionProvenanceAnalyzer`. It consumes the exact P9-C clean assessment and treats the synthetic launch boundary as a separate security decision instead of turning admission into an execution claim.

The canonical fixture binds:

- exact P9-C assessment, admission-manifest, principal/task, and planned-output identities;
- one synthetic scheduler job ID, namespace, queue, service account, executor principal, identity-token audience, attempt, and launch nonce;
- one immutable source repository/commit/tree/entrypoint plus entrypoint/config/dependency-lock SHA-256 values;
- one pinned trainer image, Python/framework/accelerator runtime, and one GPU device profile;
- an exact environment-variable allowlist, restricted network egress, read-only root filesystem, no host mounts, and two writable workspace paths;
- three ordered short-lived, non-exportable secret leases with exact provider/version/purpose/scope/mount/executor bindings; and
- four ordered least-privilege capabilities for dataset/base-model reads and checkpoint/output writes.

The hardened boundary denies or rejects swapped upstream evidence, scheduler/job substitution, source/config/lock/image substitution, remote/dynamic/custom code, privileged runtime settings, network/filesystem/device/environment expansion, missing/reordered/over-scoped/expired/exportable secrets, missing/reordered/wildcard capabilities, output substitution, stale/replayed requests, and caller-declared summaries that disagree with derived evidence.

The matched vulnerable baseline `VulnerableCallerDeclaredTrainingExecutionSafety` trusts caller-declared admission/job/code/environment/secret/capability/execution safety booleans.

### Focused deterministic evidence

An isolated API-compatible harness executed the exact P9-D implementation/evaluator/test files against the repository P9-C assessment dataclass contract:

- tests: **60 passed**;
- adversarial cases: **160**;
- vulnerable ASR: **160/160**;
- hardened ASR: **0/160**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- training-execution manifest SHA-256: `c05279a1d945b5261b5c39f696bd7be15d6d7ef14d70cb56537410e2c2056bbe`;
- adversarial dataset SHA-256: `3065fd48835db2ccc7dc3461e78a63cc21e365b265f20beabfc266c9856d953e`;
- fixture/evaluator evidence SHA-256: `b13c3bfb7aedab2cda9dc293f3f0ad7037080e7be2839ac39edebfdc40b272b6`;
- clean assessment SHA-256: `094b678ef6c3cff7a6751c6b2ec0765bef78e2546bd31fd7155476222080af3e`.

This is focused local P9-D evidence, **not** a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9d` is the explicit focused local path. The default verification path remains reserved for a real full local repository execution.

### Hosted CI boundary

`.github/workflows/phase9.yml` runs full `pytest` plus the P9-A through P9-D evaluators when a GitHub-hosted runner is actually provisioned. A GitHub job that executes zero steps because runner provisioning is blocked remains **REMOTE_CI_BLOCKED**, not a security-test failure and not a hosted CI pass.

### Claim boundary

P9-D is deterministic synthetic launch/provenance evidence. It does **not** claim production scheduler or identity-provider integration, real secret-manager delivery, enforced container/network/filesystem/GPU isolation, cryptographic workload or hardware attestation, proof that the training loop executed, proof that a produced adapter came from this launch, semantic model safety, distributed-training correctness, or production promotion.

No runtime dependency is added.

## Phase 9 roadmap

- **P9-A:** dataset provenance and holdout isolation — complete for current synthetic scope.
- **P9-B:** data poisoning, label integrity, and contributor/trust weighting — complete for current synthetic scope.
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding — complete for current synthetic scope.
- **P9-D:** training-job identity, code/config/environment provenance, and secret/capability boundaries — complete for current synthetic scope.
- **P9-E:** training checkpoint/resume integrity and rollback-safe lineage.
- **P9-F:** evaluation-set leakage and benchmark-contamination governance.
- **P9-G:** sensitive-data/PII/canary governance for training inputs and outputs.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance.
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.

The next milestone is **P9-E**, binding checkpoints and resume/rollback operations to the exact P9-D launch lineage without treating synthetic checkpoint metadata as production storage or runtime proof.
