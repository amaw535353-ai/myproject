# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 moves AegisDesk into training-data, fine-tuning, and ML training-pipeline security. Phase 5 secured model artifacts and serving supply-chain boundaries after a model exists; Phase 9 begins earlier in the lifecycle and treats data provenance, labeling, contributor trust, training execution, checkpointing, evaluation governance, and promotion as security-sensitive evidence.

## P9-A — training-dataset provenance, immutable snapshots, and holdout isolation

Status: **implemented and deterministically exercised in an isolated P9-A harness; hosted runner execution remains an external infrastructure dependency**.

P9-A adds `TrainingDatasetProvenanceAnalyzer`. It binds exact source snapshots, record digests and source keys, train/validation/test membership, preprocessing-transform provenance, and the final dataset SHA-256. Its focused evidence remains: 21 tests passed, 157 adversarial cases, vulnerable ASR 157/157, hardened ASR 0/157, hardened FPR 0/4, SafeTaskRate 4/4.

P9-A SHA-256 bindings are deterministic integrity evidence, not source authentication, and its earlier production non-claims remain unchanged.

## P9-B — data poisoning, label integrity, and contributor/trust weighting

Status: **implemented and deterministically exercised in an isolated API-compatible P9-B harness; hosted runner execution remains an external infrastructure dependency**.

P9-B adds `TrainingDataPoisoningAnalyzer`. It consumes exact P9-A assessment evidence rather than rebuilding provenance. The hardened path binds the P9-A assessment digest and final dataset digest, requires intact P9-A provenance/split/transform facts, and then evaluates the training records selected for inclusion.

The canonical fixture contains **8 training-record security records, 3 contributors, and 2 independent review records**. Two records come from a lower-trust reviewed contributor and therefore require payload-bound review evidence. Contributor weights, expected labels, record payload/source identity, anomaly thresholds, duplicate-cluster limits, poisoning-signal policy, and the final included-record set are policy owned.

The hardened boundary enforces:

- exact P9-B manifest/dataset/schema/SHA-256 and freshness;
- exact P9-A assessment SHA-256 and final-dataset SHA-256 binding;
- intact upstream P9-A manifest/source/record/split/transform evidence and zero modeled network operations;
- exact training-record coverage, payload digest, source identity, contributor identity, and expected label;
- policy-owned contributor trust tier and trust weight;
- contributor concentration limits;
- minimum label-confidence thresholds;
- anomaly-score and explicit poisoning-signal gates;
- duplicate-cluster amplification limits;
- trusted independent review below the policy-owned contributor-weight threshold;
- exact review record/payload/label/evidence-hash binding;
- rejection of conflicting/rejecting reviews;
- deterministic quarantine requirements and unnecessary-quarantine detection;
- exact derivation of the final included-record set; and
- rejection of caller-declared inclusion/quarantine/risk/safety/label-integrity summaries that disagree with derived evidence.

The matched vulnerable baseline `VulnerableCallerDeclaredTrainingDataSafety` trusts caller-declared training-data safety and label-integrity booleans.

### Focused deterministic evidence

An isolated API-compatible harness executed the exact P9-B implementation/evaluator/test files against a P9-A assessment interface matching the repository dataclass:

- tests: **19 passed**;
- adversarial cases: **112**;
- vulnerable ASR: **112/112**;
- hardened ASR: **0/112**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- P9-B manifest SHA-256: `11277f13642c4302973f479b2ebf9c8e228058e88e638f8e33d131ce9532eabb`;
- adversarial dataset SHA-256: `4523cbe3e021d10ff14f4f3bd67a103cdbab5311260e8147c25e2ce84c082340`;
- fixture/assessment evidence SHA-256: `6f1141de704927d761c4d39ff019d719d5615a68555d2adda1e3c56c38f7d7b9`;
- clean assessment SHA-256: `084afbd8c147ba60a414fee1bf0c32bf0c9cfcb6f4178ab237fb3a4b3483b193`.

This is focused P9-B evidence, not a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9b` is the explicit focused local path. The default script path remains reserved for a real full local repository execution.

### Hosted CI boundary

`.github/workflows/phase9.yml` now runs full `pytest`, P9-A, and P9-B when a GitHub-hosted runner is actually provisioned. A GitHub job with zero executed steps remains classified as infrastructure-blocked rather than a security-test failure or a hosted CI pass.

### Claim boundary

P9-B does **not** claim semantic poisoning or backdoor detection, production data-quality/labeling-platform integration, cryptographically authenticated human review, Byzantine-resilient contributor reputation, statistically robust poisoning detection, training-time influence analysis, causal poisoning attribution, or proof that a trained model is safe. Synthetic anomaly/signal values are deterministic control inputs, not validated detector outputs.

No runtime dependency is added.

## Phase 9 roadmap

- **P9-A:** dataset provenance and holdout isolation — complete for current synthetic scope.
- **P9-B:** data poisoning, label integrity, and contributor/trust weighting — complete for current synthetic scope.
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding.
- **P9-D:** training-job identity, code/config/environment provenance, and secret/capability boundaries.
- **P9-E:** training checkpoint/resume integrity and rollback-safe lineage.
- **P9-F:** evaluation-set leakage and benchmark-contamination governance.
- **P9-G:** sensitive-data/PII/canary governance for training inputs and outputs.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance.
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.

The next milestone is **P9-C**, using exact P9-A/P9-B evidence to secure fine-tune/LoRA/adapter authorization, base-model identity, permitted training targets, and adapter-to-base compatibility without claiming a real trainer or GPU runtime.
