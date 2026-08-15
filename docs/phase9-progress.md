# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 moves AegisDesk into a breadth domain that earlier phases only touched indirectly: **training-data, fine-tuning, and ML training-pipeline security**. Phase 5 secured model artifacts and serving supply-chain boundaries after a model exists; Phase 9 begins earlier in the lifecycle by treating training data and training transformations as security-sensitive provenance.

## P9-A — training-dataset provenance, immutable snapshots, and holdout isolation

Status: **implemented and deterministically exercised in an isolated P9-A harness; hosted runner execution remains an external infrastructure dependency**.

P9-A adds `TrainingDatasetProvenanceAnalyzer`. The hardened path does not accept a dataset merely because a caller labels it curated or safe. It binds a training dataset to exact source snapshots, immutable record digests, source-record identities, split membership, preprocessing-transform provenance, and a deterministic final dataset digest.

The canonical fixture contains:

- **3** source snapshots;
- **12** exact record identities;
- **6 training / 3 validation / 3 test** records;
- **3** deterministic preprocessing transforms; and
- zero network operations in the modeled transform path.

The hardened boundary enforces:

- exact manifest, dataset ID, dataset version, schema, and SHA-256 binding;
- trusted source-owner membership and owner-specific source URI prefixes;
- immutable policy-pinned source revision and snapshot SHA-256 values;
- source observation freshness relative to the manifest;
- exact record coverage;
- per-record payload SHA-256, source identity, source-record key, and parent-record binding;
- exact split coverage and assignment;
- duplicate/overlapping split denial;
- explicit validation/test holdout isolation from the training split;
- exact transform coverage/order;
- policy-pinned transform kind, owner, and configuration SHA-256;
- predecessor-transform hash continuity;
- deterministic input/output dataset-digest chaining;
- unexpected transform network-side-effect denial;
- exact final dataset digest pinning; and
- rejection of caller-declared source/count/split/final-digest/safety summaries that disagree with derived evidence.

The matched vulnerable baseline `VulnerableCallerDeclaredTrainingDataTrust` accepts caller assertions that training data is safe and provenance-complete.

### Focused deterministic evidence

The exact isolated P9-A implementation/evaluator/test files pass:

- tests: **21 passed**;
- adversarial cases: **157**;
- vulnerable ASR: **157/157**;
- hardened ASR: **0/157**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- training dataset manifest SHA-256: `5583a2a7bcebb464e1b305db178d57c7b6f74c706977701c8a1971fa62604eb6`;
- adversarial dataset SHA-256: `2d1123262971c1eb32cf9b7eb84a4ae241acac8c2a3a1340ff88ca47b45c2116`;
- fixture/evaluator SHA-256: `1fd9de08c533e8569c3d8265c261bab3a2f9a1a9c72f0ca1b4f264b5f58269ec`;
- clean assessment SHA-256: `b47663cd718ebe3493d2a0985301403a8925628b8d49a384b9d098f1822632c9`.

This is focused local P9-A execution. It is **not** a claim that full-repository pytest, GitHub-hosted Actions, a production data lake, a production trainer, or a production MLOps control plane executed successfully in the same run.

### Verification-state discipline

`scripts/verify_phase9.py --focused-p9a` provides a reproducible focused local path and emits `LOCAL_FOCUSED_PASS` only after the P9-A tests and evaluator execute successfully. The default `scripts/verify_phase9.py` path is reserved for a real full local repository test execution and should not be reported as passed unless it actually runs.

Hosted CI remains separate evidence. A GitHub job that is created but executes zero steps because a runner is not provisioned is recorded as infrastructure-blocked, not as a security-test failure and not as a CI pass.

### Claim boundary

P9-A SHA-256 bindings are deterministic integrity evidence in the lab; they are **not source authentication**. P9-A does not claim:

- cryptographic source signatures or transparency-log inclusion;
- production data-lake/object-store integration;
- production dataset access-control enforcement;
- production training-job attestation;
- semantic poisoning/backdoor detection;
- privacy/PII/consent/license compliance;
- benchmark-contamination detection beyond exact modeled split membership;
- proof that preprocessing code actually produced the declared output bytes;
- distributed append-only lineage storage;
- trusted timestamps; or
- formal end-to-end training-pipeline verification.

No runtime dependency is added.

## Phase 9 roadmap

P9-A establishes the provenance substrate. Later milestones should broaden training security rather than overload P9-A:

- **P9-B:** data poisoning, label integrity, and contributor/trust weighting;
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding;
- **P9-D:** training-job identity, code/config/environment provenance, and secret/capability boundaries;
- **P9-E:** training checkpoint/resume integrity and rollback-safe lineage;
- **P9-F:** evaluation-set leakage and benchmark-contamination governance;
- **P9-G:** sensitive-data/PII/canary governance for training inputs and outputs;
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance; and
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.
