# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 moves AegisDesk into training-data, fine-tuning, and ML training-pipeline security. Phase 5 secured model artifacts and serving supply-chain boundaries after a model exists; Phase 9 begins earlier in the lifecycle and treats data provenance, labeling, contributor trust, fine-tuning admission, training execution, checkpointing, evaluation governance, and promotion as security-sensitive evidence.

## P9-A — training-dataset provenance, immutable snapshots, and holdout isolation

Status: **implemented and deterministically exercised in an isolated P9-A harness; hosted runner execution remains an external infrastructure dependency**.

P9-A adds `TrainingDatasetProvenanceAnalyzer`. It binds exact source snapshots, record digests and source keys, train/validation/test membership, preprocessing-transform provenance, and the final dataset SHA-256. Its focused evidence remains: 21 tests passed, 157 adversarial cases, vulnerable ASR 157/157, hardened ASR 0/157, hardened FPR 0/4, SafeTaskRate 4/4.

P9-A SHA-256 bindings are deterministic integrity evidence, not source authentication, and its earlier production non-claims remain unchanged.

## P9-B — data poisoning, label integrity, and contributor/trust weighting

Status: **implemented and deterministically exercised in an isolated API-compatible P9-B harness; hosted runner execution remains an external infrastructure dependency**.

P9-B adds `TrainingDataPoisoningAnalyzer`. It consumes exact P9-A assessment evidence rather than rebuilding provenance. The hardened path binds the P9-A assessment digest and final dataset digest, verifies contributor/label/review/quarantine facts, and derives the exact included training-record set.

Focused evidence remains: 19 tests passed, 112 adversarial cases, vulnerable ASR 112/112, hardened ASR 0/112, hardened FPR 0/4, SafeTaskRate 4/4. P9-B does not claim validated semantic poisoning detection, production labeling-platform integration, cryptographically authenticated human review, causal poisoning attribution, or proof that a trained model is safe.

## P9-C — fine-tuning/LoRA/adapter authorization and base-model binding

Status: **implemented and deterministically exercised in an isolated API-compatible P9-C harness; hosted runner execution remains an external infrastructure dependency**.

P9-C adds `FineTuningAdmissionAnalyzer`. It consumes exact P9-B assessment evidence, which transitively binds P9-A. The admission boundary treats a fine-tuning request as a security-sensitive capability rather than trusting caller-selected data, base model, adapter configuration, or training parameters.

The canonical fixture contains:

- one policy-pinned training principal and task authorization;
- the exact eight P9-B included training-record identities;
- one immutable base-model identity/revision plus artifact/package/tokenizer SHA-256 values;
- two ordered adapter specifications (`LoRA` then a policy adapter);
- `safetensors` as the modeled safe serialization format;
- policy-owned target modules, rank/alpha/stack-depth limits, and hyperparameter bounds; and
- one exact planned output artifact identity.

The hardened boundary enforces:

- exact P9-C manifest/dataset/schema/SHA-256 and freshness;
- exact P9-B assessment SHA-256 plus intact P9-B provenance/record/label/contributor/poisoning evidence;
- exact selected-record equality with the P9-B included-record set;
- a deterministic selected-data SHA-256 bound to the P9-B assessment and selected records;
- exact principal, task, grant, P9-B digest, base-artifact digest, and selected-data digest authorization binding;
- authorization validity windows and policy-constrained allowed fine-tuning modes;
- exact base-model ID, immutable revision, artifact/package/tokenizer SHA-256, and runtime-profile pins;
- exact adapter order/coverage and parent-before-child stacking;
- mode allowlisting and denial of full-model fine-tuning in the canonical policy;
- `safetensors` serialization allowlisting;
- bounded adapter rank/alpha and target-module allowlisting;
- exact adapter initialization SHA-256 pins;
- denial of remote code, custom code, and native-extension requests;
- bounded deterministic learning-rate, epoch, batch, step, seed, and gradient-accumulation policy;
- exact planned output artifact identity; and
- rejection of caller-declared selected data, base binding, adapter safety, authorization, or overall admission summaries that disagree with derived evidence.

The matched vulnerable baseline `VulnerableCallerDeclaredFineTuningSafety` trusts caller-declared authorization, base-model binding, adapter safety, and overall admission booleans.

### Focused deterministic evidence

An isolated API-compatible harness executed the exact P9-C implementation/evaluator/test files against the repository P9-B assessment dataclass contract:

- tests: **37 passed**;
- adversarial cases: **139**;
- vulnerable ASR: **139/139**;
- hardened ASR: **0/139**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- fine-tuning manifest SHA-256: `19b893dac6ed7f3003df7ad5b35fe2c3b8a20d4823f678a9b19f1ed342254254`;
- adversarial dataset SHA-256: `43ddd6a3ce3105a49bf023ba68265871dd1780b18ecc85ba1b2af975d5ce8c74`;
- fixture/evaluator evidence SHA-256: `c77ca7e352b0412553a6f9650e1524656772bd56cd3e3b2da428bcb74fbd5224`;
- clean assessment SHA-256: `0c2091bc9f2e50842f2d4642c3aca39ff4e444cc15a41d639579d7b98ec77729`.

This is focused local P9-C evidence, not a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9c` is the explicit focused local path. The default script path remains reserved for a real full local repository execution.

### Hosted CI boundary

`.github/workflows/phase9.yml` runs full `pytest` plus P9-A, P9-B, and P9-C evaluators when a GitHub-hosted runner is actually provisioned. A GitHub job with zero executed steps remains classified as infrastructure-blocked rather than a security-test failure or a hosted CI pass.

### Claim boundary

P9-C is a deterministic **admission-policy** proof. It does **not** claim a real fine-tuning trainer or GPU runtime, production IAM/identity-provider integration, production scheduler enforcement, proof that the configured training job executed, proof that an output adapter was produced by the admitted job, semantic adapter/backdoor safety, cryptographic authorization signatures, hardware attestation, secure GPU isolation, distributed training correctness, or production artifact promotion.

No runtime dependency is added.

## Phase 9 roadmap

- **P9-A:** dataset provenance and holdout isolation — complete for current synthetic scope.
- **P9-B:** data poisoning, label integrity, and contributor/trust weighting — complete for current synthetic scope.
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding — complete for current synthetic scope.
- **P9-D:** training-job identity, code/config/environment provenance, and secret/capability boundaries.
- **P9-E:** training checkpoint/resume integrity and rollback-safe lineage.
- **P9-F:** evaluation-set leakage and benchmark-contamination governance.
- **P9-G:** sensitive-data/PII/canary governance for training inputs and outputs.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance.
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.

The next milestone is **P9-D**, using exact P9-C admission evidence to bind the actual synthetic training-job identity, code/config/environment provenance, secret scopes, capabilities, and execution boundary without turning admission evidence into a claim that a production trainer executed.
