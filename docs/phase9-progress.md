# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 treats training data, fine-tuning admission, training execution, checkpointing, evaluation governance, sensitive-data handling, and promotion as security-sensitive evidence.

## P9-A through P9-E

- **P9-A — dataset provenance and holdout isolation:** complete for current synthetic scope. Focused evidence: 21 tests, 157 adversarial cases, vulnerable ASR 157/157, hardened ASR 0/157, FPR 0/4, SafeTaskRate 4/4.
- **P9-B — poisoning, label integrity, contributor trust:** complete for current synthetic scope. Focused evidence: 19 tests, 112 adversarial cases, vulnerable ASR 112/112, hardened ASR 0/112, FPR 0/4, SafeTaskRate 4/4.
- **P9-C — fine-tuning/LoRA/adapter authorization:** complete for current synthetic scope. Focused evidence: 37 tests, 139 adversarial cases, vulnerable ASR 139/139, hardened ASR 0/139, FPR 0/4, SafeTaskRate 4/4.
- **P9-D — training execution provenance and least privilege:** complete for current synthetic scope. Focused evidence: 60 tests, 160 adversarial cases, vulnerable ASR 160/160, hardened ASR 0/160, FPR 0/4, SafeTaskRate 4/4.
- **P9-E — checkpoint/resume integrity and rollback-safe lineage:** complete for current synthetic scope. Focused evidence: 16 tests, 89 adversarial cases, vulnerable ASR 89/89, hardened ASR 0/89, FPR 0/4, SafeTaskRate 4/4.

Hosted runner execution remains an external infrastructure dependency. A GitHub job that executes zero steps because runner provisioning is blocked is classified as `REMOTE_CI_BLOCKED`, not as a security-test failure and not as a hosted CI pass.

## P9-F — evaluation-set leakage and benchmark-contamination governance

Status: **implemented and deterministically exercised in an isolated API-compatible P9-F harness; hosted runner execution remains an external infrastructure dependency**.

P9-F adds `EvaluationBenchmarkGovernanceAnalyzer`. It consumes exact P9-E assessment/checkpoint evidence and binds a separate policy-owned training-exposure summary so evaluation data cannot silently overlap the modeled training exposure.

The canonical fixture binds one immutable held-out benchmark/version/test split, six exact evaluation records, eight modeled training-record identities plus canonical/transform fingerprints, exact benchmark source/revision/snapshot evidence, deterministic scoring and prompt-template digests, two fixed few-shot examples, metric order, seed/sample/inference settings, zero modeled network operations, and one exact result/checkpoint/output-evidence/score tuple.

The hardened boundary denies or rejects swapped P9-E/checkpoint evidence, modified training-exposure summaries, benchmark source/version/split/revision substitution, missing/reordered/tampered evaluation records, training record-ID overlap, canonical-fingerprint overlap, transform-fingerprint overlap, training-derived records, hidden-label exposure, dynamic/external data, changed scoring/prompt/metric/few-shot/seed/sample/inference settings, unexpected network operations, result or score substitution, stale/replayed requests, and caller-declared performance trust that disagrees with derived evidence.

The matched vulnerable baseline `VulnerableCallerDeclaredEvaluationSafety` trusts caller-declared upstream, benchmark-provenance, contamination, protocol, and performance-claim booleans.

### Focused deterministic evidence

An isolated API-compatible harness executed the exact P9-F implementation/evaluator/test files against the P9-E assessment dataclass contract:

- tests: **21 passed**;
- adversarial cases: **101**;
- vulnerable ASR: **101/101**;
- hardened ASR: **0/101**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- evaluation benchmark manifest SHA-256: `3a2e67ac73b68fbcfda37779429735cd4d9acdc72056e02eea79efa908c20231`;
- adversarial dataset SHA-256: `63cc47f859060227889dcbfb8d6c238bcf1930cd4aa5313b7118b52b6aa98949`;
- fixture/evaluator evidence SHA-256: `73c2a0276bbdc6884f19245927233afb394e42ccead1d428f52cc54c48a900ad`;
- clean assessment SHA-256: `53247ee9ca6297451a63910cbb9fdca19588d6fa76d1bd8b50b3ccabcab0ac03`.

This is focused local P9-F evidence, **not** a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9f` is the explicit focused local path. The default verification path remains reserved for a real full local repository execution.

### Claim boundary

P9-F is deterministic synthetic contamination-governance evidence. Exact fingerprints do not prove semantic near-duplicate detection. P9-F does **not** claim production benchmark-registry integration, hidden-benchmark secrecy, independent score recomputation from model outputs, cryptographic benchmark authentication, trusted timestamps, actual model evaluation execution, or universal absence of training contamination.

No runtime dependency is added.

## Phase 9 roadmap

- **P9-A:** dataset provenance and holdout isolation — complete for current synthetic scope.
- **P9-B:** data poisoning, label integrity, and contributor/trust weighting — complete for current synthetic scope.
- **P9-C:** fine-tuning/LoRA/adapter authorization and base-model binding — complete for current synthetic scope.
- **P9-D:** training-job identity, code/config/environment provenance, and secret/capability boundaries — complete for current synthetic scope.
- **P9-E:** training checkpoint/resume integrity and rollback-safe lineage — complete for current synthetic scope.
- **P9-F:** evaluation-set leakage and benchmark-contamination governance — complete for current synthetic scope.
- **P9-G:** sensitive-data/PII/canary governance for training inputs and outputs.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance.
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.

The next milestone is **P9-G**, using exact upstream training/evaluation evidence to govern sensitive-data, PII, secret, and canary exposure without claiming production DLP or semantic privacy guarantees.
