# Phase 9 progress — secure AI training and dataset lifecycle

Phase 9 treats training data, fine-tuning admission, training execution, checkpointing, evaluation governance, sensitive-data handling, and promotion as security-sensitive evidence.

## P9-A through P9-F

- **P9-A:** dataset provenance and holdout isolation — complete for current synthetic scope.
- **P9-B:** poisoning, label integrity, and contributor trust — complete for current synthetic scope.
- **P9-C:** fine-tuning/LoRA/adapter authorization — complete for current synthetic scope.
- **P9-D:** training execution provenance and least privilege — complete for current synthetic scope.
- **P9-E:** checkpoint/resume integrity and rollback-safe lineage — complete for current synthetic scope.
- **P9-F:** evaluation leakage and benchmark-contamination governance — complete for current synthetic scope.

Hosted runner execution remains an external infrastructure dependency. A GitHub job that executes zero steps because runner provisioning is blocked is `REMOTE_CI_BLOCKED`, not a security-test failure and not a hosted CI pass.

## P9-G — sensitive-data, PII, secret, and canary governance

Status: **complete for the current deterministic synthetic scope; hosted runner execution remains an external infrastructure dependency**.

`SensitiveDataGovernanceAnalyzer` consumes exact P9-F assessment evidence and binds policy-owned scanner/canary profiles, ordered training/evaluation/output records, content and sanitized-content digests, finding IDs/evidence digests, sensitivity classes, dispositions, training inclusion, output identity, output-batch digest, and zero modeled network operations.

The canonical fixture includes public records, two modeled PII records that must be redacted, one modeled API secret and one canary that must be quarantined from training, and two clean model outputs. Any modeled PII, secret, or canary finding in an output fails closed. Caller-declared safety summaries cannot override derived evidence.

### Focused deterministic evidence

- tests: **21 passed**;
- adversarial cases: **114**;
- vulnerable ASR: **114/114**;
- hardened ASR: **0/114**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- sensitive-data manifest SHA-256: `4dfb72a686f3fc12980d03317b251be9c712fa6cff0a194d9ad7e0728203d85c`;
- adversarial dataset SHA-256: `a279bec3e3bfb374b6f6b8f4a86d64dc6580101660721689cc2b8fd86bc524b1`;
- fixture/evaluator evidence SHA-256: `aca0df27c879a37d2b8dc926ff9fe9ccabb366047e955e1582285371c0632b01`;
- clean assessment SHA-256: `5f6fef4642e0f9d390ba7a7745f74290176608e4f0e24eafff7cb3de28cc5849`.

This is focused local P9-G evidence, **not** a full-repository pytest claim. `scripts/verify_phase9.py --focused-p9g` is the explicit focused path.

### Claim boundary

P9-G is deterministic synthetic governance evidence. It does **not** claim comprehensive PII/secret detection, production DLP or redaction enforcement, consent/license/legal compliance, cryptographic scanner authentication, differential privacy, membership-inference resistance, memorization absence, or proof that a real model emitted the modeled outputs.

No runtime dependency is added.

## Phase 9 roadmap

- **P9-A:** complete.
- **P9-B:** complete.
- **P9-C:** complete.
- **P9-D:** complete.
- **P9-E:** complete.
- **P9-F:** complete.
- **P9-G:** complete for current synthetic scope.
- **P9-H:** training-to-model-registry promotion evidence binding into Phase 5 provenance.
- **P9-I:** integrated training compromise exercise and machine-readable Phase 9 exit gate.

The next milestone is **P9-H**, binding the exact Phase 9 training/evaluation/privacy evidence into model-registry promotion without treating synthetic lineage as production registry attestation.
