# P9-F threat model — evaluation-set leakage and benchmark contamination

## Security objective

P9-F determines whether a synthetic benchmark result is admissible as contamination-governed evaluation evidence. It consumes exact P9-E checkpoint evidence and separately pins a deterministic training-exposure summary so the evaluation set cannot silently reuse training records, canonical fingerprints, transform fingerprints, or declared training-derived examples.

## Modeled attacker capabilities

The attacker may substitute or reorder benchmark records, alter labels or payload digests, point at a different benchmark/version/split/source/revision, introduce training-record or fingerprint overlap, declare training derivation, expose hidden labels, use dynamic/external evaluation data, change few-shot examples, scoring code, prompt template, metrics, sample count, seed, inference settings, evaluation network operations, result records, output-evidence digest, score, checkpoint identity, or caller-declared trust summaries.

The trusted policy object is outside the modeled adversary's compromise.

## Hardened invariants

`EvaluationBenchmarkGovernanceAnalyzer` requires exact P9-E assessment/checkpoint binding; a policy-pinned training-exposure digest; immutable benchmark identity/source/snapshot and record pins; zero exact record-ID/canonical-fingerprint/transform-fingerprint overlap with training exposure; no declared training-derived evaluation record; no hidden-label exposure, dynamic generation, or external fetch; exact scoring/prompt/metric/few-shot/seed/sample/inference configuration; zero modeled evaluation network operations; exact result/checkpoint/record/output/score evidence; and caller summaries that match derived facts.

## Claim boundary

The overlap checks are exact deterministic fingerprints over the modeled synthetic evidence. P9-F does not claim semantic near-duplicate detection, benchmark secrecy, production benchmark-registry integration, independent score recomputation from model outputs, protection against previously unknown training exposure, cryptographic source authentication, trusted timestamps, or proof that a real model evaluation executed. A contamination-clear P9-F assessment means the modeled evidence passed these exact gates, not that a benchmark is universally uncontaminated.
