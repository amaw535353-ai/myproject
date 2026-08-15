# P9-B threat model — training-data poisoning, label integrity, and contributor trust

## Security objective

P9-B consumes the exact P9-A training-dataset provenance assessment and decides whether the training records selected for model training remain acceptable after contributor, labeling, review, duplicate-cluster, anomaly, poisoning-signal, and quarantine controls are applied.

The hardened boundary must not trust caller statements that training data is safe or correctly labeled. It derives its decision from policy-pinned evidence and fails closed when the upstream P9-A assessment or the P9-B evidence chain is inconsistent.

## Assets and trust boundaries

Assets under protection are the training record payload identities, expected labels, contributor attribution, contributor trust weights, review evidence, quarantine decisions, and final included-record set. P9-A provenance is an upstream trust dependency. Contributor and reviewer identities are deterministic lab identities, not production authenticated principals.

## Modeled attacker goals

The adversarial corpus covers record/content substitution, source substitution, label flipping, confidence manipulation, anomaly-score manipulation, poisoning-signal injection, contributor laundering, contributor trust/weight manipulation, contributor concentration, duplicate-cluster amplification, missing or forged reviews, reviewer substitution, review-label conflicts, quarantine bypass, inclusion-set tampering, upstream P9-A degradation/substitution, and caller-summary/request rebinding attacks.

## Hardened invariants

The analyzer requires exact P9-A assessment/final-dataset binding; intact P9-A provenance/split/transform flags; exact record coverage/digests/source/contributor/label pins; policy-owned contributor trust and weight; concentration limits; minimum label confidence; anomaly and poisoning-signal thresholds; duplicate-cluster limits; independent trusted review below a policy weight threshold; payload-bound review evidence; deterministic quarantine requirements; and exact included-record derivation.

Caller-declared training safety, label integrity, quarantine state, inclusion state, or weighted risk cannot override derived evidence.

## Claim boundary

P9-B is a deterministic security-control lab. The anomaly and poisoning-signal values are supplied synthetic evidence, not a validated poisoning detector. Reviewer identities are allowlisted strings with deterministic hashes, not cryptographically authenticated humans. The contributor-weighting policy is a lab governance mechanism, not a statistical guarantee or reputation system.

P9-B does not claim semantic poisoning/backdoor detection, production dataset quality monitoring, production labeling-platform integration, production human-review authentication, Byzantine contributor resistance, robust statistics, differential privacy, training-time influence analysis, causal attribution, or proof that a trained model is free from poisoned behavior.
