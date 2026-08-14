# P5-F threat model — model poisoning and backdoor indicators

## Security objective

P5-F prevents AegisDesk from treating provenance validity and runtime isolation as proof that model contents are benign. A release that passed P5-B provenance and P5-E runtime admission must also satisfy a release-scoped model-scan evidence policy before deployment handoff.

The strong property is intentionally narrow:

> A provenance-valid, runtime-admissible model release is rejected when deterministic scan evidence shows modeled poisoning/backdoor indicators, when required evidence coverage is incomplete, or when scan evidence is not bound to the deployment-pinned artifact digests.

Passing P5-F means only that the modeled indicators were not observed in the supplied deterministic evidence. It does **not** prove absence of a backdoor, poisoning, unsafe behavior, or exploitable model internals.

## Assets and trust boundaries

Protected assets:

- approved model/package identity;
- P5-B verified package closure and role mapping;
- P5-E verified non-executing runtime plan;
- release-scoped artifact SHA-256 pins used as scan subjects;
- required scan profile, baseline, scanner identity, and probe coverage;
- deployment decision that consumes the P5-F verified scan handle.

Trust boundaries:

1. P5-B establishes provenance and exact component closure.
2. P5-E establishes a deny-by-default runtime plan without parsing/executing model bytes.
3. P5-F consumes synthetic scan statistics/config/tokenizer/probe evidence and policy-pinned artifact digests.
4. A later deployment integration may consume the verified P5-F handle, but P5-F itself performs no inference or raw tensor parsing.

## Adversary capabilities

The modeled attacker may provide a model release that is otherwise correctly signed and provenance-valid, or may tamper with the scan-evidence envelope. The attacker may attempt to:

- hide NaN/Inf-style corruption or extreme tensor magnitude indicators;
- concentrate suspicious high-magnitude outliers or sparse spikes;
- add trigger-like tokenizer tokens;
- add trigger/routing markers to configuration evidence;
- produce synthetic probe evidence showing a trigger-targeted response or clean-utility collapse;
- omit suspicious artifacts or required probes from scan coverage;
- substitute scan evidence from a different artifact digest, role, profile, baseline, scanner, release, or runtime;
- bypass scanning by supplying degraded P5-B or P5-E handles.

The adversary is **not** modeled as compromising the Python process itself or forging arbitrary dataclass instances inside the trusted process boundary.

## Hardened controls

`ModelPoisoningBackdoorScanner` enforces:

- intact non-executing P5-B verified-package handle;
- intact non-executing P5-E verified-runtime handle;
- exact package/model/revision/runtime identity binding;
- exact scanner/profile/baseline binding;
- policy digest pins that exactly cover the verified package component set;
- scan evidence that exactly covers the verified package component set;
- exact component-role preservation;
- per-artifact scan-subject SHA-256 equality to deployment policy;
- deterministic evidence-shape/range validation;
- zero-tolerance non-finite value policy;
- bounded maximum absolute statistic, outlier density, and sparse-spike density;
- trigger-like tokenizer fragment rejection;
- forbidden config trigger/routing marker rejection;
- exact required synthetic-probe coverage;
- minimum probe reproducibility count;
- bounded targeted trigger-response lift and clean-utility degradation;
- canonical SHA-256 evidence digest in the accepted handle.

The hardened path never executes model code and does not parse raw model/tensor bytes.

## Matched vulnerable baseline

`VulnerableProvenanceOnlyModelScanner` deliberately treats provenance/runtime approval as sufficient and accepts the supplied scan-evidence declaration without checking statistical indicators, trigger markers, coverage, subject digests, or probe results. It remains inert and never executes model bytes.

## Deterministic adversarial cases

P5-F evaluates sixteen fixed cases:

1. non-finite tensor values;
2. extreme maximum weight magnitude;
3. dense outlier population;
4. sparse high-magnitude spikes;
5. trigger-like tokenizer token;
6. config trigger/router marker;
7. targeted trigger-response anomaly;
8. clean-utility collapse;
9. missing artifact scan coverage;
10. artifact subject-digest substitution;
11. artifact role confusion;
12. missing required probe;
13. scanner/profile substitution;
14. degraded runtime handle;
15. degraded package handle;
16. scan release-identity substitution.

Three benign cases cover a clean approved baseline, a benign tokenizer extension, and elevated-but-in-policy weight statistics.

## Evidence hygiene

All evidence is fixed and synthetic. The lab performs:

- no raw model-byte scanning;
- no real tensor parsing;
- no real inference;
- no training-data inspection;
- no network operations;
- no model downloads;
- no GPU operations;
- no arbitrary code execution.

The scaled tensor statistics and probe outcomes are deterministic fixtures designed to exercise policy logic, not measurements from a production model scanner.

## Explicit non-claims

P5-F does not claim:

- that static statistics prove a model is backdoor-free;
- semantic or behavioral model safety;
- real safetensors/ONNX tensor scanning;
- memory-safe parser behavior;
- real inference-based backdoor testing;
- training-data poisoning detection;
- neural-cleanse/spectral-signature/activation-clustering equivalence;
- robustness to adaptive attackers who know the scanner;
- scanner binary integrity or remote attestation;
- signed scanner reports or transparency-log inclusion;
- production threshold calibration;
- protection from compromised deployment hosts;
- privacy, extraction, membership-inference, or memorization defenses.

## Residual risk and next breadth move

The largest residual gap is that P5-F trusts a deterministic evidence contract rather than a production scanner/attested measurement pipeline, and passing its indicators cannot establish model behavioral safety. The next breadth milestone should leave poisoning heuristics and cover **model privacy/extraction and membership-inference controls**, with explicit query budgets, output minimization, and deterministic attack/defense evidence.
