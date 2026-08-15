# P9-C threat model — fine-tuning authorization and base-model binding

## Security objective

Prevent a fine-tuning/LoRA/adapter request from gaining authority merely because the caller claims it is approved. P9-C must bind the admitted training request to exact P9-B data evidence, the authorized principal/task, immutable base-model evidence, policy-constrained adapter configuration, and bounded hyperparameters.

## Assets and trust boundaries

Protected assets are the training authorization, the selected P9-B record set, base-model identity/digests, adapter configuration, and planned output identity. Caller-supplied request summaries, model-visible text, untrusted adapter metadata, mutable aliases, and arbitrary code requests are outside the trusted boundary.

P9-B assessment evidence is trusted only after exact digest/schema/mode/non-claim checks. P9-C consumes the P9-B assessment as transitive P9-A/P9-B evidence; it does not independently rediscover dataset provenance or poisoning facts.

## Modeled attacks

The deterministic corpus covers degraded/swapped P9-B evidence, selected-record and selected-data substitution, grant/principal/task confused-deputy attempts, authorization expiry and digest substitution, base-model/revision/artifact/package/tokenizer/runtime substitution, unauthorized fine-tuning modes, unsafe adapter serialization, excessive rank/alpha, unauthorized target modules, adapter-init substitution, invalid adapter stacking, remote/custom/native code requests, hyperparameter escape, output-identity substitution, stale manifests, and caller-summary substitution.

## Controls

`FineTuningAdmissionAnalyzer` fails closed on exact policy/evidence mismatch. It requires selected records to equal the P9-B included set, binds a deterministic selected-data digest, verifies authorization binding and freshness, pins the complete modeled base-model identity, applies ordered adapter allowlists and stack constraints, denies code-bearing adapter paths, enforces bounded hyperparameters, and derives the final allow/deny decision independently of caller safety booleans.

## Residual assumptions and non-claims

This milestone is a synthetic admission gate. SHA-256 values provide deterministic integrity binding but not authenticated provenance on their own. The authorization record is modeled evidence rather than a production signed IAM capability.

P9-C does not claim a production trainer/GPU runtime, production identity-provider or scheduler integration, proof of training execution, secure multi-node/distributed training, hardware or confidential-compute attestation, semantic adapter/backdoor safety, proof that the planned output artifact came from this admission, or promotion of the result into a production model registry.
