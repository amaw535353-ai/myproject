# P9-E threat model — checkpoint/resume integrity and rollback-safe lineage

## Security objective

Prevent a caller from substituting, reordering, mutating, cross-loading, or rolling back synthetic training checkpoints without exact evidence binding to the authorized P9-D execution lineage.

## Assets

The protected assets are checkpoint lineage identity, training job/execution identity, model state, optimizer state, RNG state, data-cursor state, trainer state, checkpoint artifact identity, active checkpoint selection, resume/rollback semantics, and operation authorization.

## Trust boundary

P9-D admission/execution evidence is upstream evidence, not proof that a production trainer ran. P9-E accepts only the exact policy-pinned P9-D assessment digest and its fail-closed verification flags. Caller declarations are untrusted.

## Threats covered

The analyzer models:

- cross-job or cross-execution checkpoint substitution;
- checkpoint deletion, insertion, reordering, and duplicate identities;
- parent-chain breaks and non-monotonic training steps;
- model/optimizer/RNG/data-cursor/trainer-state substitution;
- checkpoint artifact digest substitution;
- unsafe serialization, mutable checkpoint artifacts, external references, and custom deserializers;
- resume source/target substitution and invalid next-step progression;
- rollback without explicit authorization or to a non-allowlisted target;
- expired/mismatched operation authorization;
- stale/replayed requests; and
- caller-declared summaries that disagree with derived evidence.

## Deliberate non-claims

This milestone does not provide production checkpoint storage, atomic object-store guarantees, cryptographic signatures, trusted timestamps, hardware attestation, proof that resume or rollback executed, distributed optimizer synchronization, GPU state restoration, semantic model safety, or production promotion.

SHA-256 bindings are deterministic tamper evidence inside this lab model; they are not origin authentication.
