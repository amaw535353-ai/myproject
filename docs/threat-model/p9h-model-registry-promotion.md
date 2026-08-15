# P9-H — training-to-model-registry promotion and Phase 5 provenance handoff

## Security boundary

P9-H treats promotion of a trained artifact into the model supply chain as a separate admission decision. `ModelRegistryPromotionAnalyzer` consumes exact P9-G evidence and binds the training lineage, final checkpoint artifact, promoted component closure, promotion authorization, immutable registry identity, rollback/revocation metadata, and a deterministic bridge to the existing Phase 5 artifact/package/registry provenance schemas.

The boundary fails closed on P9-G substitution or invalid upstream claims; checkpoint/job/execution/model substitution; missing, reordered, role-swapped, digest-swapped, size-swapped, format-swapped, or untrusted-source artifacts; Phase 5 policy/schema/package/release bridge substitution; mutable tags or versions; overwrite or mutable-alias requests; authorization principal/grant/action/target/digest or time-window substitution; predecessor/rollback/revocation mismatch; and unexpected modeled network operations.

The Phase 5 bridge binds the exact P5-A artifact policy/schema, P5-B package policy/schema, and P5-C registry policy/release schema. Artifact roles use `ModelPackageComponentRole`, and the promotion policy restricts the modeled handoff to the Phase 5 data-only `safetensors`/`onnx` formats with exactly one primary-model component. P9-H does not replace Phase 5 signature, package-closure, registry acquisition, key-lifecycle, scanning, runtime, privacy, or deployment checks.

## Claim boundary

This is deterministic synthetic promotion evidence. SHA-256 provides integrity binding, not source authentication. The assessment does not claim a registry write occurred, production registry integration, cryptographic promotion signing, deployment execution, end-to-end key authenticity, semantic model safety, representative evaluation, complete privacy guarantees, or propagated revocation in a real serving fleet.
