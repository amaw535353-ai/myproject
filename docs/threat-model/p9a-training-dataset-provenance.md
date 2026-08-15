# P9-A threat model — training-dataset provenance and holdout isolation

## Security objective

A training run should consume only the exact dataset snapshot authorized by policy. Dataset identity must not be replaceable by mutable aliases, caller assertions, record substitutions, split reassignment, or undeclared preprocessing lineage.

## Protected assets

- source snapshot identity, revision, owner, and digest;
- immutable training-record identity and payload digest;
- source-record provenance;
- training/validation/test split assignment;
- evaluation holdout isolation;
- preprocessing transform order/configuration/ownership;
- transform-chain and final dataset digests; and
- evidence-derived training-data safety state.

## Adversary capabilities modeled

The deterministic adversary can alter manifest/request fields, substitute sources or revisions, change record digests/source keys/parents, remove or add records, move or overlap split membership, alter preprocessing metadata, reorder transforms, introduce transform network activity, substitute final dataset digests, and lie in caller-declared summaries.

The adversary does **not** control the trusted policy object in the security claim. A small set of policy-drift test cases verifies fail-closed behavior when trusted-owner pins are removed, but P9-A does not claim protection from malicious compromise of the policy authority itself.

## Trust boundaries

The caller request is untrusted. Source owners, URI prefixes, revisions, source snapshot digests, record evidence, split assignments, transform profiles, and final dataset digest are policy-owned facts. The manifest is evidence to verify, not authority to define its own trust.

## Hardened invariants

1. The manifest must match the exact policy-pinned dataset identity and SHA-256.
2. Source coverage must match policy and every source must satisfy owner, URI-prefix, revision, digest, and freshness constraints.
3. Record coverage and record-level source/key/digest/parent bindings must match policy.
4. Every record must occupy exactly one expected split.
5. Validation/test holdout records must not also appear in training.
6. Preprocessing transforms must match exact policy-owned order/kind/owner/configuration profiles.
7. Transform input/output and predecessor hashes must form a deterministic continuous chain.
8. The final dataset digest must equal both the derived chain head and the policy pin.
9. Modeled preprocessing performs zero network operations.
10. Caller-declared safety/provenance summaries cannot override derived facts.

## Residual risk and non-claims

SHA-256 does not authenticate who produced source data. The lab does not verify real object-store immutability, signed dataset receipts, transparency logs, real training execution, actual preprocessing byte-for-byte execution, semantic poisoning, label correctness, privacy/consent/license state, or distributed rollback resistance. Those are separate future controls.
