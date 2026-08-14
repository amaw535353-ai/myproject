# Phase 5 progress — model and AI supply-chain security

Phase 5 broadens AegisDesk beyond checkpoint and agent-runtime hardening into model artifacts, provenance, dependency trust, registry acquisition, and model-runtime supply-chain boundaries.

## P5-A — model artifact provenance and safe loading

Status: **implemented and deterministically evaluated**.

P5-A adds an inert pre-runtime model-artifact gate with:

- caller-bound artifact/model/revision identity;
- SHA-256 payload binding;
- Ed25519 signed manifests;
- pinned trusted publishers;
- publisher-specific trusted source prefixes;
- explicit data-format allowlisting;
- rejection of signed-but-unsafe serialization formats;
- a non-deserializing verified artifact handle;
- no model downloads, no real registry credentials, no arbitrary payload execution, and no network operations.

Deterministic evaluation:

- vulnerable ASR: 4/4;
- hardened ASR: 0/4;
- hardened FPR: 0/2;
- hardened SafeTaskRate: 2/2.

P5-A deliberately does not claim that real ONNX or safetensors parsing/execution is safe. Those format labels are accepted only for a verified opaque handoff.

## P5-B — transitive model-package and adapter provenance

Status: **implemented and deterministically evaluated**.

P5-B extends trust from one primary model blob to the exact signed dependency closure that may accompany it:

- one caller-bound signed package manifest;
- exactly one primary model;
- config and tokenizer components;
- LoRA/PEFT-style adapter role policy represented by inert adapter fixtures;
- quantization metadata and external-data shard roles;
- exact missing/extra component closure checks;
- package-signed component publisher/digest/size pins that reject later same-ID substitutions even from an otherwise trusted publisher;
- role-specific publisher authorization;
- dependency-reference and cycle validation;
- explicit remote-code requirement rejection;
- nested P5-A provenance validation for every transitive component;
- opaque non-deserializing package handoff with zero network operations.

Deterministic evaluation:

- vulnerable ASR: 9/9;
- hardened ASR: 0/9;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3.

The attacks cover missing and injected components, a globally trusted but role-disallowed adapter publisher, remote-code requirements, transitive payload tampering, cyclic dependencies, forged package signatures, package-identity substitution, and same-publisher component substitution outside the package-signed digest pin.

P5-B still does not claim semantic safety of model/config/tokenizer/adapter content, safe execution of real model formats, production registry integrity, production signing-key custody, or model-behavior safety.

## P5-C — immutable model-registry acquisition and release pinning

Status: **implemented and deterministically evaluated**.

P5-C protects the boundary between an approved deployment release reference and the P5-B package verifier:

- trusted registry IDs are separated from trusted registry source prefixes;
- deployment channel/tag combinations require explicit immutable SHA-256 release pins;
- mutable-tag resolution must still equal the approved release digest;
- release acquisition is digest-addressed rather than tag-trusting;
- redirects are disabled by default and every enabled redirect/final source is allowlisted;
- the release digest binds package manifest/signature evidence and every transitive artifact manifest/signature/payload digest and size;
- cached releases are re-hashed before use, detecting same-key cache substitution;
- release registry/channel/tag and package/model/revision identity are caller-bound;
- accepted releases are handed through the full P5-B package verifier before an opaque handle is returned;
- all registry operations remain fixed local synthetic fixtures with no network or model execution.

Deterministic evaluation:

- vulnerable ASR: 8/8;
- hardened ASR: 0/8;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `758aff515e6566ca80bffb5e4fae61e2b24c87832da2fcc72e406fd47608af5d`;
- fixture SHA-256: `dc553db5d14e11b65c6822b2d31265498a0551b597359e5ca63417d66469b695`.

The eight attacks cover mutable-tag drift, an unpinned channel, an untrusted registry, an untrusted resolved source, an untrusted redirect, content served under the wrong release digest, cache substitution, and release package-identity substitution.

P5-C still does not claim a production registry transport, secure real-world HTTP/TLS/DNS behavior, production cache integrity, production registry credentials, production release-signing-key custody, semantic model safety, or safe real model execution.

## Remaining Phase 5 direction

The next breadth milestone is **P5-D — provenance signing-key lifecycle and revocation**. It should add issuer key IDs, validity windows, explicit revocation, controlled rotation, stale-signature rejection, and deterministic evidence that a cryptographically valid artifact or package signed by a revoked/expired key no longer satisfies deployment trust policy.

Later Phase 5 work can add transparency/attestation evidence, parser/runtime isolation, model scanning and poisoning indicators, model privacy/extraction controls, and deployment provenance.
