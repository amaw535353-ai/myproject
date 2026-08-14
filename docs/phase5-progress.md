# Phase 5 progress — model and AI supply-chain security

Phase 5 broadens AegisDesk beyond checkpoint and agent-runtime hardening into model artifacts, provenance, dependency trust, and model-runtime supply-chain boundaries.

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

## Remaining Phase 5 direction

The next breadth milestone is **P5-C — immutable model-registry acquisition and release pinning**. It should model the boundary between a signed release reference and locally consumed bytes: immutable digest-addressed acquisition, redirect/source constraints, release-channel pinning, cache substitution resistance, and fail-closed behavior when a mutable tag or remote reference changes underneath an approved deployment.

Later Phase 5 work can add signing-key lifecycle and revocation, transparency/attestation evidence, parser/runtime isolation, model scanning and poisoning indicators, model privacy/extraction controls, and deployment provenance.
