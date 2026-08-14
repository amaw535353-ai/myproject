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

Deterministic evaluation target:

- vulnerable ASR: 4/4;
- hardened ASR: 0/4;
- hardened FPR: 0/2;
- hardened SafeTaskRate: 2/2.

P5-A deliberately does not claim that real ONNX or safetensors parsing/execution is safe. Those format labels are accepted only for a verified opaque handoff in this milestone.

## Remaining Phase 5 direction

The next useful breadth milestone is **P5-B — transitive model-package and adapter provenance**. It should extend trust from one primary model blob to the dependency graph that commonly accompanies a model: tokenizer/config files, LoRA or PEFT adapters, quantization metadata, external-data shards, and any package metadata that could request remote code. The design should remain synthetic and inert while testing manifest closure, dependency pinning, mixed-publisher policy, missing or substituted dependencies, and explicit rejection of remote-code requirements.

Later Phase 5 work can add immutable registry acquisition, signature/key lifecycle, parser/runtime isolation, model scanning and poisoning indicators, model privacy/extraction controls, and deployment provenance.
