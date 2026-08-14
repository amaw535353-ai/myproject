# Phase 5 progress — model and AI supply-chain security

Phase 5 broadens AegisDesk beyond checkpoint and agent-runtime hardening into model artifacts, provenance, dependency trust, registry acquisition, signing-key lifecycle, and model runtime/execution boundaries.

## P5-A — model artifact provenance and safe loading

Status: **implemented and deterministically evaluated**.

P5-A adds caller-bound artifact/model/revision identity, SHA-256 payload binding, Ed25519 manifests, trusted publishers and source prefixes, data-format allowlisting, and a non-deserializing verified artifact handle.

Evidence:

- vulnerable ASR: 4/4;
- hardened ASR: 0/4;
- hardened FPR: 0/2;
- hardened SafeTaskRate: 2/2.

P5-A does not claim safe real ONNX/safetensors parsing or model execution.

## P5-B — transitive model-package and adapter provenance

Status: **implemented and deterministically evaluated**.

P5-B extends trust to the exact signed model-package closure: primary model, config, tokenizer, adapters, quantization metadata, and external-data roles. It enforces exact component membership, package-pinned publisher/digest/size metadata, role-specific publisher authorization, dependency validation, remote-code rejection, and nested P5-A provenance for every component.

Evidence:

- vulnerable ASR: 9/9;
- hardened ASR: 0/9;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3.

## P5-C — immutable model-registry acquisition and release pinning

Status: **implemented and deterministically evaluated**.

P5-C separates mutable registry discovery aliases from immutable release identity. Deployment policy pins a registry/channel/tag tuple to an exact release SHA-256, constrains source/redirect origins, re-hashes fetched and cached content, binds release/package identity, and hands accepted content through P5-B.

Evidence:

- vulnerable ASR: 8/8;
- hardened ASR: 0/8;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `758aff515e6566ca80bffb5e4fae61e2b24c87832da2fcc72e406fd47608af5d`;
- fixture SHA-256: `dc553db5d14e11b65c6822b2d31265498a0551b597359e5ca63417d66469b695`.

## P5-D — provenance signing-key lifecycle and revocation

Status: **implemented and deterministically evaluated**.

P5-D adds signer key IDs, trusted issuers, exact issuer/publisher/key binding, artifact/package usage separation, signing-time and subject binding, validity windows, active/retired/revoked states, successor rotation metadata, and current-state strict rejection of expired/revoked/retired keys. Lifecycle-approved keys are composed with the existing P5-B verifier.

Evidence:

- vulnerable ASR: 12/12;
- hardened ASR: 0/12;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `3cb29e261f27df97b468e2878752d33104dc475d237c7481e8c72e42890772f9`;
- fixture SHA-256: `d263c288db5c83789eaa7898f78a819873e0c4fa36f2bc7d638e8526f47b8726`.

## P5-E — model parser/runtime isolation and execution-boundary remote-code denial

Status: **implemented and deterministically evaluated**.

P5-E separates provenance validity from execution authority. A verified package must still pass an explicit runtime-admission policy before any future parser/runtime integration may consume it:

- intact non-executing P5-B verified-package handle required;
- caller/package/runtime identity binding;
- exact runtime component set equal to the verified package closure;
- exact component-role preservation;
- role-specific parser allowlists for model/config/tokenizer/adapter/quantization/external-data roles;
- sandbox-backend allowlist;
- unconditional denial of remote/repository-supplied code;
- denial of dynamic modules, native extensions, and custom operators;
- denial of network, subprocess, host filesystem writes, environment passthrough, host IPC, and ptrace;
- required deny-by-default isolation profile;
- bounded memory, CPU-time, and thread requests;
- non-parsing, non-executing verified runtime-plan handoff.

The fifteen attacks cover pickle parser substitution, dynamic modules, remote code, native extensions, custom operators, network/subprocess/host-write/environment capabilities, unsandboxed execution, backend injection, component-role confusion, runtime component injection, resource-limit escape, and a degraded package handle.

Evidence:

- vulnerable ASR: 15/15;
- hardened ASR: 0/15;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `34d4b0e9f7884fcb545217a0d72afc890ec4dd698e5901b5ed4f20cf1d204b44`;
- fixture SHA-256: `8b16c23c7f7f864ff1cd24d0b078400dd766e6a26a905ee5a4822397d191c32d`.

P5-E is deliberately an admission-policy lab, not a production sandbox. It does not claim memory-safe real model parsing, kernel/container/microVM enforcement, real inference isolation, secure GPU isolation, syscall mediation, cgroup enforcement, or protection from vulnerabilities inside future parser/runtime implementations.

## Remaining Phase 5 direction

The next breadth milestone is **P5-F — model scanning and poisoning/backdoor indicators**. It should add deterministic synthetic evidence for suspicious tensor/config metadata, anomalous weight statistics, unexpected trigger-like artifacts, and policy-gated scan findings while explicitly avoiding a claim that static scanning proves behavioral safety.

Later Phase 5 work can add transparency/attestation evidence, model privacy/extraction controls, deployment provenance, and real runtime isolation integrations.
