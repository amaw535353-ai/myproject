# P5-E threat model: model parser/runtime isolation and remote-code denial

## Scope

P5-E protects the execution-admission boundary after P5-B/P5-D provenance verification. A signed and provenance-valid model package is still untrusted as executable content. The milestone therefore separates **provenance trust** from **runtime execution authority**.

The lab is intentionally synthetic. It does not parse model bytes, start a sandbox, execute inference, load native libraries, invoke subprocesses, or perform network operations.

## Protected properties

The hardened `RestrictedModelRuntimeBoundary` requires:

- an intact non-executing `VerifiedModelPackage` handle;
- caller/package/runtime identity binding;
- an exact runtime component set matching the verified package closure;
- exact component-role preservation from the verified package;
- role-specific data-only parser allowlists;
- an explicit sandbox-backend allowlist;
- unconditional denial of repository/remote-code hooks;
- denial of dynamic modules, native extensions, and custom operators;
- deny-by-default host capabilities for network, subprocesses, host filesystem writes, environment passthrough, host IPC, and ptrace;
- one required isolation profile;
- positive bounded memory, CPU-time, and thread requests;
- a non-executing verified runtime-plan handle.

The strong property is:

> A provenance-valid package does not gain host execution authority merely because its bytes and signatures are trusted. Runtime admission succeeds only for an explicit data-only parser/backend contract with denied host capabilities and bounded resources.

## Matched vulnerable baseline

`VulnerableHostRuntimePlanner` intentionally trusts the package/runtime declarations and records the requested backend, parser, remote-code, dynamic-code, and host-capability flags without enforcing policy.

It remains inert: no model payload is parsed or executed.

## Adversarial cases

1. pickle-style parser substitution for primary model content;
2. repository-supplied dynamic module request;
3. explicit remote-code requirement;
4. native-extension request;
5. custom-operator request;
6. network-capability request;
7. subprocess-capability request;
8. host-filesystem-write request;
9. environment-secret passthrough request;
10. unsandboxed host-process isolation mode;
11. unapproved Python/subprocess backend;
12. component-role reinterpretation;
13. injected runtime component outside the verified closure;
14. resource-limit escape;
15. degraded/unverified package handle.

## Benign cases

- safetensors-style data-only parsing with the sandboxed tensor backend;
- ONNX-style data-only parsing with the sandboxed ONNX backend;
- a lower-resource sandbox plan within policy limits.

## Deterministic evidence target

- vulnerable ASR: 15/15;
- hardened ASR: 0/15;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `34d4b0e9f7884fcb545217a0d72afc890ec4dd698e5901b5ed4f20cf1d204b44`;
- fixture SHA-256: `8b16c23c7f7f864ff1cd24d0b078400dd766e6a26a905ee5a4822397d191c32d`.

## Claim boundary and residual risk

P5-E demonstrates runtime **plan admission**, not a production sandbox. It does not claim:

- memory-safe parsing of real safetensors, ONNX, tokenizer, adapter, quantization, or external-data formats;
- kernel/container/seccomp/AppArmor/SELinux enforcement;
- actual process, namespace, VM, or microVM isolation;
- real inference isolation;
- secure GPU-driver or accelerator isolation;
- native/custom-operator malware scanning;
- protection against parser implementation vulnerabilities in a future real runtime;
- production secret management or filesystem policy;
- runtime syscall mediation;
- resource enforcement by cgroups or an orchestrator;
- semantic model safety, poisoning/backdoor detection, extraction/privacy defenses, or deployment attestation.

The `VerifiedModelPackage` object is treated as an internal capability produced by the existing provenance boundary; P5-E does not claim that an arbitrary in-process Python caller cannot forge dataclass instances. A production design would bind runtime admission to an authenticated/attested release identity rather than trusting a forgeable language-level object alone.

## Next breadth direction

P5-F should move into **model scanning and poisoning/backdoor indicators**: policy-gated static metadata/weight-statistic evidence, suspicious tensor/config indicators, deterministic synthetic poisoning fixtures, and explicit non-claims about proving behavioral safety.
