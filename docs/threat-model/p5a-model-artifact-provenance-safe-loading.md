# P5-A threat model: model artifact provenance and safe loading

## Scope

P5-A establishes the first Phase 5 model and AI supply-chain trust boundary. It covers the point where a caller asks for one exact model artifact and bytes are presented as the artifact that should later enter a model runtime.

The milestone is intentionally local and inert. It does **not** download a real model, connect to a model registry, parse safetensors or ONNX, invoke `torch.load`, unpickle data, import remote model code, or execute arbitrary serialized payloads. The hardened loader returns only a verified, non-deserialized artifact handle.

## Protected properties

The boundary requires all of the following before handoff:

- exact caller-request binding for artifact ID, model ID, and revision;
- a supported manifest schema;
- an allowlisted publisher with a pinned Ed25519 public key;
- a source URI allowed for that publisher;
- an allowlisted data-oriented artifact format;
- a signed byte length and SHA-256 digest matching the presented payload;
- a valid Ed25519 signature over the canonical manifest.

A valid signature is necessary but not sufficient. A trusted publisher can still sign an artifact in an unsafe serialization format, and P5-A rejects that artifact at the format-policy boundary.

## Modeled attacks

The deterministic evaluation exercises four inert supply-chain attacks:

1. **Payload tamper after signing** — a valid signed manifest is paired with modified artifact bytes.
2. **Untrusted publisher substitution** — an attacker-controlled publisher signs a manifest that otherwise names the requested artifact.
3. **Signed unsafe serialization** — the trusted lab publisher signs an artifact declared as `pickle`; provenance is valid but the serialization policy is not.
4. **Trusted cross-model substitution** — a valid trusted artifact for a different model/revision is supplied for the caller's requested identity.

The matched vulnerable loader deliberately trusts declaration metadata and accepts all four cases without executing the bytes. This isolates the supply-chain policy failure from arbitrary-code-execution mechanics.

## Hardened design

`aegis.model_supply_chain.RestrictedModelArtifactLoader` validates the manifest and request before producing `VerifiedModelArtifact`.

The returned handle is explicitly marked:

- `deserialized = False`;
- `code_execution_capable = False`;
- `network_operations = 0`;
- loader mode `verified-opaque-handoff-v1`.

The current format allowlist is `safetensors` and `onnx`. In P5-A those names are policy labels only: no parser is invoked and no claim is made that arbitrary real safetensors or ONNX content is safe to execute.

## Deterministic evidence

The P5-A evaluation uses fixed local byte fixtures and deterministic Ed25519 test keys. Expected security delta:

- vulnerable ASR: **4/4**;
- hardened ASR: **0/4**;
- hardened FPR: **0/2**;
- hardened SafeTaskRate: **2/2**;
- network operations: **0**;
- arbitrary serialized payload executions: **0**.

The dataset hash is pinned in the security tests so accidental scenario drift is visible in CI.

## Trust assumptions and residual gaps

P5-A does not claim a production model supply-chain system. Remaining gaps include:

- trusted publisher public keys are configured locally; there is no production key custody, rotation, revocation, transparency log, TUF/Sigstore integration, or threshold signing;
- source URIs are policy strings rather than evidence from a real authenticated model registry;
- acquisition is already complete when bytes reach the loader, so registry download TOCTOU, redirects, mirrors, resumable downloads, and cache poisoning are outside this milestone;
- safetensors and ONNX are not parsed, structurally validated, sandboxed, or executed here;
- ONNX custom operators, external-data references, tokenizer/config files, adapters, quantization artifacts, and remote-code model packages need later Phase 5 controls;
- no malware scanner, model-behavior scanner, poisoning detector, or semantic model verification is claimed;
- cryptographic provenance proves signer authorization and byte identity, not that model behavior is benign, accurate, private, or non-backdoored.

## Claim boundary

P5-A supports a **local synthetic provenance-verification and pre-runtime loading-policy claim** only. It does not support claims of a production model registry, production signing infrastructure, trusted model behavior, sandboxed inference, safe arbitrary ONNX/safetensors execution, or secure remote model acquisition.
