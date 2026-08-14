# P5-B threat model: transitive model-package and adapter provenance

## Scope

P5-B extends the P5-A single-artifact trust boundary to an entire model package. A package can contain a primary model artifact plus configuration, tokenizer metadata, adapters, quantization metadata, and external data shards. The security decision is whether the full signed dependency closure is eligible for later runtime handoff.

The milestone remains synthetic, local, and inert. It does **not** download models, execute remote model code, import a model implementation, deserialize Python objects, parse real model formats, or run inference.

## Protected properties

Before returning a package handle, the hardened loader requires:

- exact caller binding for package ID, model ID, and revision;
- a supported package-manifest schema;
- a trusted package publisher and valid Ed25519 package signature;
- exactly one declared primary model;
- unique component artifact IDs;
- a complete supplied component set with no missing or unexpected artifacts;
- an exact package-level pin for every component publisher, SHA-256 digest, byte size, and format;
- allowed component roles and exact signed role/format declarations;
- role-specific publisher policy, so global artifact trust does not automatically authorize composition in every role;
- a closed dependency graph with no missing references, self-dependencies, duplicate dependency edges, or cycles;
- explicit rejection of package or component metadata that requires remote code;
- P5-A provenance verification for every transitive component, including artifact identity, publisher/source trust, format policy, byte size, SHA-256 digest, and artifact-manifest signature.

A package signature is necessary but not sufficient. A correctly signed package can still describe unsafe composition, a role-inappropriate publisher, a dependency cycle, or a remote-code requirement and is rejected.

## Modeled attacks

The deterministic evaluation uses only fixed inert bytes and covers nine attacks:

1. **Missing required component** — the signed package declares a tokenizer but the supplied closure omits it.
2. **Unexpected component injection** — an undeclared artifact is added beside an otherwise complete package.
3. **Adapter role publisher bypass** — an adapter is signed by a publisher that is globally trusted for artifacts but is not authorized for the adapter role.
4. **Remote-code requirement** — a signed component declaration requires remote code.
5. **Tampered transitive component** — a non-primary config payload changes after its artifact manifest was signed.
6. **Cyclic dependency graph** — a signed package describes a config/tokenizer dependency cycle.
7. **Forged package signature** — the package manifest is signed by the wrong private key.
8. **Package identity substitution** — a valid signed package is supplied for a different caller-requested package identity.
9. **Same-publisher component substitution** — a different config artifact is validly signed by the same trusted publisher under the same artifact/model/revision identity, but its digest and size are not the exact values pinned by the signed package release.

The matched vulnerable loader checks only that a declared primary model is present. It deliberately ignores package signatures, exact closure, transitive provenance, role-specific publisher policy, dependency graph validity, and remote-code declarations. It never executes the supplied bytes.

## Trust model

P5-B separates two trust decisions:

1. **Artifact trust** from P5-A: whether an individual artifact is signed by a trusted publisher, comes from a trusted source prefix, uses an allowed data format, and matches its signed digest and size.
2. **Composition trust** from P5-B: whether that artifact is allowed to occupy a specific role in one exact signed package dependency graph.

This separation is important for adapters and other extension artifacts. A publisher may be globally trusted for some artifact classes without being authorized to compose arbitrary adapters into a production model package.

The evaluation uses deterministic lab Ed25519 keys embedded only as test fixtures. They are not production signing keys and do not model HSM or KMS custody.

## Safe-loading boundary

`RestrictedModelPackageLoader` returns metadata only. The returned `VerifiedModelPackage` explicitly records that it is non-deserialized, non-code-execution-capable, and has performed zero network operations.

Accepted labels such as `safetensors`, `onnx`, and `json` represent policy labels for opaque inert fixtures in this milestone. P5-B does not claim that arbitrary files with those labels are semantically safe to parse or execute.

## Fail-closed behavior

The hardened loader rejects before handoff when:

- package identity does not match the caller request;
- package publisher or signature is invalid;
- package or component remote-code execution is required;
- the artifact set is not exactly the signed dependency closure;
- a role or declared format does not match policy;
- a component publisher is not authorized for its role;
- the dependency graph is incomplete or cyclic;
- any transitive artifact fails the P5-A provenance boundary.

Nested P5-A rejection reasons are preserved as evidence when a transitive component fails verification.

## Residual assumptions and non-claims

P5-B does **not** claim:

- production model-registry integrity or immutable remote acquisition;
- production signing-key lifecycle, revocation, transparency logs, HSM, or KMS custody;
- semantic validation of tokenizer/config/quantization contents;
- secure parsing or execution of real ONNX, safetensors, adapters, or external-data files;
- adapter behavioral safety or absence of malicious weights;
- model poisoning detection, malware scanning, or backdoor detection;
- sandboxed inference;
- model extraction, membership-inference, or privacy protection;
- production deployment attestation.

A verified package proves the modeled provenance and composition properties for the supplied inert artifact closure. It does not prove that model behavior is trustworthy.

## Evidence target

The deterministic target is:

- vulnerable ASR: 9/9;
- hardened ASR: 0/9;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3.

All fixtures are local inert byte strings. No registry credentials, external network service, remote model code, or arbitrary serialized payload is used.
