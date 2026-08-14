# P5-C threat model: immutable model-registry acquisition and release pinning

## Scope

P5-C protects the boundary between an approved model release reference and the bytes handed into the already-hardened P5-B model-package verifier.

The milestone is intentionally synthetic and local. It models registry resolution, immutable release fetches, redirects, and cache reads through in-process fixtures. It does **not** contact a real model registry, perform real network I/O, use production credentials, download a real model, or execute model code.

## Protected properties

Before a release is handed to P5-B, the hardened acquisition path requires all of the following:

- the requested registry is explicitly trusted;
- the deployment channel and mutable tag have an explicit policy pin;
- the caller-supplied release digest matches that configured channel pin;
- the mutable tag still resolves to the exact pinned immutable digest;
- the registry source is within the trusted source prefixes for that registry;
- redirects are disabled by default and, when enabled, every redirect and final source must remain inside an explicit trusted redirect prefix;
- the fetched release content re-hashes to the exact immutable release digest;
- a cached release is re-hashed before reuse, so same-key cache substitution fails closed;
- the release envelope registry/channel/tag identity matches the caller pin;
- the package ID, model ID, and revision inside the release match the approved deployment identity;
- the acquired package then passes the full P5-B signed transitive package boundary.

## Release digest

P5-C computes a deterministic SHA-256 content digest over canonical immutable release evidence that binds:

- the release schema version;
- the canonical P5-B package manifest digest;
- the package-signature digest;
- each artifact ID;
- each artifact-manifest digest;
- each artifact-signature digest;
- each actual artifact payload digest and byte length.

The mutable registry alias — registry ID, channel, and tag — is deliberately **not** part of that content digest. Those fields are verified separately against caller and deployment policy. This keeps immutable release content identity distinct from mutable discovery and promotion metadata, so the same exact release content can retain one digest while aliases change or the release is promoted between channels.

A mutable tag is therefore only a discovery pointer; it is never accepted as the security identity of a deployment.

## Modeled attacks

The deterministic evaluation covers eight inert registry and release attacks:

1. **Mutable-tag drift** — `production/stable` resolves to a newer valid release than the digest approved by deployment policy.
2. **Unpinned channel** — a caller asks for a channel/tag with no configured immutable release pin.
3. **Untrusted registry** — a registry outside the explicit trust map supplies an otherwise plausible release.
4. **Untrusted resolved source** — a trusted registry identifier resolves the release from an attacker-controlled source prefix.
5. **Untrusted redirect** — registry resolution redirects through or terminates at a source outside the allowed mirror set.
6. **Release digest mismatch** — a response is served under the approved digest but contains different immutable release content.
7. **Cache substitution** — a local cache entry is stored under the approved digest key but contains a different release envelope.
8. **Release package identity substitution** — the immutable release is internally consistent but names a different package/model/revision than the approved deployment.

The matched vulnerable baseline deliberately follows the mutable registry pointer and trusts cache keys and returned release declarations without checking deployment pins, release content digests, source trust, redirects, or package identity. It remains inert and does not execute supplied bytes.

## Trust and redirect policy

Registry identity and source location are separate checks. Trusting the logical registry ID does not authorize arbitrary mirrors or redirects.

Redirects are fail-closed by default. A deployment that allows redirects must explicitly configure trusted redirect prefixes. Every redirect hop represented by the transport result, plus the final source, is checked before release content is accepted.

This is a synthetic URI-policy model, not a claim that URL prefix matching alone is sufficient for a real HTTP client. A production transport would also need robust URL parsing, DNS/IP policy, TLS identity validation, redirect limits, SSRF defenses, proxy controls, and transport-specific canonicalization.

## Cache boundary

The cache is keyed by immutable release digest, but the key alone is not trusted. Every cache hit is re-hashed with the same release digest function before use. This detects the modeled case where local cache storage is modified while preserving the expected key.

The included cache is an in-memory lab component. P5-C does not claim rollback resistance, tamper-proof storage, independent custody, production cache durability, or protection against a host compromise that can change both application policy and cached data.

## Composition with P5-B

P5-C does not replace package provenance. After registry-level checks pass, the exact package is sent through `RestrictedModelPackageLoader`, which re-verifies package signature, component closure, role-specific publisher policy, dependency graph validity, remote-code policy, and nested P5-A artifact provenance.

This separation is deliberate:

- P5-C answers **which immutable release may be acquired from which registry path?**
- P5-B answers **does the acquired release contain exactly the approved signed model-package closure?**
- P5-A answers **does each transitive artifact satisfy exact signed provenance and serialization policy?**

## Claim boundary and residual assumptions

P5-C demonstrates deterministic local evidence for digest-addressed acquisition, mutable-tag drift detection, channel release pinning, source/redirect policy, cache substitution detection, release identity binding, and composition with P5-B.

It does **not** claim:

- a production model-registry client or registry service;
- secure real-world HTTP/TLS/DNS behavior;
- production registry credentials or authorization;
- production release-signing-key custody or lifecycle;
- transparency-log or external attestation verification;
- production cache integrity, rollback resistance, or independent failure domains;
- semantic safety or absence of poisoning/backdoors in a cryptographically valid release;
- safe parsing or execution of real model formats;
- sandboxed inference or deployment-runtime attestation.

All P5-C evaluation fixtures are fixed local inert bytes. No arbitrary model code, remote code, pickle payload, or real model runtime is executed.
