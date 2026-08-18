# P11-E live-local supply-chain security

## Trust boundary and flow

P11-E composes the existing P5 artifact, package, immutable-registry, signing-key
lifecycle, runtime, scanning, privacy, and deployment-attestation contracts. It
does not replace them. The live-local path builds the P11-D image, generates and
binds a real CycloneDX SBOM and Grype report, signs the immutable OCI digest,
signs canonical build provenance, pushes to a disposable registry, and exercises
a fail-closed Kubernetes validating admission webhook with short-lived receipts.

The separate model path signs real inert bytes with Ed25519 and uses the existing
P5 loaders. A bounded scanner parses only small JSON metadata. Primary model data
remains opaque and is never deserialized. A validly signed release containing a
synthetic trigger is rejected, quarantined by immutable digest, its prior signer
generation is revoked through the P5-D lifecycle, and a clean generation restores
safe admission.

## Controls and attacks

Admission requires a registry-approved digest plus a fresh signed receipt bound
to image, SBOM, vulnerability report, provenance, signer, and policy version.
Tags, missing/malformed/tampered/expired receipts, mismatched digests, and webhook
outage fail closed. Cache reads are re-hashed. The vulnerability policy blocks
all Critical findings and High findings having an available fix; unusable scanner
database state cannot yield a live pass.

Signature validity is deliberately not treated as content safety. JSON scanning
is bounded by bytes and depth, detects forbidden markers and remote-code settings,
and unsafe serialization is denied without `pickle.loads`, `torch.load`, imports,
network access, or artifact execution.

## Claim boundary

This is live-local container and model supply-chain security validation. It is
not a production registry, CI/CD provenance system, SLSA certification, Sigstore
keyless/Rekor validation, HSM signing service, enterprise vulnerability program,
production admission controller/model registry/quarantine process, comprehensive
backdoor detector, or hardware-backed remote attestation.
