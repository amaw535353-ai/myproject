# P5-D threat model: provenance signing-key lifecycle and revocation

## Scope

P5-D protects the trust decision that sits between a cryptographically valid provenance signature and deployment acceptance. P5-A through P5-C established signed artifact/package provenance and immutable release acquisition, but a static publisher-to-public-key mapping cannot express key expiry, revocation, usage separation, issuer trust, or controlled rotation.

P5-D adds those lifecycle semantics without claiming production PKI, KMS/HSM custody, certificate-chain validation, or an online revocation service.

## Protected properties

The hardened boundary requires all of the following before a package reaches the existing P5-B transitive verifier:

- an explicit signer `key_id`;
- an issuer trusted by deployment policy;
- exact issuer-to-key-record binding;
- exact publisher-to-key binding;
- usage-scoped keys (`model_artifact` versus `model_package`);
- a signer validity interval;
- current-state expiry checks at deployment evaluation time;
- explicit retired and revoked states;
- controlled successor-key metadata for rotation evidence;
- cryptographic binding of key ID, issuer, publisher, usage, signing time, and subject SHA-256;
- a legacy subject signature verified by P5-A/P5-B under the same lifecycle-selected public key;
- fail-closed nested P5-B package provenance after lifecycle verification.

A signature that was cryptographically valid when created is not automatically deployment-valid forever. The default P5-D policy is deliberately current-state strict: expired, revoked, and retired signer keys fail deployment trust even when a signature was created before expiry, revocation, or retirement.

## Bound signature envelope

`BoundProvenanceSignature` binds:

- schema version;
- key ID;
- issuer ID;
- publisher ID;
- provenance usage;
- signing timestamp;
- SHA-256 of the exact canonical artifact or package manifest.

The lifecycle signature is Ed25519 over this canonical envelope. A second subject signature preserves compatibility with the existing P5-A/P5-B verifiers. The lifecycle-aware loader first validates the envelope and key state, then constructs an ephemeral P5-B trust policy using only the lifecycle-approved key material. P5-B independently validates the package closure and the legacy subject signatures under those selected keys.

This prevents metadata-only key-ID or signing-time substitution from bypassing lifecycle policy.

## Key states and rotation

`ACTIVE` keys may coexist during a planned overlap window. That allows old and successor generations to be accepted concurrently while both remain active and within their validity intervals.

`RETIRED` keys are rejected by default after cutover. The policy type exposes an explicit historical-signature option, but the deployment loader keeps the strict default.

`REVOKED` keys are rejected according to current policy even for signatures created before the recorded revocation timestamp. This models emergency deployment distrust rather than archival non-repudiation.

The current lab integration requires all components from one publisher inside a single package closure to use the same lifecycle-approved key ID. Mixed-key closures for one publisher during a rotation overlap are a deliberate residual limitation rather than a claimed production feature.

## Adversarial evaluation

The deterministic P5-D evaluation contains twelve attacks:

1. artifact signed by a currently expired key;
2. artifact signed by a revoked key;
3. artifact signed by a retired predecessor key;
4. artifact signed before its key becomes valid;
5. package signed by a revoked key;
6. package signed by a retired predecessor key;
7. package referencing an unknown key ID;
8. package signed by a key from an untrusted issuer;
9. artifact-usage key presented for package signing;
10. signer publisher binding mismatch;
11. key-ID substitution without recomputing the lifecycle signature;
12. subject-digest substitution in the lifecycle envelope.

The matched vulnerable baseline trusts declared signer metadata and does not evaluate issuer, key state, validity, usage, or bound signature metadata. It remains inert and never executes model bytes.

Three benign cases cover an active predecessor generation during an overlap window, an active successor generation, and successor-signed release content.

Deterministic evidence target:

- vulnerable ASR: 12/12;
- hardened ASR: 0/12;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `3cb29e261f27df97b468e2878752d33104dc475d237c7481e8c72e42890772f9`;
- fixture SHA-256: `d263c288db5c83789eaa7898f78a819873e0c4fa36f2bc7d638e8526f47b8726`.

## Evidence hygiene

All private keys are fixed synthetic evaluation fixtures. Payloads are inert bytes. The evaluation performs no network operations, registry authentication, model downloads, model deserialization, arbitrary serialized payload execution, remote model-code execution, KMS/HSM calls, or transparency-log queries.

## Residual gaps and non-claims

P5-D does not claim:

- production KMS/HSM key custody;
- production signing ceremonies or operator authorization;
- X.509 or other certificate-chain validation;
- OCSP/CRL or other online revocation distribution;
- transparency-log inclusion/consistency verification;
- secure wall-clock or trusted timestamp authority integration;
- rollback-resistant distribution of key policy itself;
- multi-key same-publisher package closures during rotation overlap;
- threshold or multi-party signing;
- compromise detection for signing infrastructure;
- semantic model safety, poisoning/backdoor detection, or malware scanning;
- safe parsing/execution of real model formats;
- sandboxed inference or deployment-runtime attestation.

## Next breadth boundary

P5-E should move outward from provenance administration into model execution safety: parser/runtime isolation, explicit remote-code denial at the execution boundary, bounded resource policy, and synthetic demonstrations that a verified artifact still cannot gain arbitrary host execution merely because its provenance is valid.
