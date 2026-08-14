# P5-H — deployment provenance and attestation

## Goal

P5-H binds the already-approved model release and downstream security gates to a specific deployment environment. It prevents a deployment controller from treating a valid model artifact or a valid scan result as sufficient evidence that the *deployed instance* is the approved one.

The milestone is deliberately a **deterministic synthetic attestation lab**. It verifies signed deployment evidence; it does not perform hardware-backed remote attestation.

## Security property

A deployment attestation is accepted only when all of the following are true:

1. the P5-C registry release handle is intact, immutable, digest-addressed, and non-executing;
2. the P5-E runtime plan is intact and bound to that exact package/model/revision;
3. the P5-F scan handle is intact, clear, and bound to that exact runtime identity;
4. deployment policy pins the exact release SHA-256;
5. deployment policy pins the exact P5-F evidence SHA-256;
6. the exact P5-G privacy policy is canonically hashed and deployment-pinned;
7. the attestation statement binds the P5-C/P5-E/P5-F/P5-G policy/mode versions;
8. the deployment ID, registry/channel/tag, package/model/revision/runtime, and environment ID all match;
9. the environment image digest and synthetic runtime measurement match deployment pins;
10. the attested sandbox backend equals the P5-E verified runtime backend and is allowlisted;
11. the environment is least privilege: isolated network mode, read-only filesystem, brokered secrets, no debug mode, no privileged mode, no host PID namespace, no host networking, and no writable root filesystem;
12. the attestor key is explicitly trusted;
13. the Ed25519 signature verifies over canonical attestation bytes;
14. the nonce matches the deployment challenge;
15. issuance/expiry timestamps are valid at deterministic evaluation time and within the configured maximum attestation age.

A cryptographically valid signature alone is therefore insufficient.

## Main implementation

`aegis/model_supply_chain/deployment_attestation.py`

Key types:

- `DeploymentAttestationRequest`
- `DeploymentEnvironmentEvidence`
- `DeploymentAttestationStatement`
- `SignedDeploymentAttestation`
- `DeploymentAttestationPolicy`
- `VerifiedDeploymentAttestation`
- `DeploymentAttestationVerifier`

Canonical helpers:

- `canonical_privacy_policy_bytes()`
- `privacy_policy_digest()`
- `canonical_deployment_attestation_bytes()`
- `deployment_attestation_digest()`

## Threats modeled

The deterministic evaluation covers sixteen adversarial cases:

1. release digest substitution;
2. scan-evidence digest substitution;
3. privacy-policy substitution;
4. deployment/model identity substitution;
5. image-digest substitution;
6. runtime-measurement substitution;
7. untrusted orchestrator;
8. sandbox-backend substitution;
9. privileged environment;
10. host networking enabled;
11. writable root filesystem;
12. untrusted attestor;
13. forged attestation signature;
14. expired attestation;
15. nonce mismatch;
16. degraded P5-C verified-release handle.

The matched vulnerable baseline trusts the attestation declarations and never verifies signature, environment, freshness, or upstream-gate integrity.

## Deterministic evidence

- vulnerable ASR: **16/16**;
- hardened ASR: **0/16**;
- hardened FPR: **0/3**;
- hardened SafeTaskRate: **3/3**;
- dataset SHA-256: `77548fcef9d14f19fd9d93b1e98ee44a54d572ea56dd4b8756b0cc0d2dd25d85`;
- fixture SHA-256: `030c244da5e5eb5fbf7a52100a569ad706f9c4e9b41244e45fa4b48ab24e5bde`.

The benign cases cover the primary trusted attestor, a trusted rotated attestor, and a fresh short-lived attestation.

## Evidence hygiene

The evaluation uses deterministic synthetic environment measurements and fixed synthetic Ed25519 test keys only.

It performs:

- zero real model inference;
- zero real deployments;
- zero network operations;
- zero transparency-log calls;
- zero hardware-rooted attestation operations.

## Explicit non-claims

P5-H does **not** claim:

- TPM, TEE, confidential-VM, enclave, or measured-boot attestation;
- production Kubernetes admission enforcement;
- real container/image runtime verification;
- secure GPU attestation;
- transparency-log inclusion or consistency proofs;
- certificate-chain/PKI lifecycle for deployment attestors;
- rollback-resistant nonce storage;
- protection against a compromised host fabricating synthetic measurements;
- production remote attestation protocols;
- real deployment startup or workload isolation.

The `VerifiedDeploymentAttestation` handle records these non-claims directly with `hardware_backed_attestation=False`, `transparency_log_verified=False`, and `real_remote_attestation=False`.

## Next breadth direction

After P5-H, Phase 5 should avoid another long provenance-only chain. A useful next milestone is model-serving abuse and incident response: security telemetry, privacy-budget exhaustion signals, suspicious-query aggregation, deployment quarantine/revocation hooks, and deterministic incident evidence. A later production track can replace synthetic environment measurements with real attestation integrations.
