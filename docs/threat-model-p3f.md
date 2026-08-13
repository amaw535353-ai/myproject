# P3-F trust-provider boundary

## Security property

Local synthetic trust components must never satisfy a production trust posture. The high-impact runtime now receives authorization signing, protected checkpoint state, checkpoint receipt sourcing, and receipt observation through an explicit provider factory.

## Default posture

The bundled `LocalSyntheticHighImpactTrustProviderFactory` is intentionally local. Its `TrustProviderManifest` classifies all four trust surfaces as `local_synthetic`, so `production_trust_claim_allowed()` is false.

The repository remains a local security lab. It includes no real external provider implementation and performs no external trust operation.

## Production-external contract

`production_external_required` accepts a manifest only when all four surfaces are present, each is classified external, provider identifiers are distinct, each provider declares an independent failure domain, and the two signing surfaces declare external key custody.

The check runs before the trust-provider factory creates the trust-bearing runtime components. The bundled local factory therefore cannot be used under the production-external profile.

## Evaluation

Run `python -m evals.p3f_trust_provider_posture`.

The fixed posture evaluation expects an implicit baseline ASR of 4/4 and a hardened ASR of 0/4, with hardened FPR 0/2 and SafeTaskRate 2/2. A structurally conformant external-provider manifest is used only as a contract check; it is not an external implementation.

## Residual risk

A real deployment still needs independently operated trust services, managed signing-key custody, authenticated provider calls, transport protections, availability and recovery engineering, rotation and revocation procedures, auditability, and validation that the declared failure domains are actually independent. P3-F creates and enforces the replacement seam; it does not make the repository production ready.
