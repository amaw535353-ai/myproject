# P4-F: checkpoint deployment trust-provider boundary

## Security boundary

P4-F makes the trust dependencies behind the P4-B through P4-E checkpoint protections explicit at deployment composition time. The checkpoint runtime now has a separate manifest covering five trust-bearing surfaces:

- checkpoint encryption-key custody,
- checkpoint integrity-key custody,
- monotonic checkpoint anchor state,
- backup authentication material, and
- checkpoint recovery authority.

The default repository implementation is still entirely local and synthetic. It is valid only under the explicit `local_synthetic` deployment profile.

## Production-required profile

`production_external_required` fails closed unless every checkpoint trust surface is represented by an external provider in an independent failure domain. Key-bearing surfaces additionally require external key custody. The monotonic anchor requires rollback-resistant external state, and recovery requires an explicit external recovery authority.

The repository does not include an external checkpoint trust implementation. Setting the production-required profile while using the default local factory therefore fails before the default API constructs the local checkpoint or anchor databases. The same boundary gates the checkpoint encryption-key provider and the P4-E backup manager composition.

This is deliberately stricter than treating a manifest label as a production claim. A hypothetical external descriptor set can satisfy the contract in deterministic evaluation, but no production runtime adapter, credential, network call, KMS/HSM request, remote witness, or recovery service is included here.

## Interaction with earlier controls

P4-A still owns exact checkpoint type reconstruction. P4-B still owns local HMAC integrity and the monotonic anchor model. P4-C still owns local authenticated encryption and metadata minimization. P4-D still owns the local versioned encryption-key lifecycle and re-encryption migration. P4-E still owns local authenticated backup and monotonic restore validation.

P4-F does not replace those controls. It states which trust dependencies would have to leave the local AegisDesk process/failure domain before a production checkpoint trust claim could be made.

The P3-F high-impact effect trust boundary remains a separate control-plane domain. Its authorization signing, protected checkpoint, signed checkpoint receipt, and receipt-witness surfaces are not conflated with the LangGraph agent checkpoint storage surfaces added here. Both domains use the same deployment-profile vocabulary so a production-required deployment fails closed in either local trust domain.

## Evaluation

The deterministic P4-F evaluation uses five adversarial deployment manifests:

1. local checkpoint encryption custody presented as production,
2. an external integrity provider without external key custody,
3. an external monotonic anchor without rollback-resistant state,
4. external backup authentication without external key custody, and
5. external recovery without an external recovery authority.

The implicit baseline accepts all five production claims. The hardened boundary rejects all five. Benign cases verify that the explicit local synthetic profile remains usable and that a complete external contract manifest is accepted as a contract only.

The target metrics are baseline ASR 5/5, hardened ASR 0/5, hardened FPR 0/2, and hardened SafeTaskRate 2/2. Reports contain provider identifiers and posture booleans only; no key bytes or real external operations are emitted.

## Residual risk and non-goals

P4-F does not create independent trust. The default encryption keys, integrity key, anchor database, backup authentication key, and recovery operation remain local. The local anchor is not a remote monotonic witness, and the local backup manager is not an independent recovery authority. There is no production key service, remote object store, external witness, recovery quorum, break-glass workflow, hardware-backed key custody, or multi-host disaster-recovery implementation.

A later milestone can implement concrete external provider adapters and operational recovery semantics. Until then, the production-required profile is expected to reject the repository's default checkpoint runtime rather than downgrade to local trust.
