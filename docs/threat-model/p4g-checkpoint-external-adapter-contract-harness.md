# P4-G synthetic external checkpoint adapter contract harness

## Scope

P4-G turns the P4-F checkpoint trust manifest from a descriptor-only posture check into an operation-bearing contract harness. It adds synthetic in-process doubles for all five checkpoint trust surfaces: encryption-key custody, integrity-key custody, monotonic anchor state, backup authentication, and recovery authority.

The harness deliberately remains local, deterministic, CPU-only, and credentialless. It performs no network calls and does not provide a production checkpoint runtime. Its purpose is to test the shape and fail-closed behavior expected from future external adapters without pretending that in-process fixture material has become independent external trust.

## Security properties exercised

The synthetic external-style encryption adapter exposes encryption and decryption operations instead of a raw key export API. The integrity and backup-authentication adapters similarly expose authenticate/verify operations while keeping fixture key material private to the in-process double. P4-G does not claim that this prevents key recovery by a process-memory adversary; it only establishes the intended adapter contract.

The monotonic-anchor double implements compare-and-advance semantics. A caller supplies the expected current generation and may advance exactly one generation. Stale expected generations, skipped generations, and rollback attempts fail closed with typed P4-G contract reasons.

The backup-authentication double rejects a modified manifest under an authenticator generated for different bytes. The recovery-authority double requires an allowed synthetic operator plus both authenticated-backup and monotonic-anchor verification signals before authorizing restore.

A `CheckpointExternalTrustAdapterBundle` binds operation-bearing adapters to a complete P4-F `CheckpointTrustProviderManifest`. The bundle validates that each adapter's provider id matches the descriptor for the same trust surface and that key-bearing adapters actually expose the external-key-custody capability required by the manifest.

## Production-profile relationship

The synthetic bundle's manifest is intentionally shaped so that P4-F accepts it under `production_external_required`. This tests the composition contract. Acceptance of that descriptor is not a production certification.

Every P4-G adapter also declares `synthetic_in_process = True` and `operationally_external = False`. Consequently, `production_runtime_eligible()` returns false even though the P4-F descriptor contract is satisfied. This separates "the adapter satisfies the expected external contract shape" from "the adapter is actually external and independently failed."

The default API is not switched to this harness. It continues using `LocalSyntheticCheckpointTrustProviderFactory`, and a production-required default API composition still fails closed before local checkpoint state is created.

## Deterministic adversarial cases

P4-G evaluates five contract failures that a descriptor-only baseline would not exercise:

- adapter provider-id mismatch between the manifest and encryption adapter;
- manifest claims external key custody while the operation-bearing adapter does not provide that capability;
- monotonic anchor rollback after forward progress;
- backup-manifest tampering after authentication;
- recovery authorization attempted without an authenticated backup.

The hardened contract harness must reject all five. Benign evaluation covers encryption/integrity round-trip behavior, monotonic forward progress, and authenticated authorized recovery.

## Evidence hygiene

Evaluation output contains provider ids, booleans, typed rejection reasons, counts, policy version, and a case-id dataset hash. It does not emit raw encryption, integrity, or backup-authentication key bytes, checkpoint plaintext, backup plaintext, or authenticators. The harness performs zero network operations and no real external trust operations.

## Limitations

P4-G is still an in-process synthetic harness. Private fixture key bytes exist in process memory. The in-memory anchor is not durable or independently rollback-resistant. The recovery authority is a local allowlist rather than a human, quorum, IAM, or external authorization service. The synthetic "external" manifest is self-described contract metadata, not proof of an independent failure domain.

P4-B and P4-E still consume raw local integrity/backup key material and P4-B still owns a local SQLite anchor directly. Therefore the current checkpoint runtime cannot yet substitute the P4-G operation-bearing adapters without refactoring those seams. P4-G makes that architectural gap explicit instead of hiding it.

No KMS/HSM, secret manager, remote witness, remote object store, recovery quorum, credentials, outbound callback, or production trust claim is introduced.
