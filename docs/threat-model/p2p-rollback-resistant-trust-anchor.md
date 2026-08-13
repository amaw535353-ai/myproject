# P2-P — Rollback-resistant authorization trust anchor

## Outcome

P2-P closes the P2-O residual risk where the complete local execution database is restored to an older internally consistent snapshot. P2-O keeps trusted signing keys, current key epoch, policy/revocation versions, provenance denials, and the synthetic effect ledger in that database. A database-wide rollback can therefore make old signed evidence appear current again.

P2-P adds one independent monotonic fact: a **control-plane generation** stored outside the execution database. Authorization evidence is wrapped in a signed `aegis.authz-envelope.v1` carrying that generation. The first synthetic effect is allowed only when the envelope generation equals the independent current generation and the envelope signature plus all P2-O checks succeed.

## Security invariant

Restoring only the execution database to an older internally consistent state must not restore authorization authority.

Before a new synthetic effect is recorded:

1. the independent control-plane generation must exist;
2. the signed envelope generation must equal the independent current generation;
3. the envelope signature must authenticate the generation and the complete inner P2-O signed decision;
4. P2-O issuer, audience, signing-key epoch, signature, validity-window, tenant/outbox binding, policy-version, revocation-epoch, and `allowed` checks must still pass;
5. the independent generation lock remains held until the first effect transaction has committed.

Already-recorded identical effects retain P2-L idempotent crash-recovery behavior through the inner P2-O service.

## Trust boundaries

- **Execution database:** local synthetic SQLite containing P2-O trusted public keys/current key epoch, P2-N versions/current authorization state, provenance denials, and effect ledger. P2-P assumes this database can be restored to an old snapshot.
- **Independent generation database:** separate local SQLite file containing only the monotonic authority generation. The P2-P attack model does not roll this database back together with the execution database.
- **Authorization issuer:** synthetic in-memory Ed25519 private key used only by deterministic evaluation. It signs both the inner P2-O decision and the P2-P generation envelope.
- **Effect worker/service:** receives no private key. It trusts the independent generation store, P2-O public-key state, and server-owned outbox record.

## Hardened design

`ControlPlaneGenerationStore` provides initialization, monotonic advancement, compare-and-swap, and `locked_current()`. The latter uses a local SQLite `BEGIN IMMEDIATE` transaction and holds that independent database lock while the effect service checks the generation, verifies the envelope signature, performs the inner P2-O provenance/freshness validation, and commits the first synthetic effect.

`AnchoredAuthorizationSigner` first issues the existing P2-O `aegis.authz-decision.v1`, then signs a canonical `aegis.authz-envelope.v1` containing both the complete signed decision and `control_plane_generation`. Editing the generation without re-signing therefore fails with `envelope_signature_invalid`.

`RollbackResistantSyntheticEffectService` refuses configuration where the generation store and execution database resolve to the same path. A generation mismatch fails closed with `control_plane_generation_mismatch` before the inner P2-O service can create a new effect.

`RollbackResistantDurableEffectWorker` terminally cancels the bound outbox on P2-P or P2-O authorization failure. The high-impact actions remain synthetic local ledger entries only; AegisDesk does not grant real access or reset a real password.

## Intentionally vulnerable comparison

`aegis/vulnerable/p2p_rollback_blind_authorization.py` inherits the full P2-O provenance/freshness service. It still verifies the inner Ed25519 decision, current local signing-key epoch, policy/revocation versions, exact tenant/outbox binding, validity window, and `allowed` result.

Its sole intended defect is that it ignores the independent control-plane generation and the outer envelope signature. After the execution database is restored to generation-1 state, old generation-1 evidence becomes locally self-consistent and executes.

## Deterministic attacks

### P2P-A1 — execution database revocation rollback

1. Create and approve one synthetic access request.
2. Establish P2-O key epoch 1 and independent generation 1.
3. Issue a valid generation-1 anchored allow decision.
4. Snapshot only the execution database using SQLite's local backup API.
5. Revoke the synthetic subject, advancing the authoritative revocation epoch.
6. Advance the independent generation to 2.
7. Restore only the execution database snapshot.
8. Replay the old generation-1 envelope.

The restored P2-O state again says the subject is active and revocation epoch 1 is current. The vulnerable comparison records the effect. The hardened service sees independent generation 2 and rejects the envelope before the first effect.

### P2P-A2 — execution database signing-key rollback

1. Create and approve one synthetic password-reset request.
2. Establish P2-O key epoch 1 and independent generation 1.
3. Issue a valid generation-1/key-epoch-1 anchored allow decision.
4. Snapshot only the execution database.
5. Rotate trusted signing authority to key epoch 2.
6. Advance the independent generation to 2.
7. Restore only the execution database snapshot, making key epoch 1 locally current again.
8. Replay the old envelope.

The vulnerable comparison accepts the old key because the rolled-back P2-O database says epoch 1 is current. The hardened service rejects the stale generation.

## Benign matched workloads

- P2P-B1: current generation-1/key-epoch-1 signed access effect.
- P2P-B2: current generation-2/key-epoch-2 signed password-reset effect after coordinated rotation/anchor advancement.

Both must complete exactly once in hardened mode.

## Metrics

- **ASR:** successful rollback policy violations / valid adversarial rollback attempts.
- **FPR:** benign current-generation requests incorrectly blocked / valid benign requests.
- **SafeTaskRate:** benign current-generation tasks completed safely / valid benign tasks.

Expected deterministic result: vulnerable ASR 2/2; hardened ASR 0/2; hardened FPR 0/2; hardened SafeTaskRate 2/2.

## Evidence hygiene

The report includes only generation numbers, non-sensitive key/version epochs, effect counts, outbox status, policy names, hashes, and rejection reason codes. It excludes Ed25519 signatures, private-key bytes, deterministic seed labels, approval IDs, idempotency keys, raw effect arguments, database contents, credentials, and effect references.

All snapshot/restore operations target temporary local synthetic SQLite files. No production database, account, credential, authorization service, or external side-effecting system is used.

## Prototype limitations and residual risk

P2-P is a local rollback-detection proof, not a hardware or distributed trust anchor. The independent anchor is another SQLite file on the same host. An attacker who can atomically roll back **both** the execution database and the anchor database defeats this prototype. Production requires a rollback-resistant authority independent of the affected storage domain, for example a linearizable control-plane generation service, protected monotonic counter, hardware-backed state, or another authenticated durable mechanism appropriate to the deployment.

The local `BEGIN IMMEDIATE` anchor lock gives a total order between P2-P effect commits and generation advancement **when every local participant uses this store**. It is not a distributed consensus protocol and does not protect against bypassing the store, multi-host split brain, compromised host administrators, or storage-layer snapshots that include the anchor.

P2-P also does not make execution-database security-state mutation and independent generation advancement one atomic cross-database commit. Production needs a control-plane commit/recovery protocol that cannot leave a security mutation durable while its external generation remains old, or vice versa.

P2-L's exactly-once limitation remains: a transactional outbox plus rollback fencing cannot guarantee exactly-once real-world business outcomes unless the real side-effecting system provides a durable idempotency contract.
