# P2-O — authenticated authorization-decision provenance and anti-rollback

## Security question

P2-N rejects stale authorization decisions whose policy version or revocation epoch is behind authoritative state. That still leaves a harder trust failure: a compromised cache or intermediary can copy an old `allowed` decision, edit its version metadata so it appears current, or replay a legitimately signed decision from an obsolete authorization signing key after key rotation.

P2-O asks whether the side-effecting node can distinguish **authentic current authorization evidence** from self-asserted metadata before the first synthetic effect is recorded.

## Security invariant

Authorization evidence is not authority merely because it contains the expected issuer name, audience, tenant, binding hash, policy version, revocation epoch, or `allowed` result.

For the first effect, the downstream requires all of the following:

1. exact expected issuer and audience;
2. a trusted Ed25519 signing key for that issuer/audience;
3. a signing-key epoch equal to the authoritative current key epoch;
4. a valid signature over canonical immutable claims;
5. a currently valid issue/expiry window;
6. exact tenant and outbox-record binding;
7. policy version and revocation epoch equal to authoritative P2-N counters;
8. an `allowed` authorization result.

The authoritative trust-key lookup, current key-epoch read, P2-N version read, durable denial check, and first synthetic effect insert occur inside the same local SQLite `BEGIN IMMEDIATE` transaction.

An already-recorded identical idempotent effect is checked before provenance validation. This intentionally preserves P2-L/P2-N crash recovery for an effect that was validly committed before a later key rotation or revocation.

## Hardened design

`AuthorizationDecisionClaims` uses schema `aegis.authz-decision.v1` and binds:

- issuer ID;
- audience;
- signing key ID and monotonic key epoch;
- tenant ID;
- exact P2-N outbox record binding;
- policy version;
- revocation epoch;
- authorization result;
- issued-at and expiry timestamps.

`AuthorizationDecisionSigner` holds the Ed25519 private key on the synthetic issuer side and signs canonical JSON claims. The effect service never receives the private key.

`TrustedAuthorizationKeyStore` stores only trusted Ed25519 public keys and the authoritative current key epoch in the same SQLite execution database as the P2-N version state and synthetic effect ledger. Key rotation is monotonic: an older or equal epoch cannot become current again through the normal API.

`ProvenanceFencedSyntheticEffectService` verifies signature and current key epoch before trusting authorization claims. Failures create a durable terminal provenance-denial tombstone and the worker cancels the outbox.

`ProvenanceFencedDurableEffectWorker` keeps the existing at-least-once/idempotent worker semantics while consuming a `SignedAuthorizationReplica` rather than an unsigned cached decision.

## Intentionally vulnerable comparison

`aegis/vulnerable/p2o_unsigned_authorization.py` receives the same signed decision envelope and preserves:

- expected issuer/audience string checks;
- tenant and exact outbox binding;
- decision validity window;
- current policy-version and revocation-epoch equality;
- `allowed` result requirement;
- P2-L idempotent synthetic effect ledger.

It intentionally **does not verify the Ed25519 signature and does not compare the decision's signing-key epoch with authoritative key-rotation state**. Thus apparently correct metadata can be forged or rolled back.

## Deterministic attacks

### P2O-A1 — forged current revocation epoch

A valid key-epoch-1 `allowed` decision is signed while Alice is active at revocation epoch 1. The authoritative node then deactivates Alice and advances the revocation epoch to 2. The attacker changes only the signed claim from epoch 1 to epoch 2 while reusing the old signature.

The vulnerable service trusts the modified metadata and records the synthetic effect. The hardened service verifies the canonical claims signature, detects `signature_invalid`, records no effect, and terminally cancels the outbox.

### P2O-A2 — old signing-key rollback

A valid decision is signed by trusted key epoch 1. Before the first effect, the authoritative trust store rotates to key epoch 2 while policy/revocation versions remain current. The old epoch-1 decision is still cryptographically valid under its old public key, but it is no longer current authorization provenance.

The vulnerable service ignores the current key epoch and records the effect. The hardened service rejects it with `key_epoch_mismatch` and records no effect.

## Benign controls

- P2O-B1: a current epoch-1 signed access decision completes exactly once.
- P2O-B2: after monotonic rotation, a current epoch-2 signed password-reset decision completes exactly once.

## Metrics

P2-O reports raw ASR/FPR/SafeTaskRate numerators and denominators plus percentages for two adversarial and two benign attempts per variant. Expected hardened target: ASR 0/2, FPR 0/2, SafeTaskRate 2/2. Expected vulnerable comparison: ASR 2/2.

Reports exclude signatures, private-key bytes, synthetic key seed labels, approval IDs, idempotency keys, record-binding hashes, raw effect arguments, credentials, and real side effects.

## Safety boundary

All keys are deterministic synthetic test material derived from public fixture labels. They are not credentials and must never be reused outside this repository. All identities, authorization state, replicas, approvals, outbox messages, and effects are local synthetic fixtures. No external authorization service or real account is contacted.

## Production limitations

P2-O proves a local signed-evidence invariant, not a production PKI or distributed authorization platform. A real deployment still needs protected issuer private-key custody, authenticated public-key distribution, rotation/revocation procedures, compromise recovery, trust-root pinning, secure clock assumptions, algorithm agility, multi-region authoritative epoch allocation, rollback-resistant durable storage, and point-of-use enforcement at the real side-effecting service.

The local SQLite key epoch cannot detect a rollback of the **entire authoritative execution database** to an older snapshot. Production anti-rollback needs an external or otherwise rollback-resistant monotonic trust anchor, such as a protected control-plane generation, append-only transparency mechanism, hardware-backed counter, or equivalent system-specific primitive.
