# P2-S: authenticated checkpoint history and equivocation detection

## Scope

P2-S hardens the P2-R protected checkpoint trust boundary. P2-R proves that a control-plane checkpoint held outside the two rollback-restorable local SQLite databases can stop a coordinated local rollback, but it still assumes the protected checkpoint authority returns honest metadata. P2-S tests that assumption with a local deterministic signer and consumer witness only; it does not contact a real transparency service, KMS, HSM, cloud control plane, or external account.

## Security property

A protected checkpoint is not authority merely because it is stored outside the local rollback set. Before authorization issuance or a first synthetic effect, the consumer must accept only one cryptographically authenticated, predecessor-linked checkpoint history for the expected authority and audience.

Each `aegis.protected-checkpoint-receipt.v1` payload binds:

- checkpoint authority ID;
- consumer audience;
- checkpoint signing-key ID and epoch;
- active control-plane generation;
- canonical P2-Q journal-head SHA-256;
- SHA-256 of the complete preceding signed checkpoint receipt.

The hardened observer verifies the Ed25519 signature with configured public trust material before the receipt enters the durable witness. The witness records one accepted receipt hash per generation. Re-observing the identical receipt is idempotent; a second distinct receipt for an already pinned generation is treated as equivocation and fails closed.

The receipt is still not enough by itself. `CheckpointReceiptGenerationFence` also reconstructs the canonical P2-Q active journal head under the local control-plane generation lock and requires exact equality between receipt generation/head and local generation/head before the P2-P/P2-O/P2-N authorization/effect path continues.

## Trust boundaries

`synthetic checkpoint receipt -> public-key verification -> durable consumer witness -> local generation/journal fence -> signed authorization evidence -> synthetic effect boundary`

Trusted for this milestone:

- server-configured checkpoint authority, audience, public key, key ID, and key epoch;
- the consumer witness database is outside the rollback/tamper capability being tested;
- existing P2-L through P2-R authorization, freshness, idempotency, and local recovery controls.

Untrusted:

- checkpoint receipt bytes before verification;
- claims carried inside an unauthenticated receipt;
- a second checkpoint history, even when signed by the same synthetic checkpoint key;
- locally restored execution/anchor databases until they match an accepted receipt.

## Hardened design

`Ed25519CheckpointReceiptObserver` verifies receipt scope and signature with public material only. `ReceiptWitness` then pins a single predecessor-linked history in a separate SQLite witness. `CheckpointReceiptGenerationFence` requires the accepted receipt to match the local active generation and canonical journal head. `AuthenticatedCheckpointDurableEffectWorker` treats checkpoint authentication/equivocation failures as terminal for the bound outbox and records no synthetic effect.

The deterministic signing seed used by the evaluator is a public synthetic label-derived fixture. It is not a credential and never appears as a report field. Production checkpoint signing-key custody is explicitly out of scope.

## Intentionally weak comparison

`aegis/vulnerable/p2s_checkpoint_metadata_lab.py` remains isolated from the hardened app. It checks only the expected synthetic authority and audience, treats receipt signature/key/predecessor metadata as self-asserted, and remembers no history. The same local generation/journal equality fence and the same downstream authorization/effect implementation are used in both variants. This isolates checkpoint authenticity and history pinning as the security delta.

## Deterministic attacks

### P2S-A1: forged rollback receipt

1. Start from valid generation 1 and snapshot both local control-plane databases.
2. Revoke the synthetic subject and advance the authentic checkpoint history to generation 2.
3. Restore both local databases to generation 1.
4. Present a generation-1 receipt whose metadata matches the restored state but whose signature is replaced with a fixed invalid value.

The metadata-only comparison accepts the obsolete state and records one synthetic effect. The hardened observer rejects the receipt as `checkpoint_receipt_signature_invalid`, cancels the outbox, and records zero effects.

### P2S-A2: same-generation equivocation

1. The hardened consumer accepts the authentic generation-1 receipt.
2. Branch A commits a subject revocation at generation 2 and the consumer pins its authentic signed receipt.
3. Restore both local databases to generation 1.
4. Branch B commits a different benign-for-access policy mutation, producing a different generation-2 journal head.
5. The same public synthetic signing fixture signs a second authentic generation-2 receipt linked to the same generation-1 predecessor.

Both branch receipts are independently authentic. The metadata-only comparison has no memory of branch A and accepts branch B. The hardened witness detects two different receipt hashes for the same pinned generation and rejects branch B as `checkpoint_receipt_equivocation_detected` before any effect.

## Benign controls

- P2S-B1: a valid signed genesis receipt permits a bound synthetic access request exactly once.
- P2S-B2: a valid predecessor-linked generation-2 receipt permits a bound synthetic password-reset request exactly once after a benign generation advance.

## Evidence hygiene

The P2-S report records only deterministic scenario IDs, metric numerators/denominators, generation-level protocol facts, non-sensitive rejection reason codes, package versions, and dataset/fixture hashes. It excludes receipt signatures, signing seed bytes, approval IDs, idempotency keys, database contents, raw effect arguments, real credentials, and external side effects.

## Residual risks

P2-S is a consumer-side witness proof, not a global transparency system. It detects equivocation only after the same durable consumer witness sees and pins one branch and is later shown another. A split-view attack shown exclusively to different isolated consumers is not detectable without independent witness gossip, quorum, transparency logging, or another consistency mechanism.

If the consumer witness is rolled back or deleted together with all other relevant state, previously observed equivocation can be forgotten. Production needs independently durable witness state and recovery procedures appropriate to the deployment.

The synthetic checkpoint signer is not a production key-management design. Real deployments need protected private-key custody, authenticated public-key distribution, key rotation/revocation and compromise recovery, algorithm agility, and operational ownership.

P2-S does not implement distributed consensus, Byzantine-fault tolerance, remote attestation, a public transparency log, multi-region quorum, or cross-organization gossip. Checkpoint/witness unavailability or inconsistency intentionally fails closed, trading availability for safety.

All effects, identities, checkpoint histories, signatures, keys labels, databases, and mutations in this milestone are synthetic and local. No real access is granted and no real password is reset.
