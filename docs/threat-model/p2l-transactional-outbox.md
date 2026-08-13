# P2-L threat model: transactional outbox and idempotent synthetic effects

## Security property

A valid human approval is necessary but not sufficient to execute a high-impact effect safely. Once an approved workflow crosses the approval-to-effect boundary, a process crash, retry, duplicate message, or duplicate worker must not cause the same logical operation to execute more than once or with different bound arguments.

P2-L keeps all effects synthetic. `request_access` and `request_password_reset` still do not grant access or reset a real credential. The downstream service only writes a local synthetic effect ledger row.

## Assets and trust boundaries

The protected assets are the approval binding, the durable workflow state, the outbox message, the server-derived idempotency key, and the downstream effect ledger. The relevant trust boundaries are:

1. human review -> approval ledger;
2. approval ledger -> transactional outbox;
3. outbox worker -> synthetic downstream effect service;
4. downstream effect acknowledgement -> workflow completion.

The model is not an authority in this milestone and is not used by the evaluation.

## Adversary capabilities

The matched synthetic adversary can cause a worker crash after the downstream effect is recorded but before the outbox acknowledgement, and can cause duplicate delivery of the same already-approved outbox message. It cannot change the server-derived principal, approval binding, or idempotency key in the hardened path.

## Intentionally vulnerable baseline

`aegis/vulnerable/p2l_duplicate_effect.py` models the classic dual-write failure: a worker reads a pending outbox row, writes a synthetic downstream effect, and only then marks the outbox complete. The downstream log has no idempotency key. A crash between those writes leaves the message pending, so retry duplicates the effect. Two workers holding the same stale pending snapshot also both execute the effect.

The vulnerable baseline is local-only and synthetic. It has no network client, OAuth credential, real account, access-control backend, or password service.

## Hardened design

`TransactionalEffectCoordinator` consumes the bound approval and inserts the outbox row inside one `BEGIN IMMEDIATE` SQLite transaction. The outbox payload is copied from the already-bound approval record, never from model output or resume-time client authority. Its idempotency key is derived server-side from the approval identifier, approval binding hash, requester, tenant, action, and canonical arguments.

`DurableEffectWorker` provides at-least-once delivery semantics. `SyntheticIdempotentEffectService` uses a separate local SQLite ledger with a unique idempotency key and unique approval identifier. Re-delivery of the same bound payload returns the original synthetic effect reference without inserting another effect. Reuse of an idempotency key or approval identifier with different payload material is rejected.

The durable agent path completes the workflow journal only after the outbox delivery is acknowledged. If the process fails after the synthetic downstream insert but before the outbox acknowledgement, the approval remains consumed, the workflow remains pending, and a retry reuses the same outbox/idempotency binding. The downstream ledger suppresses the duplicate and the workflow can then complete.

## Deterministic evaluation

P2-L uses two adversarial attempts and two benign attempts per variant:

- P2L-A1: crash after effect, before outbox acknowledgement, then restart/retry;
- P2L-A2: duplicate delivery of the same approved effect;
- P2L-B1: one approved synthetic access effect;
- P2L-B2: one approved synthetic password-reset effect.

Attack success is defined narrowly as more than one downstream synthetic effect row for the same approved operation. Reports record raw ASR/FPR/SafeTaskRate numerators and denominators.

## Evidence hygiene

Reports exclude approval identifiers, idempotency keys, raw effect arguments, effect references, credentials, and external response bodies. The evaluation uses no model and no paid API. All state is temporary local SQLite data.

## Residual risk

This is a single-node durability proof, not a distributed exactly-once guarantee. Production systems still need a shared transactional database, schema migrations, worker leasing/visibility timeouts, retry/backoff and dead-letter policy, downstream idempotency contracts with retention longer than message replay windows, disaster-recovery semantics for both ledgers, multi-worker concurrency/load tests, authorization at the real downstream service, and reconciliation for permanently failed effects. Exactly-once business outcomes ultimately require idempotency at the side-effecting system itself; an outbox alone cannot provide that guarantee.
