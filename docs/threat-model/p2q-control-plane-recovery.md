# P2-Q — Crash-safe control-plane commit and recovery

## Security objective

P2-P separates the monotonic authorization generation from the execution database, so restoring only the execution database cannot make an obsolete authorization generation current. P2-Q addresses the next failure mode: a security-state mutation and the independent generation activation are two durable writes. A process crash between those commits can leave the execution database carrying new authorization state while the independent anchor still advertises the old generation.

P2-Q requires a control-plane change to pass through a durable `prepared -> applied -> active` protocol. A change is usable for authorization only after the execution database and independent anchor have converged on the same active generation. Any pending change or generation mismatch fails closed.

This milestone is a local deterministic recovery protocol. It does **not** claim an atomic distributed transaction across the two SQLite files or distributed consensus.

## Trust boundary

The relevant boundary is:

`control-plane mutation -> independent journal/anchor SQLite -> execution authorization SQLite -> authorization evidence -> effect worker`

The independent anchor database is the durable coordinator for change identity/status and active generation. The execution database remains authoritative for subject state, tenant policy, signing-key trust, authorization versions, the execution-generation marker, and the synthetic effect ledger.

An attacker/test harness may deterministically terminate the control-plane process after a committed protocol phase. It does not corrupt SQLite pages, alter private keys, use real accounts, contact an external authorization service, or touch a real side-effecting system.

## Invariants

1. A control-plane change has one immutable change ID, target generation, canonical mutation hash, and mutation payload.
2. At most one non-active change exists per synthetic authorization authority.
3. `prepared` means the independent journal durably records the intended next generation, but the mutation is not yet active.
4. `applied` means the execution database has committed both the security-state mutation and `execution_control_plane_state.applied_generation` in the **same SQLite transaction**.
5. `active` means the independent anchor has advanced to the target generation and the journal marks the same change active in the **same anchor-database transaction**.
6. Authorization evidence may be issued only when no non-active journal entry exists and `execution.applied_generation == anchor.current_generation`.
7. The first new synthetic effect rechecks the same convergence condition under the independent generation lock, then performs the complete P2-P/P2-O/P2-N provenance and freshness checks.
8. Recovery moves a recognized partial change forward. It never restores old authorization state or decrements a generation.
9. Replaying recovery is idempotent: an already applied mutation must match the same change ID and mutation hash before activation can proceed.
10. A transient convergence failure leaves the bound outbox retryable rather than converting an incomplete control-plane transition into a permanent authorization denial.

## Protocol

### Phase 1 — prepare

`CrashSafeControlPlaneCoordinator.prepare()` starts `BEGIN IMMEDIATE` in the independent anchor database, verifies there is no other pending change, reads the current generation, assigns `target_generation = current + 1`, and writes an immutable `prepared` journal row.

At this point the active generation is unchanged. Authorization is fail-closed because a non-active journal row exists.

### Phase 2 — apply execution state

The coordinator starts `BEGIN IMMEDIATE` in the execution database. Within that single transaction it applies the requested security mutation and updates `execution_control_plane_state` to the target generation with the exact change ID and mutation SHA-256.

P2-Q currently routes three synthetic mutation classes through this boundary:

- subject active/inactive changes, with the tenant revocation epoch incremented;
- password-reset policy changes, with the tenant policy version incremented;
- authorization signing-key rotation, with the trusted key and current key epoch changed together.

If the process crashes after this transaction commits, the execution database may contain generation N+1 while the anchor still exposes generation N. The pending journal entry makes that state non-authoritative until recovery completes.

### Phase 3 — mark applied

The coordinator verifies that the execution marker contains the target generation, exact change ID, and exact mutation hash, then changes the anchor-journal row from `prepared` to `applied`.

### Phase 4 — activate

Under one anchor-database `BEGIN IMMEDIATE` transaction, the coordinator rechecks the execution marker, requires the anchor still to equal the change's `from_generation`, advances the independent generation to `target_generation`, and changes the journal row to `active`.

Only after this commit does the new control-plane state become eligible to issue authorization evidence.

## Recovery

`recover()` inspects the single pending journal entry and the execution-generation marker.

- If execution is still at the change's `from_generation`, recovery reapplies the mutation and marker atomically.
- If execution is already at the target generation, recovery requires the same change ID and mutation hash before proceeding.
- Any other generation/hash/change combination fails closed as a conflict or generation mismatch.
- Recovery then marks the change applied and activates the target generation.
- Calling recovery again with no pending change only verifies that execution and anchor generations still match.

This is a forward-recovery protocol. It intentionally avoids attempting to reconstruct or roll back a partially committed security mutation.

## Deterministic crash injection

The local lab exposes three explicit process-exception crash points:

- `after_prepare` — the journal is durable; execution remains at the old generation;
- `after_execution_apply` — the security mutation and execution marker are durable; the journal remains `prepared` and the anchor remains old;
- `after_mark_applied` — execution is at the new generation and the journal is `applied`; the anchor remains old.

These exceptions model process termination at protocol boundaries after SQLite commits. They do not simulate torn storage writes, VFS bugs, disk-controller failures, or malicious database corruption.

## Matched vulnerable comparison

`aegis/vulnerable/p2q_partial_control_plane.py` preserves the existing P2-P authorization envelope, P2-O Ed25519 provenance, signing-key epoch, P2-N policy/revocation versions, exact outbox binding, and P2-M execution-time authorization.

Its intended defect is narrow: it performs the execution-state mutation first and advances the independent generation second, with no durable change journal, no execution-generation marker, and no pending-change fence. A deterministic crash after the first commit therefore leaves new local authority usable under the still-current old P2-P generation.

The hardened implementation never imports this vulnerable module.

## Evaluation design

`evals/p2q_control_plane_recovery.py` runs the same local SQLite authorization/effect machinery for both variants.

Adversarial attempt P2Q-A1 starts with the synthetic subject inactive. The control-plane change reactivates the subject and increments its revocation epoch, then crashes after the execution transaction commits but before generation activation. The vulnerable comparison can immediately issue old-generation P2-P evidence against the now-active subject and record the first synthetic effect. The hardened variant sees a pending change, records no effect, retains the outbox as retryable, recovers forward to the target generation, and then completes exactly once.

Adversarial attempt P2Q-A2 rotates the synthetic authorization signing key from epoch 1 to epoch 2 in the execution database, then crashes at the same boundary. The vulnerable comparison can use the newly authoritative key while the P2-P generation remains old. The hardened variant fences the window until recovery activates the matching generation.

Benign P2Q-B1 and P2Q-B2 fully commit the corresponding subject-reactivation and signing-key-rotation changes before executing their approved synthetic effects.

Metrics retain the existing definitions:

- ASR = successful policy violations / valid adversarial attempts;
- FPR = benign requests incorrectly blocked / valid benign requests;
- SafeTaskRate = authorized tasks completed safely / authorized tasks attempted.

The report excludes raw change payloads, private-key bytes, signatures, approval IDs, idempotency keys, database contents, real credentials/accounts, and external authorization services.

## Source alignment

P2-Q relies on SQLite's transaction semantics only **within each database file**. The protocol deliberately does not assume that two independent SQLite databases commit atomically as one unit.

Primary references:

- SQLite Transactions: https://www.sqlite.org/lang_transaction.html
- SQLite Atomic Commit: https://www.sqlite.org/atomiccommit.html
- SQLite Transactional guarantees: https://www.sqlite.org/transactional.html
- SQLite Write-Ahead Logging: https://www.sqlite.org/wal.html

`BEGIN IMMEDIATE` is used to acquire the local write transaction before checking/updating the corresponding protocol state. The execution security mutation and execution-generation marker share one transaction; generation activation and journal activation share a separate transaction in the independent anchor database. The durable journal and fail-closed convergence checks bridge the otherwise unsafe crash window.

## Residual risk

P2-Q is still a single-host synthetic prototype. If an attacker can restore both the execution database and the independent anchor/journal database to the same older snapshot, there is no external rollback-resistant fact to detect that event. Production needs an independently protected generation/trust authority appropriate to its deployment.

All writers must use the coordinator. A direct database writer that modifies authorization state, signing-key trust, versions, the execution-generation marker, journal rows, or anchor generation can violate the protocol. Production needs write-path exclusivity, database permissions, authenticated administrative APIs, audit controls, and a recovery service that runs reliably at startup/after failures.

The protocol does not implement distributed consensus, multi-region generation allocation, fencing leases across hosts, two-phase commit with an external transaction manager, or Byzantine/storage-corruption recovery. A prolonged pending change intentionally stops new authorization/effect execution until recovery succeeds, so control-plane availability and recovery liveness remain operational dependencies.

Only the security-state mutation classes explicitly routed through P2-Q receive this guarantee. Future authorization tables or trust roots must be brought under the same protocol rather than updated independently. Private signing keys remain deterministic in-memory lab fixtures; HSM/KMS custody and external trust-root protection are out of scope.

Finally, holding local `BEGIN IMMEDIATE` locks while verifying convergence and committing the first synthetic effect serializes relevant writers. The lab favors a clear safety invariant over production throughput; contention, lock timeouts, distributed worker concurrency, and high-availability recovery require separate engineering.
