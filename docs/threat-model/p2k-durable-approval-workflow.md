# P2-K Threat Model: Durable Approval Workflow Restart Safety

## Security property

A process restart must not turn a human approval into a replayable bearer capability. The approval remains bound to the original requester, tenant, action, normalized arguments, nonce, reviewer, decision, expiry, and one-time workflow completion state.

High-impact AegisDesk tools still create approval requests only. P2-K does not grant access or reset a password; it hardens the lifecycle of the pending approval workflow.

## Trust boundaries

1. **Authenticated principal -> MCP tool**: identity is server-derived and not model-controlled.
2. **MCP tool -> approval ledger**: the request creates a pending approval record with a cryptographic binding hash.
3. **Approval ledger -> workflow journal**: when the agent has a durable workflow context, the approval record and workflow row are created in one SQLite transaction.
4. **Human reviewer -> approval transition**: reviewer role, tenant, self-approval, and prior state are checked server-side.
5. **Restarted process -> resume**: resume context comes from the durable workflow journal, not client-supplied requester/action/arguments.
6. **Resume -> terminal workflow**: an approved record becomes `consumed`; the workflow journal then becomes `completed`. A completed workflow cannot be resumed again.

## Adversary goals

- Replay the same approved workflow after a restart.
- Rebind an approval to another requester, tenant, action, or argument set.
- Submit a conflicting reviewer decision after a crash.
- Exploit a crash between decision and consumption, or between consumption and workflow completion, to obtain a second authorized completion.

## Hardened design

`DurableApprovalStore` persists approval state in SQLite and uses `BEGIN IMMEDIATE` for write transitions. The existing nonce/requester/tenant/action/argument binding is preserved. Repeating the *same* already-recorded reviewer decision is tolerated only as crash recovery while the durable workflow is still pending; a different reviewer or decision is rejected.

`DurableWorkflowStore` persists the server-owned resume context: thread/trace identifiers, requester identity and roles, action, normalized arguments, tool-call count, and terminal workflow status. `AgentRunner` reconstructs resume authority from this journal rather than from client input.

Crash recovery intentionally distinguishes incomplete recovery from replay:

- crash after review decision: the same reviewer/decision may continue the still-pending workflow;
- crash after approval consumption: the still-pending workflow may finish without consuming again;
- after workflow status is `completed`: every later resume attempt is rejected.

## Intentionally vulnerable baseline

`aegis/vulnerable/p2k_restartable_approval.py` stores only a coarse approval status. It trusts caller-supplied requester/action/arguments during resume and never consumes approved records. This makes approved state replayable and transferable across synthetic process restarts.

The baseline is isolated, local, and synthetic. It does not touch real accounts, credentials, authorization systems, or external services.

## Deterministic evaluation

P2-K uses two adversarial and two benign attempts per variant:

- A1: approved workflow replay after restart;
- A2: requester/tenant/argument rebinding after restart;
- B1: legitimate access approval survives restart and completes once;
- B2: legitimate password-reset approval survives restart and completes once.

Release evidence records ASR, FPR, and SafeTaskRate with raw numerators/denominators. Approval IDs, nonces, binding hashes, and raw workflow arguments are excluded from the report.

## Residual risks

SQLite is appropriate for this local portfolio lab, not a multi-instance production control plane. Production deployment still needs a transactional shared database, protected storage credentials, migrations/backups, HA/failover semantics, retention rules, concurrent reviewer conflict testing, and an idempotent outbox/idempotency key around any future real downstream side effect. The current high-impact tools intentionally stop at approval state and never perform a real grant/reset.
