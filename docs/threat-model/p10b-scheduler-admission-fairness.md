# P10-B threat model — scheduler fairness, admission control, and resource isolation

## Security objective

P10-B prevents a caller or one tenant from converting a P10-A-valid inference request into scheduler state that starves peers, exceeds tenant/global resource budgets, bypasses deterministic batching order, or replays already-admitted work. The control consumes an exact `VerifiedInferenceTenantIsolationAssessment` and does not re-implement P10-A.

## Trusted evidence boundary

The hardened boundary requires the exact P10-A assessment digest, request/tenant/session identity, schema/mode contract, an `allow` decision with no risks, all P10-A verification flags true, caller trust false, and all P10-A production/non-claim flags false. P10-B then evaluates a policy-pinned scheduler manifest containing concurrent request evidence, per-tenant weighted-deficit state, worker-pool capacity, a selected batch plan, and the prior admitted-request ledger.

SHA-256 bindings provide deterministic integrity evidence only; they are not source authentication or hardware attestation.

## Enforced invariants

- scheduler and worker-pool identities are allowlisted;
- current P10-A request identity is present exactly once and retains its tenant/session ownership;
- all request tenant/session namespaces are valid and request IDs are unique and absent from the prior admitted ledger;
- priority classes, per-request token/memory limits, per-tenant concurrency/queue/token/memory limits, and global slot/token/memory limits are policy-owned;
- starvation bounds are checked against policy-owned maximum wait values;
- tenant state must exactly match derived active/queued/reserved counts;
- weighted deficit accounting is deterministic: `deficit_after = deficit_before + weight * quantum - service_units`;
- the selected tenant must have the highest policy-weighted eligible deficit, with deterministic tie-breaking;
- the batch is a deterministic greedy prefix over admitted, non-running, non-cancelled requests ordered by priority, wait time, and request ID, subject to batch token/memory/size limits;
- batch totals must equal the selected request evidence;
- prior-admission ledger integrity and request replay are fail-closed;
- caller-declared scheduler safety cannot override derived evidence;
- modeled network side effects are denied.

## Adversary model

The adversary may modify upstream assessment fields, request tenant/session/resource attributes, queue priority and wait evidence, per-tenant deficit/accounting state, scheduler/worker identities, batch membership/totals, capacity evidence, replay ledgers, freshness, policy bindings, or caller-declared summaries. The matched vulnerable baseline trusts `declared_scheduler_safe`.

## Deterministic evaluation scope

The focused P10-B corpus contains 135 adversarial cases spanning upstream degradation, tenant/session substitution, oversized requests, queue and concurrency pressure, priority/starvation manipulation, deficit and service-accounting tampering, unfair tenant selection, batch-plan substitution, global resource exhaustion, admitted-request replay, policy drift, and caller-summary lies. Four safe cases include alternate evaluation times and a valid subsequent weighted-fairness turn selecting the beta tenant.

## Claim boundary

P10-B does **not** claim a real scheduler, model server, accelerator, GPU allocator, kernel/cgroup quota, autoscaler, distributed queue, or production admission controller executed. It does not establish wall-clock fairness under arbitrary arrivals, work-conserving optimality, distributed linearizability, physical memory isolation, timing/cache side-channel resistance, production denial-of-service resilience, or semantic model safety. The resource units and queue ages are synthetic deterministic evidence.
