# P4-L checkpoint lifecycle failure and fencing semantics

P4-L adds a deterministic, synthetic failure-and-fencing harness around the P4-J external-style checkpoint lifecycle provider. The goal is to make failure semantics explicit before any real external provider exists. This milestone does not add a production lifecycle service, durable distributed lock, quorum, or network dependency.

## Security objective

A lifecycle command must not be executed twice merely because a caller observes an ambiguous response, must not execute with a stale fencing token, must not execute against anchor state that changed after the command was issued, and must fail before mutation when the synthetic provider is unavailable. If the harness injects partial anchor-state progression, the in-process coordinator restores the pre-command anchor snapshot before allowing a retry.

The P4-L command envelope binds a command id, lifecycle operation, monotonic fence token, expected anchor-state fingerprint, and logical resource id. Successful commands produce an in-memory receipt that is recorded before an injected ambiguous-after-commit response is surfaced. An exact retry returns that receipt without reinvoking the lifecycle provider. Reusing the same command id with different bound fields is rejected.

## Adversarial cases

The deterministic harness covers five cases:

1. an operation commits but the caller receives an ambiguous outcome and retries;
2. the lifecycle provider is unavailable before mutation;
3. a stale command or conflicting replay is submitted after a newer fence committed;
4. another writer changes monotonic-anchor state after a command is issued but before execution;
5. synthetic provider-side anchor progression occurs before an injected failure.

The hardened harness requires exact replay idempotency, fail-closed provider unavailability, monotonic fence rejection, anchor-fingerprint mismatch rejection, and restoration of injected partial anchor state before retry.

## What the harness does not prove

The fence counter and command receipts are in process and are lost on process restart. The anchor bridge is also in process. The partial-progress recovery path is compensating single-process logic, not a distributed transaction. P4-L does not establish durable leases, multiprocess or multi-host fencing, crash-consistent command receipts, remote idempotency keys, provider-side compare-and-swap receipts, consensus, cross-region recovery, or exactly-once execution.

The `resource_id` field is a logical binding used by the synthetic command digest; P4-L does not define production canonicalization or authorization for external object-store keys, remote backup ids, KMS resources, or service-specific request identifiers.

## Trust and production posture

The harness uses the P4-J lifecycle provider and P4-G/P4-H synthetic external-style anchor bridge. Both remain synthetic in process and operationally non-external. P4-K production lifecycle trust requirements are unchanged, and the P4-L harness cannot satisfy them. No real credentials, network calls, KMS/HSM operations, object store, external ledger, recovery quorum, or production service are introduced.

Production checkpoint lifecycle claim: none. Durable distributed fencing claim: none. Distributed transaction or exactly-once claim: none.
