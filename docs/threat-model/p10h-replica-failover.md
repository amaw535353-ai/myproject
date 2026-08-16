# P10-H threat model — replica autoscaling, failover, routing consistency, and lineage

## Security objective

P10-H prevents a multi-replica inference router from treating replica availability as sufficient proof of safe routing. A route is accepted only when the exact P10-G streaming assessment, request/tenant/session, model revision, adapter composition, accelerator partition set, stream identity, router generation, replica identity/generation, health/capacity evidence, failover fence, scaling authorization, idempotency key, and replacement lineage remain mutually consistent.

## Adversary capabilities

The adversary may forge caller safety booleans; replay a previously served request; present a stale router generation; revive a failed or fenced replica; alias two replica IDs onto one process or endpoint; substitute model, adapter, partition, or config identity; roll back instance generation; forge or reorder routing, scaling, or failover events; exceed replica capacity; age or future-date heartbeats; route to an unhealthy/draining/failed instance; remove failover fencing; forge autoscaling/failover authorization digests; or replace a replica without preserving predecessor lineage.

## Invariants

- the exact clean P10-G assessment is consumed and all P10-G production/distributed nonclaims remain false;
- the router ID and generation are policy-pinned and cannot roll back;
- every policy replica is covered exactly once with unique process and endpoint identity;
- READY replicas are healthy, accepting, unfenced, current-generation, fresh, and within capacity;
- FAILED replicas are non-accepting and fenced;
- at least the policy minimum number of READY replicas remains available;
- routing decisions are ordered, hash-chained, request/tenant/session/stream bound, generation-current, and select only safe replicas;
- the current request idempotency digest is absent from the prior-request ledger;
- scale events are ordered, hash-chained, authorized, and remain within replica-count bounds;
- failover events bind failed and successor generations, advance router generation, fence after failure observation, and prevent later routing to the failed replica;
- replacement replicas preserve a policy-pinned predecessor and predecessor-lineage digest;
- deterministic evidence evaluation performs no network operation.

## Claim boundary

P10-H deterministic SHA-256 values are integrity bindings, not cryptographic identity or remote attestation. The executable mastery lab uses four local OS processes and real localhost HTTP, but does not prove Kubernetes/service-mesh enforcement, production autoscaler correctness, distributed consensus, cross-zone failover, load-balancer stickiness, network-partition tolerance, exactly-once delivery, or internet-facing availability. The P10-F live GPU debt remains deferred.
