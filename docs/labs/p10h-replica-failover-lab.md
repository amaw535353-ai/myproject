# P10-H professional-mastery lab — localhost multi-process replica failover

This lab turns the P10-H threat model into executable distributed-serving behavior without claiming production orchestration.

Run:

```bash
python scripts/run_p10h_replica_lab.py
```

The runner forks four real OS processes: three FastAPI/Uvicorn replica servers and one FastAPI/Uvicorn router. Two replicas begin active and one begins as a cold replacement. The runner then:

1. proves a wrong-tenant inference request is denied;
2. routes a valid request and records the selected replica generation;
3. fails that live replica through an authenticated admin endpoint;
4. sends another request and verifies the failed replica is fenced and not reused;
5. verifies the router generation advances and the cold replacement is activated because ready capacity fell below the floor;
6. replays the same idempotency key and requires HTTP 409;
7. sends additional requests and requires traffic to reach both surviving ready replicas while the fenced replica receives none.

A passing run emits a JSON report with `process_count=4`, `stale_replica_fenced=true`, `post_failover_routes_to_failed=0`, `replay_status=409`, a router generation increase, a replacement scale event, a failover event, and a deterministic report SHA-256.

Professional interpretation: this closes the **local multi-process replica-routing/failover gate**. It does not close production Kubernetes, service mesh, distributed-consensus, cross-zone, network-partition, real load-balancer, or exactly-once semantics. Those remain explicit nonclaims.
