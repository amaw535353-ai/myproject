# P10-I local incident-response lab

Run:

```bash
python scripts/run_p10i_ir_lab.py --output /tmp/p10i-ir-report.json
```

The lab starts four real localhost OS processes: two initial FastAPI/Uvicorn replicas, one router, and one clean replacement replica. It serves a clean request, uses an explicitly lab-only authenticated fault-injection endpoint to mark the first replica compromised, runs an integrity scan, fences the compromised replica, fails over to the remaining clean replica, rejects an idempotency replay, rejects a wrong-tenant request, registers a clean replacement, advances router generation, and verifies that later traffic never returns to the fenced replica.

The report must show all checks `true`, router generation advancement, `replica-ir-a` fenced, replay HTTP 409, wrong-tenant HTTP 403, and post-recovery routing across `replica-ir-b` and `replica-ir-c`.

This is professional-mastery evidence for local detection/containment/recovery mechanics and forensic event review. It is not evidence of production SOC/SIEM integration, cloud orchestration, cross-zone recovery, network-partition tolerance, or live GPU security.
