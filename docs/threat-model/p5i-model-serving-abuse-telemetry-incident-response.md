# P5-I threat model — model-serving abuse telemetry and incident response

## Scope

P5-I moves Phase 5 from pre-deployment model trust into post-deployment abuse response. A deployment can pass provenance, runtime, model-content, privacy, and deployment-attestation gates and still be probed for extraction, membership inference, sensitive output channels, replay, or canary leakage.

The lab models how **signed, deployment-bound serving telemetry** is accepted and how an incident action is derived. It does not operate a production SIEM/SOAR or actually disable a serving endpoint.

## Security objective

An attacker must not be able to downgrade or forge an incident decision merely by supplying a caller-declared severity/action, a batch from a different deployment, an untrusted collector, a stale/future batch, a replayed batch, a sequence gap, or a forked telemetry chain.

Conversely, authenticated high-risk signals must deterministically produce stronger actions according to policy. The caller does not choose `observe`, `throttle`, `quarantine`, or `revoke_deployment`; the engine derives the action from trusted telemetry and policy weights.

## Trust chain

P5-I consumes a P5-H `VerifiedDeploymentAttestation`. The response policy pins the exact P5-H statement SHA-256. The telemetry batch repeats the exact deployment/package/model/revision/runtime identity and statement digest.

A batch is accepted only when:

- the P5-H handle remains intact;
- the batch is bound to that exact deployment and attestation statement digest;
- the collector ID is explicitly trusted;
- the Ed25519 signature verifies over canonical batch bytes;
- the batch is complete and fresh;
- batch IDs are not replayed;
- sequence numbers are exactly contiguous;
- the previous-batch digest extends the accepted per-deployment chain;
- event IDs are unique and unreplayed;
- event sources are allowlisted;
- event timestamps fall inside the signed batch window;
- occurrence counts and scaled signal scores are bounded;
- thresholded memorization/membership/extraction signals satisfy policy score floors.

## Modeled abuse signals

P5-I includes deterministic synthetic signals for:

- normal traffic;
- output-detail probing;
- sensitive-channel probing;
- session privacy-budget exhaustion;
- repeated-query probing;
- query replay;
- canary leakage;
- memorization indicators;
- membership-inference indicators;
- model-extraction indicators;
- serving identity anomalies.

The policy assigns risk points to signal types. Cross-principal privacy/extraction signals receive a distributed-attack bonus once a configured principal-count threshold is reached.

## Response actions

The lab derives one of four actions:

1. `observe` — accepted evidence below the throttle threshold;
2. `throttle` — suspicious activity merits reduced serving capability;
3. `quarantine` — deployment isolation is required;
4. `revoke_deployment` — the deployment should be withdrawn from service.

`VerifiedIncidentDecision` records the exact batch digest, sequence range, signal counts, risk points, deployment identity, and the P5-H attestation digest. Quarantine/revocation fields are **decision evidence**, not proof that an external platform enforced the action.

## Strong property

A caller cannot make a high-risk signed batch appear safe by declaring a lower action. The hardened path ignores caller severity declarations and derives the response from policy. Likewise, an untrusted or incorrectly signed batch cannot be used to fabricate a quarantine/revocation event against an attested deployment.

The accepted chain also prevents straightforward replay, omission-by-sequence-gap, and branch/fork substitution relative to the engine's in-memory cursor.

## Adversarial evaluation

The deterministic evaluation contains seventeen attacks:

1. degraded P5-H deployment attestation;
2. untrusted collector;
3. telemetry signature substitution;
4. deployment identity substitution;
5. attestation-statement digest substitution;
6. incomplete telemetry window;
7. stale telemetry;
8. future-dated telemetry outside skew policy;
9. untrusted telemetry source;
10. duplicate event identifiers;
11. replayed telemetry batch;
12. sequence gap;
13. telemetry-chain fork;
14. privacy-budget exhaustion burst requiring throttling;
15. repeated sensitive-channel probing requiring quarantine;
16. distributed membership-inference probing requiring quarantine;
17. canary-leakage signal requiring deployment revocation.

Three benign fixtures remain at `observe`: a normal query, normal multi-principal traffic, and an isolated low-risk output-detail probe.

## Claim boundary

P5-I **does** claim deterministic enforcement of the modeled evidence contract:

- exact P5-H deployment binding;
- trusted-collector Ed25519 verification;
- canonical signed telemetry integrity;
- freshness and future-skew checks;
- replay rejection;
- per-deployment sequence continuity;
- previous-batch digest-chain continuity;
- event/source/counter validation;
- policy-derived response actions.

P5-I **does not** claim:

- real model-serving traffic capture;
- production behavioral anomaly detection accuracy;
- proof that a trusted collector reported every event;
- tamper-proof collector hosts;
- rollback-resistant or distributed telemetry cursor state;
- production SIEM ingestion;
- production SOAR execution;
- actual endpoint throttling, quarantine, or revocation;
- distributed enforcement consistency;
- side-channel detection;
- guaranteed extraction or membership-inference detection;
- hardware-backed telemetry provenance.

A compromised trusted collector can still omit or fabricate observations before signing them. A process rollback can also roll back the in-memory chain cursor. Production designs would need durable append-only state, collector/workload attestation, independent telemetry sources, and real enforcement integrations.

## Phase 5 boundary

P5-I completes the current Phase 5 breadth arc: model supply-chain trust, runtime admission, model-content evidence, inference privacy, deployment attestation, and post-deployment abuse response. Production integrations remain future work rather than claims of this synthetic lab.
