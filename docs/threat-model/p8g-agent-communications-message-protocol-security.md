# P8-G threat model — agent communications, message-bus, and inter-agent protocol security

## Scope

P8-G treats an inter-agent message as untrusted evidence until sender identity, receiver/channel authorization, tenant/principal/task/goal/delegation provenance, freshness, schema/protocol version, negotiated capabilities, parent-chain continuity, and any required human approval have been derived from policy-pinned evidence.

The milestone is deterministic and synthetic. It does not connect to a live broker, sign messages, establish mTLS, or inspect production network traffic.

## Security objective

A message must not gain authority merely because it arrived over a valid transport or because an intermediate agent relabeled it. The effective authority of a message is bounded by its exact channel policy, the sender identity pin, the originating P8-A delegation, the P8-C plan step, and P8-F human approval for sensitive command channels.

## Canonical fixture

The fixture contains **7 channels** and **7 messages**:

- tenant orchestrator → retrieval request;
- tenant orchestrator → tool broker request;
- tool broker → tool executor command as a safe two-hop delegation chain;
- release-orchestrator → release-agent command bound to P8-F release approval;
- security-agent → observability-agent telemetry command bound to P8-F telemetry approval;
- security-agent → policy-controller command bound to P8-F policy approval; and
- an authenticated external advisory message that is informational only and has no delegated capability.

The external advisory channel is intentionally modeled as authenticated but not authoritative. Authentication of an external sender does not imply command authority.

## Hardened properties

`AgentMessageProtocolSecurityAnalyzer` enforces:

- exact message graph ID/version/SHA-256 and freshness;
- exact P8-A delegation, P8-C goal/plan, and P8-F human-approval evidence digests and verification flags;
- exact channel and message coverage with unique identifiers;
- trusted evidence owners;
- policy-pinned channel type, sender set, receiver set, intent set, tenant scope, schema version, protocol version, capability set, approval requirement, exact approval action, and message lifetime;
- policy-pinned sender identity SHA-256 evidence;
- sender and receiver authorization for the exact channel;
- exact message schema plus protocol downgrade rejection;
- negotiated capabilities bounded by the channel and by the P8-A delegation;
- original-principal and tenant continuity with the exact delegation;
- goal/step continuity with the P8-C plan;
- exact P8-F approval-action binding for command channels that require human review;
- nonce replay detection, expiry, age, future-skew, and invalid time-window checks;
- acyclic parent-message chains;
- parent receiver → child sender continuity;
- principal/tenant/task/goal continuity across chained messages;
- P8-A parent/child delegation continuity for multi-hop tool messages;
- child time windows contained within the parent message window;
- external-channel command escalation detection;
- command laundering detection when informational or externally sourced content is promoted into a downstream command; and
- rejection of caller-declared denial/risk summaries that disagree with evidence-derived results.

## Threats addressed

### Transport trust confused with message authority

A channel being authenticated or broker-delivered is not sufficient. The exact sender, receiver, intent, schema, capability set, delegation, plan step, and approval evidence must remain valid.

### Cross-agent command laundering

An informational message from an external or lower-trust source cannot be converted into an authoritative command merely by passing through a trusted internal agent. Parent-message provenance is carried forward and evaluated.

### Capability negotiation escalation

Negotiated message capabilities must fit both the channel policy and the exact P8-A delegated capability set. A message cannot add `model.deploy`, `policy.write`, or another stronger capability simply because the receiver possesses it.

### Replay and stale-message execution

Message nonces are unique across the graph and every message has policy-bounded issuance/expiry semantics. Replayed, stale, future-dated, or internally inconsistent time windows are denied.

### Protocol downgrade

A message that uses an older protocol version or the wrong schema is not silently accepted. A newer-but-unexpected version is also rejected until policy explicitly pins it.

### External advisory escalation

An authenticated external advisor may provide information, but the canonical external channel carries no delegated capability and cannot directly emit commands. Authentication is represented as `AUTHENTICATED`, not `VERIFIED` internal authority.

## Intentionally vulnerable baseline

`VulnerableDeclaredMessageSafety` trusts caller-owned claims that the sender is authenticated, the channel is authorized, replay is absent, and denied-message count is zero. It does not derive authority from channel policy, P8-A/P8-C/P8-F evidence, sender identity pins, capability negotiation, parent-message provenance, schema version, or replay state.

## Deterministic evidence

The exact standalone P8-G analyzer, vulnerable baseline, fixture, evaluator, and tests were exercised in an isolated Python environment:

- tests: **15 passed**;
- adversarial cases: **103**;
- vulnerable ASR: **103/103**;
- hardened ASR: **0/103**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- message graph SHA-256: `2afd5ddd030144a9983d34353771d2445276b47793cc57c68db464e5d7a9ba2e`;
- adversarial dataset SHA-256: `9602be70877a2fabb55b1c567466ec53340a18b9cad09c5b6e9ac4ee7d089a15`;
- fixture SHA-256: `e67cf7dbb2da2b219db9c52f48e53137f40eeeae221f53a2cc6bd6e4a1285ce6`;
- clean assessment SHA-256: `f670e1a9e736e47c341543c29d11b4ed00dc5e23ea818be4e27090d47829cf69`.

This is isolated P8-G execution, not a claim that full-repository pytest ran locally or that a production broker/workload-identity system was exercised.

## Free/open-source integration paths

P8-G adds no runtime dependency. The following free/open-source components were reviewed as optional future integration points:

- **NATS Server — Apache-2.0:** supports authenticated clients, accounts with independent subject namespaces, and per-user publish/subscribe subject permissions. These map naturally to P8-G channel, sender, receiver, and tenant-boundary policy.
- **Apache Kafka — Apache-2.0:** provides client authentication/encryption and an authorization framework with ACLs over resources and operations. It is a heavier option for durable event-streaming paths where P8-G message provenance could be carried as record metadata.
- **SPIFFE / SPIRE — Apache-2.0:** provides workload identities through SPIFFE IDs and SVIDs. X.509-SVIDs can establish authenticated workload channels and verify message provenance; P8-G would still separately enforce message-level tenant/task/goal/delegation and capability semantics.
- **OpenTelemetry — Apache-2.0:** messaging semantic conventions define vendor-neutral spans, metrics, and logs for messaging systems, suitable for correlating message IDs, sender/receiver paths, replays, and protocol-denial evidence.

These are integration options only. The deterministic milestone does not claim live NATS/Kafka transport enforcement, SPIFFE identity attestation, or OpenTelemetry collection.

## Claim boundary

P8-G can claim deterministic synthetic inter-agent message/channel security with evidence-bound sender/receiver authorization, freshness/replay controls, schema/protocol checks, capability non-amplification, parent-chain provenance, external-command laundering detection, and exact P8-A/P8-C/P8-F binding.

P8-G does **not** claim production broker enforcement, production workload identity attestation, cryptographic message signatures, production mTLS, packet-level interception, durable exactly-once semantics, exhaustive protocol-semantic proof, real cross-cluster federation security, or networked remediation.
