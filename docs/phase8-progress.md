# Phase 8 progress — agentic trust, authority, state, execution, autonomy, and communications integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A through P8-F established delegation/authority propagation, memory/context boundaries, goal/plan integrity, tool-result/environment integrity, execution-budget security, and human approval/autonomy boundaries. P8-G now secures the inter-agent message and protocol boundary.

## P8-A through P8-F

P8-A through P8-F are complete for the current deterministic synthetic-lab scope. Their evidence establishes original-principal authority, state provenance, instruction/goal integrity, exact tool-result binding, bounded resource consumption, and evidence-bound human approval before sensitive autonomous actions.

## P8-G — agent communications, message-bus, and inter-agent protocol security

Status: **implemented and deterministically exercised in an isolated P8-G environment; hosted runner execution pending infrastructure**.

P8-G adds `AgentMessageProtocolSecurityAnalyzer`. A message is not trusted merely because it was transported successfully. The analyzer binds channel policy, sender identity, receiver authorization, tenant/principal/task/goal/delegation provenance, schema/protocol version, negotiated capabilities, message freshness/replay state, parent-message chains, P8-C plan steps, and P8-F approval state.

The canonical fixture contains **7 channels and 7 messages** covering tenant retrieval, a safe two-hop tool delegation chain, approved release/telemetry/policy commands, and an authenticated-but-non-authoritative external advisory channel.

The hardened boundary enforces:

- exact message graph ID/version/SHA-256 and freshness;
- exact P8-A delegation, P8-C goal/plan, and P8-F human-approval evidence binding;
- exact channel/message coverage and trusted owners;
- policy-pinned sender/receiver sets, message intents, tenant scope, schema, protocol version, capabilities, approval requirements, and message lifetime;
- policy-pinned sender identity evidence;
- sender and receiver authorization for the exact channel;
- message expiry, future-skew, invalid time-window, and nonce-replay checks;
- schema mismatch and protocol downgrade rejection;
- capability negotiation bounded by channel policy and exact P8-A delegated capabilities;
- principal/tenant continuity with delegation evidence;
- goal/step continuity with P8-C plan evidence;
- exact P8-F approval-action binding for sensitive command channels;
- acyclic parent-message chains, parent receiver → child sender continuity, and P8-A parent/child delegation continuity;
- child message time containment inside the parent message window;
- external-channel command escalation detection; and
- command-laundering detection when informational/external content is promoted into an internal command.

### Free/open-source implementation path

No new runtime dependency was added. P8-G was designed to remain compatible with free/open-source infrastructure:

- **NATS Server (Apache-2.0):** authenticated clients, account-level subject namespaces, and per-user publish/subscribe subject permissions map well to channel and tenant authorization;
- **Apache Kafka (Apache-2.0):** client authentication/encryption plus resource/operation ACLs are suitable for durable event-streaming paths;
- **SPIFFE / SPIRE (Apache-2.0):** SPIFFE IDs and SVIDs can provide workload identity and authenticated workload channels while P8-G retains message-level authorization/provenance checks; and
- **OpenTelemetry (Apache-2.0):** messaging semantic conventions can carry correlation and denial evidence through a vendor-neutral telemetry pipeline.

These are optional integration paths only. P8-G does not add them as runtime dependencies or claim they were exercised.

### Deterministic evidence

The exact standalone P8-G implementation/evaluator/test set was exercised in an isolated Python environment:

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

This is not a claim that full-repository pytest ran locally or that live brokers, workload identity, mTLS, or network transports were exercised.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: complete for current deterministic synthetic scope.
- P8-D: complete for current deterministic synthetic scope.
- P8-E: complete for current deterministic synthetic scope.
- P8-F: complete for current deterministic synthetic scope.
- P8-G: implemented with isolated deterministic evidence; hosted execution remains infrastructure-blocked.

## Next direction

P8-H should broaden into **agent state-machine, concurrency, and race-condition security**: duplicate execution, concurrent approval/use races, stale-state compare-and-swap failures, conflicting tool actions, idempotency-key semantics, cancellation races, lock/lease expiry, and preventing two individually authorized agent branches from combining into an unsafe state transition.
