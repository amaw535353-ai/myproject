# P8-K — provenance-led incident containment and forensic reconstruction

## Scope

P8-K treats an agent incident as an evidence graph rather than a caller-provided label. A compromised agent can emit messages, write artifacts, use credentials, mutate state, invoke recovery, and hand work to another agent before an operator notices. Containment is therefore safe only when the system can derive the causal scope from tamper-evident events, quarantine every affected agent, preserve the exact evidence set, reconstruct the chain deterministically, and gate re-entry on clean recovery evidence.

The deterministic `AgentProvenanceIncidentForensicsAnalyzer` models chained agent events, containment actions, forensic packages, incident records, and re-entry authorizations. It binds exact P8-G message, P8-H state-transition, P8-I artifact, and P8-J recovery assessment digests and verification flags.

## Threat model

The attacker can influence incident requests, event metadata, event payload digests, causal-parent links, per-agent event-chain links, incident trigger selection, containment action targets/timing, preserved evidence, reconstruction order, re-entry checkpoint/credential/state version, or upstream evidence objects. The attacker succeeds if a compromised path is declared contained while some causally affected agent or object remains active, evidence is missing or rewritten, reconstruction is ambiguous, or re-entry occurs against stale/compromised state.

Representative threats include:

- rewriting an event while recomputing only higher-level manifest digests;
- cutting a causal parent to shrink the incident blast radius;
- omitting a downstream agent from quarantine;
- leaving a compromised message channel open;
- failing to freeze mutated task/recovery state;
- allowing a credential used after compromise to remain active;
- preserving only a caller-selected subset of incident evidence;
- changing a preserved event hash after containment;
- reordering the forensic reconstruction to hide causality;
- changing the incident trigger to exclude downstream compromise;
- authorizing re-entry before containment and evidence packaging complete;
- re-entering from a compromised checkpoint;
- reusing an old credential rather than a policy-pinned replacement; and
- using caller-declared “complete incident” or “scope” summaries to override derived evidence.

## Hardened properties

The analyzer enforces:

- exact incident graph ID/version/SHA-256 and manifest freshness;
- exact P8-G/P8-H/P8-I/P8-J assessment digests and exact-binding flags;
- upstream non-caller-trusting safety facts;
- exact event/action/package/re-entry/incident coverage and trusted evidence owners;
- policy-pinned security-relevant event and incident profiles;
- SHA-256 self-digests for each event;
- per-agent hash-chain continuity from an explicit genesis anchor;
- globally unique positive sequence numbers;
- causal-parent existence, temporal ordering, and sequence ordering;
- causal forward-closure from policy-pinned incident triggers;
- quarantine of every agent in derived incident scope;
- isolation of every message channel touched by the derived scope;
- freezing of state/recovery objects touched by the derived scope;
- revocation of every credential used in the derived scope;
- containment-action timing bounded by trigger and containment time;
- one complete evidence-preservation action over the exact derived scope;
- exact preserved event-hash mapping in the forensic package;
- deterministic reconstruction order derived from event sequence;
- trigger/root continuity in reconstruction;
- forensic package creation after containment;
- re-entry only for policy-authorized affected agents;
- policy-pinned safe checkpoint, rotated credential digest, and minimum state version;
- re-entry only after containment and forensic package generation; and
- rejection of caller-declared completion, scope, reconstruction, or re-entry sets that disagree with derived facts.

## Deterministic fixture

The canonical fixture contains:

- **8 chained incident events** across planner and worker agents;
- **7 containment actions**;
- **1 forensic package**;
- **2 controlled re-entry authorizations**; and
- **1 multi-agent incident**.

The causal path begins with a prompt-injection detection event, crosses an inter-agent message channel, reaches a generated executable artifact, credential use, task-state mutation, a compromised recovery target, and an irreversible tool boundary. The containment set quarantines both agents, isolates the channel, freezes state/recovery objects, revokes the used credential, and preserves the complete event set. The forensic package stores the exact event hashes and deterministic reconstruction order. Re-entry is bound to `checkpoint-safe-2`, replacement credential digests, and minimum state version 9.

Isolated focused validation:

- tests: **19 passed**;
- adversarial cases: **178**;
- vulnerable ASR: **178/178**;
- hardened ASR: **0/178**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- incident graph SHA-256: `3f3f75891ec0f6b5678841b296b50ac7703021a749da8be6c79afdb44722bb27`;
- adversarial dataset SHA-256: `a41d8b510e710032494ee4af1c6091d658ea5ba53e0c10f64c888dac5dbf6092`;
- fixture SHA-256: `e460824ef7ca48d370c2e3698da0100d306fd5d040778d15b5d381541063b1b5`;
- clean assessment SHA-256: `7dda5fdc4b43d25bda9fed630ec3c8ce6902d37fc5f2c942e123c0831098ef0d`.

This validation exercised the exact focused P8-K module, fixture, evaluator, vulnerable baseline, and test file in an isolated Python environment. It is not full-repository pytest and not production SIEM, EDR, distributed event-log, credential, orchestration, or agent-runtime integration.

## Free/open-source implementation path

P8-K adds no runtime dependency. The implementation is deterministic and Python-standard-library-only. Production telemetry, event-store, SIEM/EDR, evidence-retention, and workload-identity integrations remain explicit future substrates rather than being treated as executed evidence.

## Claim boundary

P8-K does **not** claim:

- production SIEM or EDR integration;
- production distributed or append-only event-log guarantees;
- cryptographic signatures, transparency logs, or trusted timestamping for events;
- cross-host clock attestation;
- real credential revocation or rotation;
- production workload isolation/quarantine;
- immutable/WORM forensic storage;
- legal-chain-of-custody certification;
- semantic proof that reconstructed causality is complete outside the modeled event graph;
- formal causality or containment proof;
- exhaustive incident/forensic attack coverage; or
- networked remediation.

“Tamper-evident” here means deterministic SHA-256 chaining and exact policy/evidence binding inside the synthetic lab. It is not a claim of a keyed MAC, digital signature, hardware root of trust, or independently witnessed log.
