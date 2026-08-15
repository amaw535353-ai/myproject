# Phase 8 progress — agentic trust, authority, state, execution, autonomy, communications, concurrency, artifact, recovery, incident, and exit integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A through P8-I established delegation/authority propagation, memory/context boundaries, goal/plan integrity, tool-result/environment integrity, execution-budget security, human approval/autonomy boundaries, inter-agent message/protocol security, concurrency/race security, and artifact/workspace/generated-code integrity. P8-J secures rollback, recovery, and durable persistence boundaries. P8-K adds provenance-led incident containment, evidence preservation, deterministic reconstruction, and controlled re-entry. P8-L closes the current Phase 8 synthetic scope with an integrated evidence-lineage exercise and machine-readable exit gate.

## P8-A through P8-I

P8-A through P8-I are complete for the current deterministic synthetic-lab scope. Together they establish original-principal authority, provenance-preserving context and messaging, bounded execution, evidence-bound approval, race-aware state transitions, and generated-artifact/workspace confinement.

## P8-J — agent rollback, recovery, and persistence-boundary security

Status: **implemented and deterministically exercised in an isolated P8-J harness; hosted runner execution pending infrastructure**.

P8-J adds `AgentRollbackRecoverySecurityAnalyzer`. Recovery is modeled as a security operation: a checkpoint is not resumable merely because it is recent or internally consistent. The analyzer reasons about checkpoint ancestry, generation floors, persistent-item state, explicit quarantine/revocation, recovery authorization, and exact upstream memory/artifact/state evidence.

The canonical fixture contains **8 persistence items, 4 checkpoints, 2 recovery authorizations, and 3 recovery operations**. Its compromised generation contains a rejected message, stale credential, and poisoned artifact. The clean rollback returns to the last known-good checkpoint while explicitly quarantining or revoking compromised source-only persistence.

The hardened boundary enforces:

- exact graph ID/version/SHA-256 and freshness;
- exact P8-B memory, P8-I artifact, and P8-H state-transition evidence binding;
- exact item/checkpoint/authorization/recovery coverage and trusted owners;
- policy-pinned item/checkpoint profiles;
- acyclic monotonically increasing checkpoint ancestry;
- tenant/session/original-principal/state-digest continuity;
- checkpoint expiry and recovery-floor generations;
- compromised-checkpoint resume denial;
- exact target restore partitioning;
- explicit quarantine/revocation of compromised source-only persistence;
- non-restoration of revoked, quarantined, or superseded items;
- stale credential resurrection denial;
- non-restorable message/artifact policy;
- upstream denied/missing memory, artifact, or state evidence denial;
- actor/principal/tenant/mode/item/depth/expiry authorization binding;
- destructive rollback authorization; and
- rejection of caller-declared recovery summaries that disagree with derived facts.

### P8-J deterministic evidence

- tests: **17 passed**;
- adversarial cases: **130**;
- vulnerable ASR: **130/130**;
- hardened ASR: **0/130**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- recovery graph SHA-256: `b8a38dd2e9002fb9ff4864442918e6ac4ec11f9584c8b851f93de034e57b774a`;
- adversarial dataset SHA-256: `66f2aa0fd8e99c3f7dedf65d63fc3448cfedd4aee49930f86b19e6ae7bc13e46`;
- fixture SHA-256: `d4071cd7552a2ce9be3dfeec85763591a05dcd5eeadd4b9541d6199aa16d297b`;
- clean assessment SHA-256: `1bbf03a27b206911c23abed3af2cbace3c515e48785aeff802cf947857ff23eb`.

This is isolated focused P8-J execution, not a claim that full-repository pytest or production backup/checkpoint/credential/runtime systems were exercised.

## P8-K — provenance-led incident containment and forensic reconstruction

Status: **implemented and deterministically exercised in an isolated P8-K harness; hosted runner execution pending infrastructure**.

P8-K adds `AgentProvenanceIncidentForensicsAnalyzer`. It treats an agent incident as a causal evidence graph rather than a caller-supplied “compromised” label. The analyzer verifies per-agent SHA-256 event chains, exact causal-parent ordering, forward-derives the incident scope from policy-pinned triggers, requires containment for every affected agent/channel/state/credential, preserves the exact event-hash set, derives a deterministic reconstruction order, and gates re-entry on a policy-pinned safe checkpoint, rotated credential digest, minimum state version, and exact forensic package.

The canonical fixture contains **8 incident events, 7 containment actions, 1 forensic package, 2 re-entry authorizations, and 1 incident** across planner and worker agents. The modeled compromise crosses an inter-agent channel, generated executable artifact, credential use, task-state mutation, recovery state, and an irreversible tool boundary.

The hardened boundary enforces:

- exact graph ID/version/SHA-256 and freshness;
- exact P8-G message, P8-H state-transition, P8-I artifact, and P8-J recovery evidence binding;
- upstream non-caller-trusting safe facts;
- exact event/action/package/re-entry/incident coverage and trusted owners;
- policy-pinned event and incident security profiles;
- event self-digests and per-agent hash-chain continuity;
- globally unique monotonic event sequence numbers;
- causal-parent existence and temporal/sequence ordering;
- causal forward-closure from exact incident triggers;
- quarantine of every affected agent;
- isolation of every affected message channel;
- freezing of affected state and recovery objects;
- revocation of credentials used in the compromised scope;
- containment timing bounded by trigger and containment time;
- complete evidence preservation over the derived scope;
- exact event-hash preservation in the forensic package;
- deterministic sequence-derived reconstruction and exact trigger roots;
- forensic package generation after containment;
- re-entry only for affected policy-authorized agents;
- policy-pinned safe checkpoint, replacement credential digest, and minimum state version;
- re-entry only after containment and forensic package generation; and
- rejection of caller-declared completion/scope/reconstruction/re-entry summaries that disagree with derived facts.

### P8-K deterministic evidence

The exact focused P8-K implementation/evaluator/test files were exercised in an isolated Python environment:

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

This is isolated focused P8-K execution, not a claim that full-repository pytest or production SIEM/EDR, distributed event-log, credential, orchestration, quarantine, or agent-runtime systems were exercised.

### Free/open-source implementation path

P8-K adds no runtime dependency. The security logic is Python-standard-library-only. Production telemetry, event-store, SIEM/EDR, evidence-retention, and workload-isolation integrations remain explicit future substrates rather than executed evidence.

## P8-L — integrated multi-agent compromise exercise and machine-readable Phase 8 exit gate

Status: **implemented and deterministically exercised in an isolated P8-L harness; Phase 8 exits the current synthetic/local scope with an explicit external hosted-CI limitation**.

P8-L adds `Phase8IntegratedExitGate`. It binds one ordered P8-A-through-P8-K evidence lineage using exact milestone manifest/assessment SHA-256 values, predecessor-assessment links, policy-pinned assessment schema/mode profiles, and cross-milestone input/output-state continuity. It also makes verification provenance part of the security decision instead of collapsing every green/red infrastructure state into a generic pass/fail.

The machine-readable exit states are:

- `PASS` — local security validation is complete and remote CI evidence proves a runner actually started and executed steps;
- `PASS_WITH_EXTERNAL_CI_LIMITATION` — deterministic local/synthetic evidence is complete, while hosted CI is externally blocked before execution for a policy-recognized reason;
- `FAIL` — evidence is missing/tampered/unsafe, local verification did not execute, remote CI actually executed and failed, or unsupported production claims are asserted.

The canonical fixture models the currently observed hosted-runner condition as `REMOTE_CI_BLOCKED` with `runner_started=false`, `steps_executed=0`, and reason code `github-hosted-runner-account-billing-or-spending-limit`. The gate therefore refuses to call hosted CI “passed,” while also refusing to reinterpret a runner-provisioning failure as a security-test failure.

The hardened boundary enforces:

- exact P8-A through P8-K coverage and ordering;
- exact control-domain and step-index binding;
- a single execution-lineage identity across all milestones;
- predecessor assessment-chain continuity;
- cross-milestone input/output-state continuity;
- exact milestone manifest, assessment, output-state, schema, and mode policy pins;
- upstream safe evidence with no caller-declared-safety trust;
- zero unexpected network operations in the synthetic evidence envelopes;
- explicit local verification execution markers and positive executed-step counts;
- `REMOTE_CI_PASS` only when a runner started and steps actually executed;
- `REMOTE_CI_BLOCKED` only when no runner started, zero steps executed, and the reason is policy-recognized;
- `REMOTE_CI_FAIL` as a real exit failure when a remote runner actually executed and failed;
- exact machine-readable synthetic/local assumptions;
- fail-closed production-claim boundaries; and
- rejection of caller-declared exit/evidence/verification summaries that disagree with derived facts.

### P8-L deterministic evidence

The focused P8-L implementation/evaluator/test harness and the local verification wrapper were exercised locally:

- tests: **21 passed**;
- adversarial cases: **198**;
- vulnerable ASR: **198/198**;
- hardened ASR: **0/198**;
- hardened FPR: **0/4**;
- SafeTaskRate: **4/4**;
- Phase 8 exit manifest SHA-256: `d38530c7d925c7df5705c142c01b59dc9a849a7509f24b6dc85a410adface203`;
- adversarial dataset SHA-256: `809c95a014771eb79a626b42cca018ff4f147146df67de562314a2060053a1d2`;
- fixture/evaluator SHA-256: `fe880b63ffc256b44a73c3768cf2ce0de8c2876fad4e9d643ebdf34b8ee0c1f6`;
- clean assessment SHA-256: `afef4e4035e3b0bd25b8036d324d0479bdbb37b5eaffbef8404277ee7646e9c6`;
- canonical exit decision: `PASS_WITH_EXTERNAL_CI_LIMITATION`;
- canonical remote CI status: `REMOTE_CI_BLOCKED`.

`scripts/verify_phase8.py --focused-p8l` provides a reproducible focused local path; its JSON evidence explicitly sets `hosted_ci_execution_verified=false` and `production_validation_claimed=false`. The default script mode is reserved for a real full local Phase 8 run and must not be reported as passed unless it actually completes.

This evidence is focused local P8-L execution. It is not a claim that full-repository pytest, every P8-A-through-P8-K evaluator, GitHub-hosted Actions, or production agent infrastructure executed successfully in the same run.

### P8-L claim boundary

P8-L does not independently re-run every prior analyzer inside the exit gate, digitally sign historic assessment origins, provide trusted distributed timestamps, integrate production SIEM/EDR, rotate real production secrets, isolate real workloads, prove production distributed-system behavior, or establish legal chain of custody. SHA-256 binding is deterministic tamper evidence in the lab, not origin authentication.

P8-L adds no runtime dependency.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: complete for current deterministic synthetic scope.
- P8-D: complete for current deterministic synthetic scope.
- P8-E: complete for current deterministic synthetic scope.
- P8-F: complete for current deterministic synthetic scope.
- P8-G: complete for current deterministic synthetic scope.
- P8-H: complete for current deterministic synthetic scope.
- P8-I: complete for current deterministic synthetic scope.
- P8-J: implemented with isolated deterministic evidence; hosted execution remains infrastructure-blocked.
- P8-K: implemented with isolated deterministic evidence; hosted execution remains infrastructure-blocked.
- P8-L: implemented with isolated deterministic evidence and a verification-aware exit gate; current exit is `PASS_WITH_EXTERNAL_CI_LIMITATION`, not hosted-CI `PASS`.

**Phase 8 is closed for the current deterministic synthetic/local scope.** Hosted GitHub Actions remains a separate external verification dependency and must be rerun against an exact commit SHA after the account billing/spending-limit runner-provisioning condition is resolved.

## Next direction

Do not add another isolated Phase 8 control layer merely to compensate for unavailable hosted CI. Preserve the deterministic local verification path, rerun exact Phase 8 commit evidence remotely when GitHub-hosted execution becomes available, and pivot the roadmap to the next breadth domain with the same evidence/claim discipline.
