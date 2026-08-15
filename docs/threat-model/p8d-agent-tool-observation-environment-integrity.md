# P8-D threat model — agent tool-result, observation, and environment integrity

## Scope

P8-D treats a successful tool call as insufficient evidence that the resulting observation is safe or authoritative. The milestone models the full chain from agent plan step → delegated tool invocation → tool result → side-effect acknowledgement → environment snapshot → agent observation.

The analysis is deterministic and synthetic. It performs no live tool execution, network calls, production environment inspection, or cryptographic attestation verification.

## Security objective

An agent must not be able to convert stale, replayed, swapped, cross-tenant, unacknowledged, spoofed, or otherwise weakly sourced tool output into authoritative state merely by asserting that the tool succeeded.

P8-D therefore requires exact binding between:

1. the P8-A delegation evidence authorizing the invoking agent;
2. the P8-C goal/plan step that requested the operation;
3. the P7-I invariant set that must remain safe for the tool;
4. the tool contract and its tenant/effect/freshness/acknowledgement policy;
5. the invocation's principal, tenant, task, goal, step, arguments, and pre-state snapshot;
6. the result's invocation, tool identity, argument digest, nonce, timestamps, environment transition, acknowledgement, and optional attestation; and
7. the final observation's principal/task/goal/step provenance, environment state, content digest, and derived trust level.

## Modeled tool classes

The canonical fixture contains four tools:

- `tool-search`: read-only tenant search; results remain `TOOL_ASSERTED` because success alone does not make the output authoritative;
- `tool-ticket`: tenant-scoped mutation with mandatory side-effect acknowledgement and allowlisted result attestation;
- `tool-release`: shared irreversible deployment action with mandatory acknowledgement and release-control invariant;
- `tool-telemetry`: system mutation with mandatory acknowledgement and administrative invariant.

The fixture carries six versioned environment snapshots, four invocations, four results, and four observations.

## Threats addressed

### Invocation/result swapping

A result must retain the exact invocation ID, tool ID, and argument SHA-256 of the originating call. A result from another invocation cannot be rebound to the current observation.

### Replay and stale-result use

Result nonces are unique across the manifest. Duplicate nonces are treated as replay. Results are bounded by production time, explicit expiry, and the tool contract's maximum acceptable age.

### Side-effect acknowledgement forgery

Mutating and irreversible tools require an acknowledgement digest over the side-effect identifier, result payload digest, and observed environment version. Missing or mismatched acknowledgements are denied.

This is evidence modeling, not a production transaction protocol.

### Environment-state spoofing

Pre/post environment snapshots are policy-pinned to tenant, version, and SHA-256 state digest. The result and observation must agree on the observed environment version and state digest, and environment versions cannot regress below the invocation's pre-state version.

### Observation laundering

A result becomes `VERIFIED` only when the tool contract explicitly permits authoritative results, an allowlisted attestation digest is present, and no other integrity risk has been derived. A read-only tool result without attestation remains `TOOL_ASSERTED` even if execution succeeded.

### Upstream authorization drift

The observation is denied when the related P8-C plan step is denied, the related P8-A delegation is denied, or a P7-I invariant required by the tool is unsafe.

### Tenant/task/principal drift

Original principal, tenant, task, goal, and step identity must remain consistent from invocation through observation. Caller declarations cannot erase mismatches.

## Intentionally vulnerable baseline

`VulnerableDeclaredToolObservationSafety` trusts caller-owned declarations that the tool succeeded, the observation is authoritative, denied count is zero, and maximum risk is zero. It performs no invocation/result binding, freshness/replay check, environment-state verification, side-effect acknowledgement check, or upstream evidence binding.

## Deterministic evidence

The canonical clean fixture produces **4/4 allowed observations** and zero denied observations.

The repository adversarial evaluator encodes **208 cases** spanning request and manifest substitution, upstream evidence degradation, policy weakening, contract drift, snapshot spoofing, invocation substitution, result replay/staleness/acknowledgement/attestation manipulation, and observation provenance/trust manipulation.

An isolated API-compatible harness compiled the standalone P8-D implementation/evaluator/test files, passed **18 P8-D pytest tests**, and completed the evaluator with:

- vulnerable ASR: **208/208**;
- hardened ASR: **0/208**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**.

Exact deterministic hashes:

- tool-observation graph SHA-256: `1542df3c4f06744f5cb1ad26024e5e4bdac1b4a0d31379944c207ee3e3020ada`;
- adversarial dataset SHA-256: `24a0f4c3c864f95dbba2faaec65015fc5b6868165bcd43b930bcc58d4b32c1f6`;
- fixture SHA-256: `1f9b05b6f02d2ec640c2630debc28de45602714992ec58aad63a2d5c93600abb`;
- clean assessment evidence SHA-256: `add8a12a1fb6c4d3aa3d23b0159c81135dda418a35cfeb9d18dc886f26eddd31`.

Representative truthful unsafe states include replayed result nonces, an expired search result, a missing side-effect acknowledgement, a spoofed post-mutation environment digest, a denied upstream plan step, and an unattested search result falsely promoted to `VERIFIED` authority.

The isolated harness uses API-compatible P8-A/P8-C/P7-I evidence objects. This is not a claim that full-repository pytest ran locally or that production tool runtimes were exercised.

## Claim boundary

P8-D can claim deterministic synthetic evidence for invocation/result/observation binding, stale and replay detection, side-effect acknowledgement integrity, environment snapshot/version integrity, upstream delegation/plan/invariant dependencies, and evidence-derived observation trust.

P8-D does **not** claim production tool-runtime interception, production environment attestation, cryptographic verification of external tool results, semantic proof that tool output is truthful or safe, distributed transaction correctness, real rollback execution, exhaustive environment-state coverage, live tenant data isolation, or networked enforcement.
