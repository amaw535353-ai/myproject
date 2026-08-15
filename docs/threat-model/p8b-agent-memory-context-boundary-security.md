# P8-B threat model — agent memory and context-boundary security

## Scope

P8-B extends Phase 8 from multi-agent authority propagation into stateful agent security. It models session memory, durable tenant memory, and system/security memory as explicit security boundaries rather than treating retrieved context as inherently trustworthy.

The analysis is deterministic and synthetic. It does not connect to a vector database, agent-memory provider, external cache, production IAM system, or live agent runtime. It validates an evidence-bound memory graph and derives allow/deny decisions for modeled writes and retrievals.

## Security objective

A caller must not be able to convert unsafe memory into trusted context by changing a label, moving it through another agent, persisting it across sessions, or claiming that a revoked/superseded record remains current.

The hardened boundary therefore treats memory as security-relevant state with explicit provenance, tenant/session scope, trust, classification, delegation, retention, revocation, supersession, data-flow, and architecture-invariant bindings.

## Canonical memory model

The fixture contains three policy-pinned stores:

1. `memory-session-a` — Tenant A session memory. It requires exact session binding and permits only `USER_ASSERTED` or stronger trust within a one-hour retention window.
2. `memory-tenant-a-longterm` — Tenant A durable memory. It requires `DELEGATED` or stronger trust, explicit allowed reader/writer agents, and P7-I tenant/tool invariants.
3. `memory-system-security` — system security memory. It requires `VERIFIED_SYSTEM` trust, restricted classification support, and P7-I telemetry/admin invariants.

The canonical inventory contains six memory records, six write events, and four retrieval events.

## Trust and classification

Memory trust is ordered:

`UNTRUSTED < USER_ASSERTED < DELEGATED < VERIFIED_SYSTEM`

Data classification is ordered:

`PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`

A writer cannot assign a trust label above its policy-pinned maximum. A child memory record cannot silently become more trusted than its parent or less classified than its parent unless the record is explicitly sanitized with an allowlisted sanitization evidence digest.

This prevents an agent from taking untrusted user/tool content, rewriting it, and persisting it as if the content had acquired independent system trust.

## Tenant and session isolation

Every original principal has a policy-owned tenant. Writes and retrievals must preserve that tenant, and the target memory/store must belong to the same tenant unless the store is explicitly system-scoped.

Session-scoped stores require an exact session identifier on both the memory record and the operation. A session-scoped record cannot be read or rewritten from a sibling session simply because the same tenant or agent is involved.

System memory does not accept injected tenant-session context.

## Delegated memory writes

Delegated memory records bind to exact P8-A delegation evidence. The referenced delegation must be allowed and must preserve:

- delegatee agent = memory writer;
- original principal identity; and
- tenant identity.

A memory record labeled `DELEGATED` without a valid delegation is denied. A P8-A delegation that has become denied also invalidates the delegated write.

## Provenance and memory laundering

Each record carries:

- content SHA-256;
- source-context SHA-256;
- source kind;
- creating agent;
- original principal;
- optional P8-A delegation ID;
- parent memory IDs;
- P7-C data-path IDs;
- sanitization state/evidence;
- creation/expiry/revocation timestamps; and
- optional supersession relation.

The provenance graph must be acyclic and all parents must exist.

Memory laundering is derived when a child or superseding record increases trust or lowers classification relative to its source without approved sanitization evidence. Cross-tenant parentage is also denied even when all objects exist and all hashes are syntactically valid.

## Poisoned-memory persistence

Low-trust content from `user_message`, `tool_result`, or `external_content` sources cannot be persisted into tenant/system durable memory below the store trust floor unless an approved sanitization transition is present.

The model reports both `UNTRUSTED_PERSISTENCE` and `POISON_PERSISTENCE` when low-trust content would otherwise survive beyond its intended ephemeral boundary.

This is a deterministic synthetic control. It is not a semantic malware detector and does not prove that sanitized content is benign.

## Retrieval-time trust labels

Retrievals carry caller-declared trust/classification maps only so the analyzer can detect attempted relabeling. The authoritative labels are derived from the canonical memory records.

If a caller declares a memory record as more trusted or less classified than the record itself, the retrieval is denied with `RETRIEVAL_TRUST_MISMATCH` or `RETRIEVAL_CLASSIFICATION_MISMATCH`.

The returned assessment exposes the exact derived trust/classification for every retrieved memory object.

## Revocation, expiry, and supersession

A retrieval is denied when a record is:

- revoked at or before evaluation time;
- expired; or
- superseded by a newer canonical record.

A superseding record must remain in the same store and tenant. It cannot silently upgrade trust or downgrade classification unless an approved sanitization transition is present.

## Upstream evidence binding

P8-B binds memory security to three prior assurance layers:

- **P8-A** — delegation authorization, identity continuity, tenant continuity, and authority non-amplification;
- **P7-C** — data-flow/exfiltration path evidence for data entering or leaving memory; and
- **P7-I** — end-to-end architecture invariants required by each memory store.

A referenced P7-C path that is exposed or a required P7-I invariant that is degraded/violated makes the corresponding memory operation unsafe.

## Fail-closed validation

The analyzer rejects malformed or substituted evidence before semantic risk derivation, including:

- request/manifest identity, version, digest, freshness, or scope substitution;
- missing upstream verification flags or digest mismatches;
- duplicate upstream delegation/path/invariant inventories;
- store deletion, duplication, owner drift, scope/tenant drift, reader/writer drift, trust/classification/retention drift, and invariant drift;
- missing/duplicate memory records;
- invalid content/source digests;
- unknown agents, principals, delegations, parents, P7-C paths, stores, or supersession targets;
- provenance cycles;
- invalid sanitization evidence;
- missing/duplicate/malformed write and retrieval events; and
- caller-declared decision/risk summaries that disagree with derived evidence.

## Intentionally vulnerable baseline

`VulnerableDeclaredMemorySafety` trusts caller-owned booleans asserting tenant isolation, session isolation, and memory trust, plus zero denied-write/retrieval counts. It does not bind those claims to memory provenance, delegation evidence, P7-C paths, P7-I invariants, revocation state, or retrieval-time labels.

## Deterministic fixture and evaluation

Clean canonical fixture:

- memory stores: **3**;
- memory records: **6**;
- writes: **6/6 allowed**;
- retrievals: **4/4 allowed**;
- denied writes/retrievals: **0/0**.

Representative truthful unsafe states:

- cross-agent memory laundering on `memory-tenant-tool-note` → one denied write with exact risks `MEMORY_LAUNDERING`, `TRUST_UPGRADE`, and `CLASSIFICATION_DOWNGRADE`;
- revoked current tenant profile → one denied retrieval with `REVOKED_MEMORY`;
- retrieval of a superseded profile → one denied retrieval with `SUPERSEDED_MEMORY`;
- sibling-session retrieval → denied by `CROSS_SESSION`;
- denied P8-A delegation, exposed P7-C path, or unsafe P7-I invariant → the dependent memory operation is denied.

The repository evaluator contains **126 adversarial cases** plus three truthful benign/denial contexts. An isolated local harness executed the standalone P8-B implementation/evaluator/test files, passed **16 P8-B pytest tests**, and completed the deterministic evaluator with:

- vulnerable ASR: **126/126**;
- hardened ASR: **0/126**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- memory graph SHA-256: `7bb96cd8d40a57419bd2ec4bf31fcbdd38db05d512f2eadff410f522886b54ff`;
- adversarial dataset SHA-256: `f047bce2916ff0d745c0258b61db9205597afbfae80416a4f4bd01dc80b983fb`;
- fixture SHA-256: `a151395b84d35ff3ac40755372478bbfbcfb9a1a7e2754a0db3966104a930d9b`.

The harness uses API-compatible P8-A, P7-C, and P7-I evidence objects. This is not a claim that full-repository pytest ran locally or that production integrations were exercised.

## Claim boundary

P8-B can claim deterministic synthetic agent-memory security analysis with exact graph/evidence binding, tenant/session isolation, delegated-write checks, provenance and trust/classification transition checks, poisoned-memory persistence detection, retrieval-time trust-label derivation, and revocation/supersession enforcement.

P8-B does **not** claim production vector-database enforcement, production memory-provider integration, live cache invalidation, cryptographic memory attestation, semantic proof that sanitized content is safe, formal noninterference, exhaustive poisoning coverage, production data-retention compliance, or networked enforcement.
