# Onyx Security Validation Progress

## O1 — Onyx Target Adapter + RAG Authorization

State: `planned`

### Inspection record

Pinned revisions inspected:

- AegisDesk: `1a119067ca27cff38c8ace4fb46fbe5484d51262`
- Onyx: `cbfd6b327b348beac532801306de63eed8551248`

AegisDesk inspection confirmed existing fail-closed evidence semantics (`VERIFIED`, `FAILED`, `BLOCKED`), deterministic/live-local/production claim separation, raw ASR/FPR/SafeTaskRate reporting, local Qdrant authorization coverage, provider-neutral live-model boundaries, and synthetic vulnerable-vs-hardened comparisons.

Onyx inspection identified current authorization/retrieval boundaries in:

- `backend/onyx/auth/users.py`
- `backend/onyx/access/access.py`
- `backend/ee/onyx/access/access.py`
- `backend/onyx/context/search/preprocessing/access_filters.py`
- `backend/onyx/context/search/pipeline.py`
- `deployment/docker_compose/README.md`

Preliminary non-O1 architecture inventory also located MCP/OAuth under `backend/onyx/server/features/mcp/`, sandbox code under `backend/onyx/server/features/build/sandbox/`, Docker Compose under `deployment/docker_compose/`, and Helm/Kubernetes assets under `deployment/helm/`. Those components are not implemented or attacked in O1.

### Files changed

Documentation-only design slice:

- `docs/onyx-security-validation/architecture.md`
- `docs/onyx-security-validation/trust-boundaries.md`
- `docs/onyx-security-validation/threat-model.md`
- `docs/onyx-security-validation/test-matrix.md`
- `docs/onyx-security-validation/assumptions.md`
- `docs/onyx-security-validation/evidence-model.md`
- `docs/onyx-security-validation/local-lab.md`
- `docs/onyx-security-validation/progress.md`

No implementation code has been changed in this slice, intentionally: architecture, threat model, and acceptance criteria are recorded first.

### Tests executed

None for this documentation-only slice. No claim of executable O1 verification is made.

### Exact inspection commands/actions

Repository revisions were resolved from GitHub and source files were read at the exact SHAs above. Local cloning was attempted in the execution sandbox but outbound DNS was unavailable; no test result is inferred from that tooling limitation.

### Evidence generated

No O1 security evidence JSON yet. Documentation is planning evidence only and must not be labeled `VERIFIED`.

### Known limitations

- Exact authenticated API calls for fixture provisioning and retrieval still need to be bound to the pinned Onyx revision during implementation.
- Group-specific live cases depend on an Onyx edition/configuration that exposes group ACLs.
- Runtime image-to-source commit binding for Docker Compose must be made explicit.
- Revocation/index/cache consistency behavior is not yet executed.
- No live-local Onyx process has been started by this documentation slice.

### Follow-up tasks

1. Implement `aegis.targets.onyx` safety/config/client/evidence vertical slice.
2. Add deterministic unit tests for fail-closed target validation and evidence/metric aggregation.
3. Add programmatic synthetic fixture definitions.
4. Bind fixture provisioning and retrieval to current Onyx APIs at the pinned revision.
5. Add explicit opt-in live-local RAG authorization tests.
6. Run focused quality/test gates and generate sanitized O1 evidence.
7. Update this file to `implemented` and then `verified` only when acceptance criteria have executable evidence.

## O2 and later

State: `deferred`

MCP, confused-deputy, SSRF, sandbox, resource-abuse, supply-chain, and broader detection implementation is deferred until O1 is clean and tested.