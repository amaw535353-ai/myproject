# Onyx Security Validation Progress

## O1 — Onyx Target Adapter + RAG Authorization

State: `planned`

The O1 milestone is not yet complete. The architecture/design checkpoint and the first deterministic target-adapter slice are implemented; live-local fixture provisioning and RAG authorization execution remain pending.

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
- `backend/onyx/server/features/search/api.py`
- `deployment/docker_compose/README.md`

The pinned search API exposes `POST /api/search`, requires the server-resolved user to hold `Permission.READ_SEARCH`, creates the search tool with `bypass_acl=False`, and routes through the normal search authorization path. It also obtains an LLM and performs usage-limit checks, so it is not yet assumed to be the cheapest or most deterministic live-local O1 retrieval surface.

Preliminary non-O1 architecture inventory also located MCP/OAuth under `backend/onyx/server/features/mcp/`, sandbox code under `backend/onyx/server/features/build/sandbox/`, Docker Compose under `deployment/docker_compose/`, and Helm/Kubernetes assets under `deployment/helm/`. Those components are not implemented or attacked in O1.

### Files changed

Design/documentation slice:

- `docs/onyx-security-validation/architecture.md`
- `docs/onyx-security-validation/trust-boundaries.md`
- `docs/onyx-security-validation/threat-model.md`
- `docs/onyx-security-validation/test-matrix.md`
- `docs/onyx-security-validation/assumptions.md`
- `docs/onyx-security-validation/evidence-model.md`
- `docs/onyx-security-validation/local-lab.md`
- `docs/onyx-security-validation/progress.md`

First implementation slice:

- `aegis/targets/__init__.py`
- `aegis/targets/onyx/__init__.py`
- `aegis/targets/onyx/config.py`
- `aegis/targets/onyx/safety.py`
- `aegis/targets/onyx/client.py`
- `aegis/targets/onyx/fixtures.py`
- `aegis/targets/onyx/evidence.py`
- `tests/security/test_onyx_target_adapter.py`
- `.github/workflows/quality.yml`

### Implemented acceptance slice

- Mandatory `AEGIS_ONYX_LAB_ACK=YES` acknowledgement is represented by the target configuration and enforced by the safety gate.
- Loopback literals are accepted only after acknowledgement; `localhost` must resolve exclusively to loopback.
- Non-loopback targets are disabled by default.
- Private-lab targets require explicit private-network opt-in, an exact hostname allowlist entry, and resolution entirely inside loopback/RFC1918/IPv6 ULA ranges.
- Target URLs containing credentials, query strings, fragments, application paths, invalid ports, or unsupported schemes fail closed.
- A matching lab marker is required after location validation.
- The client wrapper validates location before calling the marker probe, so an obviously unauthorized public target receives no application-level probe or attack request.
- The client revalidates target resolution before every request and blocks resolution drift.
- Synthetic `alice`, `bob`, and `attacker` identities plus engineering/HR/public/revoked/poisoned document fixtures are deterministic and contain only `.test` identities and synthetic canaries.
- Evidence serialization redacts credential-bearing fields and rejects evidence explicitly marked unsanitized.
- ASR, FPR, and SafeTaskRate preserve raw numerator/denominator counts; blocked cases do not enter executable denominators and a zero denominator produces `null`/`None`, not `0%`.
- Run aggregation is fail closed: an empty run is `BLOCKED`; confirmed unauthorized effects force `FAILED`; otherwise any blocked case prevents `VERIFIED`.

### Tests executed

The execution container cannot resolve `github.com`, so cloning the branch for an exact repository-native local run failed with:

```text
git clone --depth 1 --branch onyx-o1-design https://github.com/amaw535353-ai/myproject.git /tmp/aegisdesk-o1
fatal: unable to access 'https://github.com/amaw535353-ai/myproject.git/': Could not resolve host: github.com
```

A local isolated reconstruction of the current adapter logic was executed with the installed Python/pytest environment to validate imports and the core target/client/evidence assertions. Result:

```text
2 passed in 0.07s
```

That reconstruction is a developer sanity check, not repository-native O1 evidence and not a live-local Onyx result.

The repository's `focused-quality` workflow was extended so the exact branch implementation is covered by:

```text
ruff format --check aegis/targets/onyx tests/security/test_onyx_target_adapter.py ...
ruff check aegis/targets/onyx tests/security/test_onyx_target_adapter.py ...
mypy ... aegis/targets/onyx
bandit -q -r ... aegis/targets/onyx ...
semgrep scan --config p/python --error ... aegis/targets/onyx ...
detect-secrets-hook --baseline .secrets.baseline aegis/targets/onyx/*.py tests/security/test_onyx_target_adapter.py
python -m pytest ... tests/security/test_onyx_target_adapter.py ...
```

GitHub Actions runs were queued for the branch during this slice. A queued or cancelled workflow is not recorded as a passing test.

### Evidence generated

No O1 security evidence JSON has been generated yet because no authenticated Onyx RAG authorization case has executed. The deterministic adapter tests are control-development evidence only and must not be described as live-local Onyx verification.

### Known limitations

- No concrete HTTP transport is bound to Onyx yet; `OnyxTransport` is deliberately a protocol so endpoint contracts are not guessed before source inspection.
- The lab-marker probe endpoint/service still needs a reproducible loopback/private-lab implementation. It should preferably be an external lab marker/sidecar or other clearly local mechanism rather than an upstream production behavior assumption.
- Exact authenticated API calls for user creation/login, group provisioning, document ingestion/ACL assignment, revocation, and retrieval still need to be bound to the pinned Onyx revision.
- `POST /api/search` is source-confirmed but may require an LLM path; a more deterministic authorization-focused retrieval surface should be preferred if the pinned code exposes one.
- Group-specific live cases depend on an Onyx edition/configuration that exposes group ACLs.
- Runtime image-to-source commit binding for Docker Compose must be made explicit.
- Revocation/index/cache consistency behavior is not yet executed.
- No live-local Onyx process has been started by this slice.
- No production security claim is made.

### Follow-up tasks

1. Bind a concrete loopback/private-lab transport and lab-marker probe without relaxing the target gate.
2. Inspect and bind current Onyx user/admin authentication APIs for synthetic fixture provisioning.
3. Inspect and bind current group/document ACL provisioning APIs for the selected local edition.
4. Select the narrowest source-confirmed retrieval API that exercises Onyx ACL enforcement without requiring paid/external services.
5. Add explicit opt-in live-local cross-user/cross-group RAG tests and direct document-ID negative cases.
6. Generate sanitized case JSON with exact Onyx and AegisDesk commits and raw metrics.
7. Run focused repository-native quality gates plus broader relevant regressions.
8. Change O1 to `implemented` only after the full milestone code path exists, and to `verified` only after every acceptance gate has executable evidence.

## O2 and later

State: `deferred`

MCP, confused-deputy, SSRF, sandbox, resource-abuse, supply-chain, and broader detection implementation is deferred until O1 is clean and tested.
