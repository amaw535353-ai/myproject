# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-I

P2-I adds a deterministic **malicious artifact and file handling** comparison at the untrusted-file -> storage/extraction/rendering trust boundary.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- retrieved text cannot expand server-owned tool capabilities;
- MCP discovery metadata cannot override host-owned server/tool bindings;
- inbound MCP bearer credentials terminate at the gateway and never reach downstream tool execution;
- downstream access uses a server-owned credential broker with a separate least-privilege credential;
- outbound URL policy revalidates DNS answers and every redirect target before synthetic connection;
- durable memory remains data and cannot replace server-derived identity, tenant, role, or approval authority;
- multi-step agent execution is bounded by server-owned step/model/tool/retry/byte/time budgets;
- telemetry is converted to typed, allowlisted, pseudonymized security events before export;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, SQLite, in-memory MCP, and GitHub Actions require no paid model API.

P2-I introduces a hardened `ArtifactService` with server-assigned storage paths, passive-content allowlisting, strict UTF-8 text handling, `nosniff` presentation metadata, and bounded ZIP extraction. Client filenames are display metadata only and cannot choose filesystem destinations. ZIP members are normalized and rejected for traversal, absolute/drive-like paths, backslashes, symlinks, duplicate normalized names, disallowed member types, excessive member count, excessive member size, excessive aggregate expansion, or excessive compression ratio.

The intentionally vulnerable comparison trusts the client filename as a filesystem path, trusts the declared content type for inline rendering, and expands ZIP members without path or size validation. The matched evaluation uses only temporary local directories and synthetic artifact bytes.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The separate intentionally vulnerable HTTP lab from earlier Phase 2 exercises is launched only through its explicit factory:

```bash
uvicorn apps.vulnerable_api.main:create_intentionally_vulnerable_lab_app \
  --factory --host 127.0.0.1 --port 8001
```

Never expose the vulnerable lab publicly and never point attack examples at third-party systems.

## Deterministic security comparisons

```bash
python -m evals.p2a_tenant_boundary
python -m evals.p2b_indirect_prompt_injection
python -m evals.p2c_mcp_tool_poisoning
python -m evals.p2d_token_passthrough
python -m evals.p2e_ssrf_redirects
python -m evals.p2f_durable_memory_poisoning
python -m evals.p2g_resource_exhaustion
python -m evals.p2h_telemetry_leakage
python -m evals.p2i_artifact_handling
```

P2-I uses three fixed adversarial attempts and two benign attempts per variant. The attacks cover client-filename path traversal, active HTML inline rendering, and archive expansion beyond the server-owned byte budget. Unit tests additionally cover ZIP-member traversal, symlinks, content-type mismatch, duplicate normalized archive names, and safe nested extraction.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/policy/dataset/fixture evidence. They report only policy decisions, safe path/byte facts, and metric outcomes; they do not print artifact bodies, active HTML, raw archive-member contents, credentials, canaries, or external filesystem data.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `docs/threat-model/p2c-mcp-tool-poisoning.md`
- `docs/threat-model/p2d-token-passthrough.md`
- `docs/threat-model/p2e-ssrf-redirects.md`
- `docs/threat-model/p2f-durable-memory-poisoning.md`
- `docs/threat-model/p2g-resource-exhaustion.md`
- `docs/threat-model/p2h-telemetry-redaction.md`
- `docs/threat-model/p2i-malicious-artifacts.md`

### Prototype limitations

P2-I is a local stdlib-only ingestion proof, not a malware scanner or document-sanitization platform. Production artifact handling still needs authenticated object storage, per-tenant access control, antivirus/content-disarm integration where appropriate, quarantine workflows, signed download URLs, retention/deletion rules, storage quotas, media-specific parsers running under strong sandboxing, and browser response headers such as a production Content Security Policy.

P2-H proves application-side telemetry minimization before an in-memory sink. A production observability pipeline still needs protected HMAC-key storage and rotation, transport encryption, collector/backend access control, retention limits, tenant-aware query authorization, exporter/collector-side defense in depth, log-injection hardening, and periodic automated secret scanning of telemetry samples.

P2-G remains an in-process resource-control proof. A production agent still needs provider-side token/cost limits, cancellation for hung tools, streaming byte caps, distributed per-user/per-tenant quotas, concurrency/load shedding, and operating-system/container CPU and memory isolation.

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable approval persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, memory records, resource-exhaustion workloads, telemetry records, artifacts, archives, and side effects in this repository are synthetic.
