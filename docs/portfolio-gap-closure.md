# Portfolio gap closure

This plan was derived from the top-level documentation, `pyproject.toml`, all workflows, phase progress records, threat models, evaluations, security tests, and the vulnerable/hardened RAG, agentic, supply-chain, training, and inference implementations. Status describes repository implementation evidence, not production deployment.

| Gap | State | Evidence / remaining work |
|---|---|---|
| Concise P11-E portfolio presentation and four case studies | implemented | `README.md` |
| Explicit deterministic/live-local/production claim boundary | implemented | `README.md`; existing phase progress records |
| Contributor guidance | implemented | `CONTRIBUTING.md` |
| Repository security policy | blocked | Draft requires explicit preview approval under the repository security-policy workflow before `SECURITY.md` is written. |
| Owner-selected license | blocked | No license is present. The owner must choose MIT, Apache-2.0, or another policy; none is invented here. |
| Pinned lint, format, types, static security, audit, coverage, secret gates | implemented | `pyproject.toml`; `.github/workflows/quality.yml` |
| Quality-gate execution in this workspace | verified | The configured focused quality sequence passed locally. The current complete unit, integration, evaluation, and security sequence passed: 2,848 tests. |
| Duplicated full pytest in historical workflows | deferred | Branch-protection settings were unavailable (`403`) and phase jobs share the `tests` name. Workflows remain unchanged; `docs/ci-consolidation-plan.md` maps a proposed nine-run reduction and required owner checks. |
| Provider-neutral real-model boundary | implemented | `real_model_evals/`; fake and live evidence cannot be confused |
| Real-model execution | blocked | Requires explicit opt-in, endpoint, model identifier, repository-specific credential, and budget approval. No normal test requires it. |
| Compact adaptive adversarial corpus | implemented | `synthetic_data/adaptive_ai_security_cases.json`; feedback mutation in `evals/portfolio_adaptive_security.py` |
| Multimodal model execution | deferred | Safe image metadata boundary exists in the corpus; no real multimodal model is configured. |
| Raw ASR/FPR/SafeTaskRate derivation | implemented | `evals/portfolio_adaptive_security.py`; flagship demo evidence |
| Citation binding, support, conflict, abstention, leakage and tool-output checks | implemented | `aegis/rag/evaluation.py`; focused tests |
| Proof of factual correctness | deferred | Structural heuristics are explicitly not represented as factual proof. A governed external fact source/model evaluation would be required. |
| Real Qdrant local authorization cases | implemented | `KnowledgeStore`; focused tests cover tenant filtering, collection identity, poison/near duplicate, revocation and metadata bypass |
| Distributed stale-index behavior | deferred | Local Qdrant tests model revocation state; production replicas and concurrent index refresh are not available. |
| Verified framework crosswalk | implemented | `docs/framework-crosswalk.md`; mappings are limited to full/partial/gap and repository evidence |
| Four-case deterministic portfolio command | implemented | `python scripts/run_portfolio_demo.py` writes sanitized JSON and Markdown under ignored `build/portfolio-demo/` |

## Implementation notes

The vertical slices reuse existing analyzers and Qdrant local mode. The real-model adapter uses an OpenAI-compatible HTTP contract but is provider-neutral at the adapter protocol. It records model/endpoint class, seed, temperature, dataset/policy hashes, code revision, bounded sanitized outputs, and budget use. It never requests or records chain of thought. A missing live configuration returns `BLOCKED` and exit code 2.

The quality workflow has read-only contents permission, pinned action commits, credential persistence disabled, dependency caching, concurrency cancellation, and a job timeout. Ruff and mypy are initially focused on the new and RAG security boundary; Bandit and Semgrep cover the same security-sensitive slice. Dependency and reviewed-baseline secret scans remain repository-wide. Historical full-suite duplication is recorded rather than changed without repository-settings evidence.

## Local verification record (2026-08-20 UTC)

- `ruff format --check ...`: passed, 11 files already formatted.
- `ruff check ...`: passed with no findings.
- `mypy real_model_evals aegis/rag/evaluation.py`: passed, 5 source files checked.
- `bandit -q -r aegis/rag real_model_evals`: passed with no reportable findings.
- `semgrep scan --config p/python --error aegis/rag real_model_evals`: passed with no reportable findings.
- `pip-audit .`: passed with no known vulnerabilities in the project dependency graph. The unscoped shared-environment audit separately reports unrelated Codespace tool advisories and is not the configured project audit.
- Reviewed-baseline secret detection: passed; the baseline is valid JSON containing exactly eight reviewed synthetic findings, and changed files produced no unreviewed findings.
- Focused pytest with branch coverage: 7 passed; 75.70% coverage, above the 65% focused floor.
- P8-A regression proof after restoring its missing fixture import: 13 passed.
- `python scripts/run_portfolio_demo.py`: `VERIFIED`; four reports emitted under ignored `build/portfolio-demo/`.
- Offline adapter: `VERIFIED`, 2/4 request budget used. Live adapter: `BLOCKED` and exit 2 because no opt-in/configuration exists.
- The current complete sequence passed outside the bundled sandbox: unit 122, integration 10, evaluations 5, and security 2,711, for 2,848 tests.
- The earlier AnyIO/TestClient and MCP negotiation timeouts were sandbox artifacts, not repository blockers.
- System bubblewrap 0.9.0 at `/usr/bin/bwrap` resolved the Codex bundled-bubblewrap sandbox issue.
- Real-model and multimodal execution, NVIDIA GPU/MIG/CUDA, production cloud IAM/KMS/HSM, multi-node and production infrastructure, production registry/SIEM/SOC, production-scale reliability, the repository security-policy approval, and an owner-selected license remain unverified, deferred, or owner-blocked as described above.
