# Follow-up engineering roadmap

These plans are intentionally separate from the governance branch. They do not authorize workflow changes, live infrastructure execution, or broad typing rewrites.

## `codex/ci-consolidation`

Reconcile the current workflow inventory with protected-branch requirements before editing CI. Preserve required check identities; retain one complete suite and one focused quality/security gate; make remaining jobs phase-targeted or scheduled; measure before/after workflow duration from comparable runs; and demonstrate no coverage reduction. Acceptance requires a clean test PR whose required contexts complete successfully, documented duration evidence, the complete suite still passing, and focused and repository-wide coverage at or above current thresholds.

## `codex/p11b-live-kind-evidence`

Reconcile PRs #104 and #105 before selecting or porting any implementation. Use a disposable local kind cluster and record Kubernetes, kind, and CNI versions or immutable digests. Preserve sanitized command, admission, authorization, network, and audit evidence. Missing tooling or unavailable live execution must remain `BLOCKED`, never a pass. Acceptance requires successful cleanup of the disposable cluster, hash-bound evidence from the executed environment, explicit failure states, and no production-cluster or production-readiness claim.

## `codex/incremental-typing-coverage`

Expand strict mypy one package at a time and extend coverage beyond `aegis.rag` and `real_model_evals`. Report focused and repository-wide coverage separately, do not lower current thresholds, and avoid a mass annotation-only rewrite. Acceptance for each increment requires behavior-preserving tests, strict mypy success for the newly included package, unchanged or higher configured thresholds, and recorded focused and repository-wide coverage deltas.
