# Phase 8 progress — agentic trust, authority, state, execution, autonomy, communications, concurrency, and artifact integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A through P8-H established delegation/authority propagation, memory/context boundaries, goal/plan integrity, tool-result/environment integrity, execution-budget security, human approval/autonomy boundaries, inter-agent message/protocol security, and concurrency/race security. P8-I now secures agent workspaces, generated artifacts, and code/supply-chain persistence paths.

## P8-A through P8-H

P8-A through P8-H are complete for the current deterministic synthetic-lab scope. Their evidence establishes original-principal authority, state provenance, instruction/goal integrity, exact tool-result binding, bounded resource consumption, evidence-bound human approval, provenance-preserving messaging, and race-aware state transitions.

## P8-I — agent artifact, workspace, and generated-code integrity

Status: **implemented and deterministically exercised in an isolated P8-I harness; hosted runner execution pending infrastructure**.

P8-I adds `AgentArtifactWorkspaceSecurityAnalyzer`. The workspace is modeled as a security boundary: an authorized agent write is not automatically safe if it escapes the allowed path, crosses tenant scope, changes executable state, persists through dependency/build/CI/startup configuration, launders untrusted provenance, or races against the approved state.

The canonical fixture contains **2 workspaces, 9 artifacts, and 9 actions** spanning generated source, dependency manifest, lockfile, CI workflow, startup hook, inbound archive, release artifact, Dockerfile/build configuration, and a generated document.

The hardened boundary enforces:

- exact graph ID/version/SHA-256 and freshness;
- exact P8-C goal/plan, P8-F human-approval, and P8-H state-transition evidence binding;
- exact workspace/artifact/action coverage and trusted owners;
- policy-pinned workspace tenant/root/write/execute/build-context prefixes;
- policy-pinned initial artifact path, kind, trust label, content digest, executable state, and link metadata;
- relative-only normalized paths and allowed-write-prefix confinement;
- symlink/hardlink target confinement;
- archive member path/link confinement plus deterministic member/byte limits;
- cross-tenant denial;
- exact expected-base and resulting content SHA-256 reasoning;
- plan-step actor continuity and state-transition safety;
- approval requirements for dependency/lock/build/CI/startup/release/executable paths;
- generated/untrusted source lineage preventing trust-label laundering;
- build-context poisoning detection;
- executable-write and execution approval/path checks; and
- rejection of caller-provided denied/risk/result summaries that disagree with derived evidence.

### Deterministic evidence

The exact standalone P8-I module, fixture, evaluator, vulnerable baseline, and tests were exercised in an isolated Python environment:

- tests: **16 passed**;
- adversarial cases: **135**;
- vulnerable ASR: **135/135**;
- hardened ASR: **0/135**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- artifact graph SHA-256: `397b28558c6ddf50a67263dc3cb06f66a7d6b2eec67c7354b4909efc750265f4`;
- adversarial dataset SHA-256: `8ef250681c0d454b866fd2c58ffd5e0c5f7e709083209184cd3285bed8bad87c`;
- fixture SHA-256: `f18e3afef238a177109a73cdfe619fb5bedd9cf835fd612f88e1e088b15e559b`;
- clean assessment SHA-256: `6c5b49bd8798e7a9c35c945bdc3eab89e342f0d9365945411a604ef8787994b8`.

This is isolated P8-I execution, not a claim that full-repository pytest ran locally or that production filesystems, sandboxes, build systems, or signing systems were exercised.

### Free/open-source implementation path

No new runtime dependency was added. P8-I documents optional future integration paths using Trivy for repository/filesystem security scanning and SBOM generation, OSV-Scanner for dependency vulnerability analysis, in-toto for signed/authorized supply-chain step and artifact-rule evidence, and Sigstore Cosign for signing/verifying blobs or release artifacts. These remain optional future enforcement/evidence sources, not dependencies or executed P8-I evidence.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: complete for current deterministic synthetic scope.
- P8-D: complete for current deterministic synthetic scope.
- P8-E: complete for current deterministic synthetic scope.
- P8-F: complete for current deterministic synthetic scope.
- P8-G: complete for current deterministic synthetic scope.
- P8-H: complete for current deterministic synthetic scope.
- P8-I: implemented with isolated deterministic evidence; hosted execution remains infrastructure-blocked.

## Next direction

P8-J should broaden into **agent rollback, recovery, and persistence-boundary security**: durable checkpoints, safe resume, compromised-state quarantine, persistence revocation, recovery provenance, destructive rollback authorization, and ensuring recovery cannot silently reintroduce previously rejected memory, artifacts, messages, or credentials.
