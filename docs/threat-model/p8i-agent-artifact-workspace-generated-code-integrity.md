# P8-I — agent artifact, workspace, and generated-code integrity

## Security objective

P8-I treats the agent workspace as an execution and supply-chain boundary, not a trusted scratch directory. A write is only safe when its destination, provenance, upstream authorization, resulting artifact type/trust, executable state, archive/link semantics, and persistence implications all remain inside an evidence-bound policy.

The implementation adds `AgentArtifactWorkspaceSecurityAnalyzer` with a matched intentionally vulnerable `VulnerableDeclaredArtifactSafety` baseline.

## Threat model

The attacker may control or influence prompts, retrieved content, tool outputs, generated patches, archive contents, target paths, declared artifact types/trust labels, source provenance, approval references, and action summaries. The attacker may try to turn an otherwise permitted file operation into broader code execution or durable persistence.

P8-I specifically models:

- relative-path traversal, absolute paths, alternate backslash-style escape attempts, and writes outside policy-pinned prefixes;
- symlink and hardlink targets that escape the workspace boundary;
- archive member traversal, archive link escapes, and deterministic member/byte limits;
- cross-tenant artifact actions and workspace/profile drift;
- stale base-content digests and caller-forged resulting digests;
- generated/untrusted inputs laundered into `verified` or `trusted_control` artifacts;
- dependency-manifest and lockfile persistence;
- CI workflow, startup hook, and build-configuration persistence;
- generated/untrusted material introduced into protected build-context paths;
- creation or mutation of executable artifacts outside approved execution paths;
- execution/publish actions without evidence-bound approval;
- exact P8-C plan-step, P8-F approval, and P8-H state-transition safety at use time; and
- caller-declared denied/risk/result summaries that disagree with derived evidence.

## Evidence model

The canonical manifest contains **2 workspaces, 9 artifacts, and 9 artifact actions**. It binds exact P8-C/P8-F/P8-H assessment digests and pins workspace tenants/roots/write/execute/build-context prefixes plus initial artifact path, type, trust, digest, executable state, and link metadata.

The clean path covers:

- a tenant-scoped generated source update;
- approved dependency-manifest and lockfile updates;
- an approved CI workflow update;
- an approved executable startup-hook update and later execution;
- extraction of an untrusted archive into a scratch prefix with safe members;
- an approved release-artifact publish action; and
- an approved Dockerfile/build-config update.

No caller-owned `safe`, `path_confined`, `trusted`, `approved`, or final-digest flag is accepted as authoritative evidence.

## Free/open-source implementation path

P8-I adds no runtime dependency. It is intentionally compatible with optional open tooling that can strengthen later production integrations:

- **Trivy** can scan repositories/filesystems for known vulnerabilities, misconfigurations, secrets, licenses, and can generate SBOMs;
- **OSV-Scanner** can analyze source manifests/lockfiles and other supported artifacts for known vulnerable dependencies;
- **in-toto** can record and verify authorized supply-chain steps plus material/product rules; and
- **Sigstore Cosign** can sign and verify files/blobs or container artifacts, providing a future cryptographic provenance layer.

These tools are optional integration paths only. P8-I does not add them as dependencies or claim they were executed by the analyzer.

## Deterministic evidence

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

This is isolated P8-I execution, not a claim that full-repository pytest or production filesystem/sandbox/build systems ran locally.

## Claim boundary

P8-I does **not** claim production filesystem or container sandbox enforcement, operating-system-level path resolution, real symlink race prevention, kernel namespace isolation, semantic malware/backdoor detection, real archive decompression safety, cryptographic signing/verification, production SBOM/SCA coverage, production build-system isolation, formal filesystem-confinement proof, exhaustive supply-chain attack coverage, or automatic remediation.

`trusted_control`, `verified`, and related labels are deterministic policy classifications in this synthetic lab, not cryptographic trust assertions.
