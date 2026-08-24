# Changelog

This project records notable capability changes here. It does not imply a published release.

## Unreleased

- Added an opt-in, budgeted real-model RAG/MCP security slice with 20 reviewed prompt-injection attacks, 5 safe tasks, strict model-output validation, vulnerable/hardened replay, and synthetic side-effect evidence.
- Added a release-candidate workflow for wheel/source builds, CycloneDX dependency SBOMs, archive and metadata validation, smoke installation, SHA-256 manifests, exact-SHA artifacts, and manually gated build-provenance attestations.
- Hardened model endpoint validation against lookalike loopback hosts, credential-bearing URLs, redirects, oversized responses, and malformed response payloads.
- Added detection-to-incident correlation, lifecycle governance, execution controls, and handoff boundaries.
- Added deterministic and live-local Phase 11 platform, Kubernetes, cloud, serving, supply-chain, and detection-engineering evidence.
- Added training and inference tenant-isolation controls, multi-agent approval boundaries, and model supply-chain validation.
- Added a deterministic four-case portfolio demonstration with explicit evidence limitations.

Earlier work is traceable through the repository history and `docs/phase*-progress.md` records; no version dates are invented here.
