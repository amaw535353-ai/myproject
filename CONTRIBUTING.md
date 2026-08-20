# Contributing

AegisDesk accepts small, reviewable security-engineering changes. Keep intentionally vulnerable code under `aegis/vulnerable` or the explicit vulnerable app, use only synthetic local targets, and preserve the distinction between deterministic, live-local, and production evidence.

Before proposing a change:

1. Install pinned development dependencies with `python -m pip install -e ".[dev]"`.
2. Add a focused test that demonstrates the security invariant and, where useful, the vulnerable comparison.
3. Run the Ruff, mypy, Bandit, dependency-audit, secret-scan, and focused pytest commands from `.github/workflows/quality.yml`.
4. Report raw metric numerators and denominators; never replace an unexecuted live gate with fake output.
5. Do not include credentials, raw sensitive transcripts, chain of thought, private prompts, or real third-party attack traffic.

Dependency changes must be pinned and justified. New exclusions, accepted risks, network access, external side effects, and production claims require explicit maintainer review. The repository currently has no owner-selected license; contribution terms should not be inferred until that decision is made.
