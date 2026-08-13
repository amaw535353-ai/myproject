# Phase 3 integration progress

Phase 3 started with six integration gaps. P3-A closed `P3-G01`, P3-B closed `P3-G02`, P3-C closed `P3-G03`, P3-D closed `P3-G04`, P3-E closed `P3-G05`, and P3-F closes `P3-G06` by putting the trust-bearing high-impact dependencies behind an explicit provider boundary.

Current posture after P3-F:

- Phase 2 controls: 19/19 implemented and evaluated.
- Default API controls: 16.
- Partial default API controls: 0.
- Lab-only controls: 3 (`P2-E`, `P2-I`, `P2-J`).
- Open Phase 3 integration gaps: 0.

P3-F makes authorization signing, protected checkpoint state, checkpoint receipt sourcing, and receipt witnessing explicit provider surfaces. The bundled provider factory remains local and synthetic and its manifest is not eligible for a production trust claim. A production-external profile requires external provider classification, independent failure domains, and external key custody for the signing surfaces.

No real external trust provider is included. Closing the integration gap means the replacement seam and fail-closed posture are now explicit; it does not mean the repository is production ready. Real external provider implementations and operational validation remain deployment work outside this lab.
