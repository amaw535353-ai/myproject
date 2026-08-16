# P11-B runtime evidence

`runtime_evidence.example.json` is a template only. It intentionally defaults all security observations to false and must never be treated as evidence or converted into a passing result by editing values manually.

A valid P11-B live run must be performed against a real Kubernetes cluster and must retain the underlying command output, Kubernetes audit material, pod identities, token observations, and network/CNI observations supporting the populated runtime evidence. See `docs/p11b-live-execution.md`.
