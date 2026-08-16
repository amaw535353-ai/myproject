# P11-B review boundary

This branch is suitable for review of the deterministic Kubernetes enforcement contract and the live-cluster harness, but it must not be merged under a claim that P11-B professional mastery is complete until a real Kubernetes run is available.

The deterministic analyzer is intentionally paired with a vulnerable baseline that trusts only a caller declaration. The hardened path requires admission, RBAC, service-account token, NetworkPolicy/CNI, namespace isolation, containment/recovery, and audit evidence. The live harness obtains the cluster identity, PSA state, NetworkPolicy objects, server-side admission outcomes, and RBAC outcomes directly from Kubernetes.

Two evidence-integrity issues discovered during branch review were corrected before review: pod-level fields are no longer duplicated into container objects in server-side admission probes, and RBAC probes now preserve the source service-account namespace independently from the target resource namespace. This prevents schema-error false positives and false cross-namespace denials.

Generic CI deliberately does not claim a live Kubernetes pass. It validates deterministic tests/evaluation and compiles the live harness. The live mastery debt remains explicit.
