# P11-B live Kubernetes mastery execution

P11-B is not complete from deterministic evaluation or static manifests alone. A live mastery result requires a disposable Kubernetes cluster with an enforcing NetworkPolicy-capable CNI and a real attack → observe → contain → recover exercise.

## Required live observations

The operator must establish the `tenant-acme-inference` namespace with `pod-security.kubernetes.io/enforce=restricted`, the `aegisdesk-inference` service account, least-privilege RBAC, and NetworkPolicies. The live run must then demonstrate all of the following from the cluster rather than from caller declarations:

1. Server-side admission rejects privileged execution, host namespaces, hostPath, added capabilities, and privilege escalation.
2. The workload identity can read only its intended runtime configuration and cannot list secrets, create pods, create RoleBindings or ClusterRoleBindings, or read secrets in another namespace.
3. The workload uses a projected, audience-bound, short-lived service-account token; wrong-audience use fails; post-containment replay fails.
4. The intended serving dependency remains reachable while cross-namespace traffic, arbitrary egress, direct Kubernetes API egress, and metadata-style egress are denied by the live CNI.
5. A compromised pod is terminated, its effective identity is fenced, and a clean replacement with a different pod UID becomes ready.
6. Audit evidence records the attack signal, admission/RBAC denials, and containment actions.

## Harness boundary

`scripts/run_p11b_kubernetes_lab.py` obtains admission, RBAC, namespace, cluster, and NetworkPolicy observations directly through `kubectl`. The `--runtime-evidence` input exists only for observations that the current generic harness cannot safely infer across arbitrary CNI/runtime implementations. The example JSON under `deploy/p11b/` is a schema/template, not evidence.

A `LIVE_MASTERY_PASS` is therefore acceptable only when the runtime-evidence file is produced during the same documented live exercise and the operator retains the command/output or audit artifacts that substantiate each boolean. Supplying `true` values manually is not professional-mastery evidence.

Until such a run occurs, `p11a-live-kubernetes-cluster` remains open and Phase 11 must report live Kubernetes mastery as deferred.
