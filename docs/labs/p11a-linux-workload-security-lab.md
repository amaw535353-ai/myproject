# P11-A professional lab — Linux workload isolation and Kubernetes hardening

Run the focused gate from the repository root:

```bash
python scripts/verify_phase11.py --focused-p11a
```

The Linux lab uses real OS processes under separate numeric UIDs. It drops the capability bounding/effective sets, enables `no_new_privs`, checks owner-only secret access, denies a foreign tenant secret read, proves a read-only root-like directory with a scoped writable directory, verifies raw-socket and setuid-root denial, verifies cross-UID signal and `/proc/<pid>/environ` denial, and exercises Unix-domain-socket DAC isolation. Root or passwordless `sudo` is required because the lab deliberately changes process UIDs.

The Kubernetes artifact is `deploy/p11a/kubernetes.json`. Kubernetes accepts JSON manifests, so no YAML dependency is required. `scripts/check_p11a_k8s_manifests.py` verifies Pod Security Admission labels, disabled service-account-token automount, namespaced RBAC, digest-pinned images, non-root security contexts, `allowPrivilegeEscalation=false`, read-only root filesystems, `ALL` capability drop, RuntimeDefault seccomp/AppArmor, resource requests/limits, no hostPath/runtime socket surface, restricted secret/projected-token modes, bounded workload-token audience/TTL, and ingress/egress network allowlists.

A passing static manifest check is not a live-cluster result. Until an authorized Kubernetes cluster is available, `p11a-live-kubernetes-cluster` remains on the professional-mastery debt ledger. Live CNI enforcement, admission-controller behavior, service-account token behavior, and container-runtime/kernel isolation must be tested later on actual cluster infrastructure.
