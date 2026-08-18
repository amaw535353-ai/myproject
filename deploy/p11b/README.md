# P11-B local Kubernetes security lab

`lab.yaml` is the hash-bound bootstrap manifest. The runner creates one k3d server using pinned `rancher/k3s:v1.33.5-k3s1`, disables Traefik and ServiceLB, and deletes the cluster in `finally` unless `--keep` is explicitly supplied.

Admission attacks use server-side dry-run, RBAC cases use the Kubernetes authorization API, and NetworkPolicy is tested baseline-first with live pods. Deterministic fixtures never support a live claim.
