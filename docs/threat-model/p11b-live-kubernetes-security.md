# P11-B live Kubernetes security threat model

## Boundary and assets

The local gate protects a Restricted namespace, a least-privilege ServiceAccount, and a victim service. Attackers may submit hostile pod specifications, abuse Kubernetes authorization, or reach the victim from an unauthorized pod. Kubernetes admission responses, authorization API results, and in-cluster probes are authoritative.

## Required controls

Pod Security Admission must reject privileged execution, privilege escalation, `SYS_ADMIN`, host PID/network namespaces, hostPath, UID 0, and missing seccomp while admitting one Restricted-compatible pod. RBAC grants only named ConfigMap read and denies the other nine cases. NetworkPolicy evidence requires a working baseline, an authorized post-policy path, and a denied attacker path.

Canonical SHA-256 binds `deploy/p11b/*.yaml`; metrics derive from raw observations. Missing tools, cluster failures, pre-API errors, DNS failures, and infrastructure failures are never security passes.

## Claim boundary

This is a single-node local k3d/K3s validation with pinned k3d `v5.8.3` and K3s image `rancher/k3s:v1.33.5-k3s1`. It does not validate EKS, GKE, AKS, production Kubernetes/CNI, cloud IAM/workload identity, multi-node behavior, container escape or kernel compromise resistance, NVIDIA GPU/MIG/CUDA, or production SOC/IR maturity. Production-validation and professional-mastery claims remain false.
