#!/usr/bin/env bash
set -euo pipefail

KIND_VERSION="${KIND_VERSION:-v0.27.0}"
KUBECTL_VERSION="${KUBECTL_VERSION:-v1.32.3}"
CLUSTER_NAME="${P11B_CLUSTER_NAME:-aegis-p11b}"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

need() { command -v "$1" >/dev/null 2>&1 || return 1; }

if ! need docker; then
  echo "P11B_BOOTSTRAP_BLOCKED: docker CLI missing" >&2
  exit 20
fi
if ! docker info >/dev/null 2>&1; then
  echo "P11B_BOOTSTRAP_BLOCKED: docker daemon unreachable" >&2
  exit 21
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) kind_arch=amd64; kubectl_arch=amd64 ;;
  aarch64|arm64) kind_arch=arm64; kubectl_arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 22 ;;
esac

if ! need kind; then
  curl -fsSLo "$BIN_DIR/kind" "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${kind_arch}"
  chmod +x "$BIN_DIR/kind"
fi
if ! need kubectl; then
  curl -fsSLo "$BIN_DIR/kubectl" "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${kubectl_arch}/kubectl"
  chmod +x "$BIN_DIR/kubectl"
fi

cat > /tmp/p11b-kind.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: false
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        audit-log-path: /var/log/kubernetes/audit.log
        audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml
      extraVolumes:
      - name: audit-policies
        hostPath: /etc/kubernetes/policies
        mountPath: /etc/kubernetes/policies
        readOnly: true
        pathType: DirectoryOrCreate
      - name: audit-logs
        hostPath: /var/log/kubernetes
        mountPath: /var/log/kubernetes
        readOnly: false
        pathType: DirectoryOrCreate
  extraMounts:
  - hostPath: /tmp/p11b-audit
    containerPath: /var/log/kubernetes
  - hostPath: /tmp/p11b-policies
    containerPath: /etc/kubernetes/policies
EOF

mkdir -p /tmp/p11b-audit /tmp/p11b-policies
cat > /tmp/p11b-policies/audit-policy.yaml <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["pods", "secrets", "serviceaccounts"]
- level: RequestResponse
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
- level: Metadata
EOF

if kind get clusters | grep -qx "$CLUSTER_NAME"; then
  kind delete cluster --name "$CLUSTER_NAME"
fi
kind create cluster --name "$CLUSTER_NAME" --config /tmp/p11b-kind.yaml
kubectl cluster-info
kubectl get nodes -o wide
kubectl version

cat <<EOF
P11B_BOOTSTRAP_PASS
cluster=${CLUSTER_NAME}
kubeconfig=${KUBECONFIG:-$HOME/.kube/config}
audit_log=/tmp/p11b-audit/audit.log
EOF
