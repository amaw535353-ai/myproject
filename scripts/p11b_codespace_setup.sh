#!/usr/bin/env bash
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
REPORT_DIR="$ROOT/artifacts/p11b"
mkdir -p "$REPORT_DIR"
PROBE="$REPORT_DIR/codespace-probe.txt"
BOOTSTRAP="$REPORT_DIR/bootstrap.txt"
SUMMARY="$REPORT_DIR/setup-summary.txt"

{
  echo "P11B_CODESPACE_SETUP_START"
  date -u +"utc=%Y-%m-%dT%H:%M:%SZ"
  echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
} | tee "$SUMMARY"

chmod +x "$ROOT/scripts/p11b_probe_codespace.sh" "$ROOT/scripts/p11b_bootstrap_kind.sh" 2>/dev/null || true

if "$ROOT/scripts/p11b_probe_codespace.sh" >"$PROBE" 2>&1; then
  echo "probe=pass" | tee -a "$SUMMARY"
else
  rc=$?
  echo "probe=fail rc=$rc" | tee -a "$SUMMARY"
fi

# Docker-in-Docker may need a short startup delay in a fresh Codespace.
for i in $(seq 1 30); do
  if docker info >/dev/null 2>&1; then
    echo "docker_ready_after_seconds=$((i-1))" | tee -a "$SUMMARY"
    break
  fi
  sleep 1
done

if "$ROOT/scripts/p11b_bootstrap_kind.sh" >"$BOOTSTRAP" 2>&1; then
  echo "bootstrap=pass" | tee -a "$SUMMARY"
  kubectl get nodes -o wide >>"$BOOTSTRAP" 2>&1 || true
  kubectl get pods -A >>"$BOOTSTRAP" 2>&1 || true
else
  rc=$?
  echo "bootstrap=blocked_or_failed rc=$rc" | tee -a "$SUMMARY"
fi

if command -v kubectl >/dev/null 2>&1 && kubectl get nodes >/dev/null 2>&1; then
  echo "live_kubernetes_api=reachable" | tee -a "$SUMMARY"
else
  echo "live_kubernetes_api=unavailable" | tee -a "$SUMMARY"
fi

if kubectl -n kube-system get daemonset calico-node >/dev/null 2>&1; then
  echo "network_policy_runtime=calico" | tee -a "$SUMMARY"
else
  echo "network_policy_runtime=unverified" | tee -a "$SUMMARY"
fi

echo "P11B_CODESPACE_SETUP_END" | tee -a "$SUMMARY"
printf '\nP11-B setup evidence written to %s\n' "$REPORT_DIR"

# Deliberately return success so an environmental limitation does not brick the Codespace.
exit 0
