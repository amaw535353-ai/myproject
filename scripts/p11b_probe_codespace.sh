#!/usr/bin/env bash
set -euo pipefail

printf 'P11B_PROBE_START\n'
printf 'kernel=%s\n' "$(uname -srmo)"
printf 'uid=%s gid=%s\n' "$(id -u)" "$(id -g)"
printf 'codespaces=%s\n' "${CODESPACES:-false}"
printf 'container=%s\n' "${container:-unknown}"

check_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf 'cmd:%s=present path=%s\n' "$cmd" "$(command -v "$cmd")"
  else
    printf 'cmd:%s=absent\n' "$cmd"
  fi
}

for cmd in docker podman nerdctl containerd ctr kubectl kind k3d k3s helm iptables nft unshare nsenter capsh; do
  check_cmd "$cmd"
done

if command -v docker >/dev/null 2>&1; then
  if docker info >/tmp/p11b-docker-info.txt 2>/tmp/p11b-docker-info.err; then
    printf 'docker_daemon=reachable\n'
    docker info --format 'docker_server={{.ServerVersion}} cgroup_driver={{.CgroupDriver}} cgroup_version={{.CgroupVersion}} rootless={{json .SecurityOptions}}\n' 2>/dev/null || true
  else
    printf 'docker_daemon=unreachable\n'
    sed 's/^/docker_error=/' /tmp/p11b-docker-info.err | head -20
  fi
fi

for f in /proc/self/status /proc/1/cgroup /proc/filesystems; do
  if [[ -r "$f" ]]; then
    printf '%s_begin\n' "$f"
    sed -n '1,120p' "$f"
    printf '%s_end\n' "$f"
  fi
done

if [[ -r /proc/sys/kernel/unprivileged_userns_clone ]]; then
  printf 'unprivileged_userns_clone=%s\n' "$(cat /proc/sys/kernel/unprivileged_userns_clone)"
fi

if command -v unshare >/dev/null 2>&1; then
  if unshare -Ur true >/dev/null 2>&1; then
    printf 'userns_unshare=allowed\n'
  else
    printf 'userns_unshare=blocked\n'
  fi
fi

if command -v iptables >/dev/null 2>&1; then
  iptables --version | sed 's/^/iptables_version=/' || true
fi
if command -v nft >/dev/null 2>&1; then
  nft --version | sed 's/^/nft_version=/' || true
fi

printf 'P11B_PROBE_END\n'
