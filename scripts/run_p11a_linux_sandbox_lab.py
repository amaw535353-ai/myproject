from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
TENANT_A_UID = 20001
TENANT_B_UID = 20002


def _reexec_as_root_if_possible() -> None:
    if os.geteuid() == 0:
        return
    sudo = shutil.which("sudo")
    if sudo and subprocess.run([sudo, "-n", "true"], capture_output=True).returncode == 0:
        os.execvp(sudo, [sudo, "-n", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    raise SystemExit("P11-A Linux sandbox mastery lab requires root or passwordless sudo")


def _sandbox_prefix(uid: int) -> list[str]:
    return [
        "setpriv",
        "--reuid", str(uid),
        "--regid", str(uid),
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
    ]


def _probe(uid: int, *args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = _sandbox_prefix(uid) + [sys.executable, "-m", "apps.p11a_linux_sandbox_lab", *args]
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=check)


def _json_stdout(proc: subprocess.CompletedProcess[str]) -> dict:
    text = proc.stdout.strip().splitlines()
    return json.loads(text[-1]) if text else {}


def _stable_report_sha(report: dict) -> str:
    payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="P11-A real Linux least-privilege workload isolation lab")
    parser.add_argument("--output")
    args = parser.parse_args()
    _reexec_as_root_if_possible()
    if not shutil.which("setpriv"):
        raise SystemExit("setpriv is required for the P11-A Linux sandbox lab")

    checks: dict[str, bool] = {}
    evidence: dict[str, object] = {}
    target = None

    with tempfile.TemporaryDirectory(prefix="p11a-linux-") as raw:
        lab = Path(raw)
        os.chmod(lab, 0o711)

        identity_proc = _probe(TENANT_A_UID, "identity", check=True)
        identity = _json_stdout(identity_proc)
        checks["non_root_identity"] = identity.get("uid") == TENANT_A_UID and identity.get("gid") == TENANT_A_UID
        checks["no_new_privs"] = identity.get("no_new_privs") is True
        checks["effective_capabilities_dropped"] = identity.get("cap_eff") == "0000000000000000"
        checks["bounding_capabilities_dropped"] = identity.get("cap_bnd") == "0000000000000000"
        evidence["sandbox_uid"] = identity.get("uid")
        evidence["cap_eff"] = identity.get("cap_eff")
        evidence["cap_bnd"] = identity.get("cap_bnd")

        secret = lab / "tenant-a-secret"
        secret.write_text("acme-secret-material\n")
        os.chown(secret, TENANT_A_UID, TENANT_A_UID)
        os.chmod(secret, 0o400)
        owner_read = _probe(TENANT_A_UID, "read-file", str(secret))
        foreign_read = _probe(TENANT_B_UID, "read-file", str(secret))
        checks["secret_owner_can_read"] = owner_read.returncode == 0 and _json_stdout(owner_read).get("read") is True
        checks["cross_tenant_secret_read_denied"] = foreign_read.returncode != 0 and _json_stdout(foreign_read).get("read") is False

        rootfs = lab / "rootfs"
        rootfs.mkdir(mode=0o555)
        os.chown(rootfs, 0, 0)
        root_write = _probe(TENANT_A_UID, "write-file", str(rootfs / "blocked"))
        writable = lab / "writable"
        writable.mkdir(mode=0o700)
        os.chown(writable, TENANT_A_UID, TENANT_A_UID)
        tmp_write = _probe(TENANT_A_UID, "write-file", str(writable / "ok"))
        checks["readonly_root_area_enforced"] = root_write.returncode != 0 and _json_stdout(root_write).get("write") is False
        checks["scoped_writable_area_available"] = tmp_write.returncode == 0 and _json_stdout(tmp_write).get("write") is True

        raw_socket = _probe(TENANT_A_UID, "raw-socket")
        setuid_root = _probe(TENANT_A_UID, "setuid-root")
        checks["raw_socket_capability_denied"] = raw_socket.returncode == 0 and _json_stdout(raw_socket).get("raw_socket_denied") is True
        checks["setuid_root_denied"] = setuid_root.returncode == 0 and _json_stdout(setuid_root).get("setuid_root_denied") is True

        target_env = {**os.environ, "P11A_TENANT_SECRET": "beta-only"}
        target = subprocess.Popen(
            _sandbox_prefix(TENANT_B_UID) + ["sleep", "30"],
            cwd=ROOT,
            env=target_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.1)
        signal = _probe(TENANT_A_UID, "signal", str(target.pid))
        proc_read = _probe(TENANT_A_UID, "read-proc-environ", str(target.pid))
        checks["cross_tenant_signal_denied"] = signal.returncode == 0 and _json_stdout(signal).get("cross_tenant_signal_denied") is True
        checks["cross_tenant_proc_environ_denied"] = proc_read.returncode == 0 and _json_stdout(proc_read).get("cross_tenant_proc_environ_denied") is True

        ipc_dir = lab / "ipc"
        ipc_dir.mkdir(mode=0o700)
        os.chown(ipc_dir, TENANT_A_UID, TENANT_A_UID)
        sock_path = str(ipc_dir / "service.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        os.chown(sock_path, TENANT_A_UID, TENANT_A_UID)
        os.chmod(sock_path, 0o600)
        server.listen(2)
        accepted = []

        def accept_one():
            try:
                conn, _ = server.accept()
                accepted.append(conn.recv(16))
                conn.close()
            finally:
                server.close()

        thread = threading.Thread(target=accept_one, daemon=True)
        thread.start()
        owner_connect = _probe(TENANT_A_UID, "unix-connect", sock_path)
        foreign_connect = _probe(TENANT_B_UID, "unix-connect", sock_path)
        thread.join(timeout=2)
        checks["owner_ipc_connect_allowed"] = owner_connect.returncode == 0 and bool(accepted)
        checks["cross_tenant_ipc_connect_denied"] = foreign_connect.returncode != 0

        userns = subprocess.run(["unshare", "--user", "--map-root-user", "true"], capture_output=True).returncode == 0 if shutil.which("unshare") else False
        checks["kernel_user_namespace_available"] = userns
        evidence["cgroup_v2_observed"] = Path("/sys/fs/cgroup/cgroup.controllers").exists()
        evidence["live_kubernetes_cluster_validated"] = False
        evidence["production_cni_enforcement_validated"] = False
        evidence["container_escape_resistance_validated"] = False
        evidence["network_namespace_isolation_validated"] = False

    if target is not None and target.poll() is None:
        target.terminate()
        try:
            target.wait(timeout=2)
        except subprocess.TimeoutExpired:
            target.kill()
            target.wait(timeout=2)

    passed = all(checks.values())
    report = {
        "lab": "p11a-linux-workload-isolation",
        "status": "pass" if passed else "fail",
        "checks": checks,
        "evidence": evidence,
        "professional_mastery_scope": "local-linux-process-and-filesystem-isolation",
        "live_kubernetes_cluster_validated": False,
        "production_validation_claimed": False,
    }
    report["report_sha256"] = _stable_report_sha(report)
    text = json.dumps(report, sort_keys=True)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
