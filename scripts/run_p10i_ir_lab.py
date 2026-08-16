#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
LAB_TOKEN = "p10i-authorized-lab"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_replica(replica_id: str, generation: int, port: int) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "apps.p10i_ir_lab", "replica", "--port", str(port), "--replica-id", replica_id, "--generation", str(generation)],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_router(port: int, initial: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "apps.p10i_ir_lab", "router", "--port", str(port), "--initial", initial],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_ready(url: str, *, router: bool = False) -> None:
    headers = {"x-lab-control": LAB_TOKEN} if router else {}
    path = "/lab/status" if router else "/health"
    deadline = time.time() + 8
    last = None
    while time.time() < deadline:
        try:
            r = httpx.get(url + path, headers=headers, timeout=0.5)
            if r.status_code == 200:
                return
            last = f"{r.status_code} {r.text}"
        except Exception as exc:
            last = repr(exc)
        time.sleep(0.08)
    raise RuntimeError(f"server not ready: {url}: {last}")


def canonical_hash(value) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(body).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the P10-I local incident-response compromise/recovery lab")
    parser.add_argument("--output", default="/tmp/p10i-ir-report.json")
    args = parser.parse_args()

    ports = [free_port() for _ in range(4)]
    a_url, b_url, c_url, router_url = [f"http://127.0.0.1:{p}" for p in ports]
    procs: list[subprocess.Popen] = []
    try:
        a = start_replica("replica-ir-a", 10, ports[0]); procs.append(a)
        b = start_replica("replica-ir-b", 10, ports[1]); procs.append(b)
        wait_ready(a_url); wait_ready(b_url)
        initial = f"replica-ir-a|{a_url}|10,replica-ir-b|{b_url}|10"
        router = start_router(ports[3], initial); procs.append(router)
        wait_ready(router_url, router=True)
        headers = {"x-lab-control": LAB_TOKEN}

        safe1 = httpx.post(router_url + "/infer", json={"tenant_id": "acme", "idempotency_key": "safe-1"}, timeout=2)
        safe1.raise_for_status()
        first_replica = safe1.json()["replica_id"]
        if first_replica != "replica-ir-a":
            raise RuntimeError(f"expected first route to replica-ir-a, got {first_replica}")

        compromise = httpx.post(a_url + "/lab/compromise", headers=headers, timeout=1)
        compromise.raise_for_status()
        scan = httpx.post(router_url + "/lab/scan", headers=headers, timeout=2)
        scan.raise_for_status()
        if "replica-ir-a" not in scan.json()["fenced"]:
            raise RuntimeError("integrity scan did not fence compromised replica")

        safe2 = httpx.post(router_url + "/infer", json={"tenant_id": "acme", "idempotency_key": "safe-2"}, timeout=2)
        safe2.raise_for_status()
        failover_replica = safe2.json()["replica_id"]
        if failover_replica != "replica-ir-b":
            raise RuntimeError(f"expected failover to replica-ir-b, got {failover_replica}")

        replay = httpx.post(router_url + "/infer", json={"tenant_id": "acme", "idempotency_key": "safe-2"}, timeout=2)
        wrong_tenant = httpx.post(router_url + "/infer", json={"tenant_id": "beta", "idempotency_key": "cross-tenant"}, timeout=2)

        c = start_replica("replica-ir-c", 11, ports[2]); procs.append(c)
        wait_ready(c_url)
        registered = httpx.post(router_url + "/lab/register", headers=headers, json={"replica_id": "replica-ir-c", "endpoint": c_url, "generation": 11}, timeout=2)
        registered.raise_for_status()

        distribution = []
        for i in range(6):
            r = httpx.post(router_url + "/infer", json={"tenant_id": "acme", "idempotency_key": f"post-{i}"}, timeout=2)
            r.raise_for_status()
            distribution.append(r.json()["replica_id"])

        status = httpx.get(router_url + "/lab/status", headers=headers, timeout=2).json()
        kinds = [e["kind"] for e in status["events"]]
        required_events = {
            "integrity_failure_detected",
            "replica_fenced",
            "idempotency_replay_detected",
            "cross_tenant_request_denied",
            "clean_replacement_registered",
        }
        checks = {
            "wrong_tenant_denied": wrong_tenant.status_code == 403,
            "replay_denied": replay.status_code == 409,
            "compromise_detected": "integrity_failure_detected" in kinds,
            "compromised_replica_fenced": "replica-ir-a" in status["fenced"],
            "failover_to_clean_replica": failover_replica == "replica-ir-b",
            "replacement_registered": "replica-ir-c" in status["replicas"],
            "router_generation_advanced": status["router_generation"] >= 202,
            "no_post_compromise_routes_to_fenced": "replica-ir-a" not in distribution,
            "survivors_receive_traffic": {"replica-ir-b", "replica-ir-c"}.issubset(set(distribution)),
            "required_ir_events_present": required_events.issubset(kinds),
        }
        report = {
            "lab": "p10i-local-incident-response",
            "processes": 4,
            "first_replica": first_replica,
            "failover_replica": failover_replica,
            "post_recovery_distribution": distribution,
            "router_generation": status["router_generation"],
            "fenced": status["fenced"],
            "event_kinds": kinds,
            "checks": checks,
            "claim_boundary": {
                "production_soc_integrated": False,
                "production_siem_integrated": False,
                "cross_zone_recovery_validated": False,
                "production_orchestrator_remediation_validated": False,
                "live_gpu_hardware_validated": False,
                "professional_mastery_complete": False,
            },
        }
        report["report_sha256"] = canonical_hash(report)
        Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, sort_keys=True))
        return 0 if all(checks.values()) else 1
    finally:
        for p in reversed(procs):
            p.terminate()
        for p in reversed(procs):
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    raise SystemExit(main())
