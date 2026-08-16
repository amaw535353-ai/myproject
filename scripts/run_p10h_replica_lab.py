#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import socket
import sys
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "p10h-local-admin"
TENANT = "acme"
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
os.environ["no_proxy"] = "127.0.0.1,localhost"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_ready(url: str, timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    with httpx.Client(trust_env=False) as client:
        while time.time() < deadline:
            try:
                r = client.get(url + "/health", timeout=0.25)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(0.05)
    raise RuntimeError(f"server did not become ready: {url}")


def _serve(port: int, env_values: dict[str, str]) -> None:
    os.environ.update(env_values)
    os.environ["PYTHONPATH"] = str(ROOT)
    import uvicorn
    from apps.p10h_replica_lab import app
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


def spawn(port: int, env_values: dict[str, str]) -> mp.Process:
    ctx = mp.get_context("fork")
    process = ctx.Process(target=_serve, args=(port, env_values), daemon=True)
    process.start()
    return process


def main() -> int:
    replica_ports = [free_port() for _ in range(3)]
    router_port = free_port()
    replicas = [
        {"id": "replica-lab-a", "generation": 11, "url": f"http://127.0.0.1:{replica_ports[0]}", "active": True},
        {"id": "replica-lab-b", "generation": 12, "url": f"http://127.0.0.1:{replica_ports[1]}", "active": True},
        {"id": "replica-lab-c", "generation": 13, "url": f"http://127.0.0.1:{replica_ports[2]}", "active": False},
    ]
    procs: list[mp.Process] = []
    client = httpx.Client(trust_env=False)
    try:
        for replica, port in zip(replicas, replica_ports):
            p = spawn(
                port,
                {
                    "P10H_ROLE": "replica",
                    "P10H_REPLICA_ID": replica["id"],
                    "P10H_REPLICA_GENERATION": str(replica["generation"]),
                    "P10H_ADMIN_TOKEN": ADMIN,
                    "P10H_TENANT": TENANT,
                },
            )
            procs.append(p)
            wait_ready(replica["url"])

        router_url = f"http://127.0.0.1:{router_port}"
        router = spawn(
            router_port,
            {
                "P10H_ROLE": "router",
                "P10H_ROUTER_ID": "router-lab-01",
                "P10H_ROUTER_GENERATION": "100",
                "P10H_REPLICAS_JSON": json.dumps(replicas, separators=(",", ":")),
                "P10H_MIN_READY": "2",
                "P10H_ADMIN_TOKEN": ADMIN,
                "P10H_TENANT": TENANT,
            },
        )
        procs.append(router)
        wait_ready(router_url)

        wrong = client.post(
            router_url + "/infer",
            json={"request_id": "req-wrong", "payload": "deny"},
            headers={"X-Tenant": "beta", "Idempotency-Key": "key-wrong"},
            timeout=2,
        )
        if wrong.status_code != 403:
            raise AssertionError(f"cross-tenant request was not denied: {wrong.status_code}")

        first = client.post(
            router_url + "/infer",
            json={"request_id": "req-1", "payload": "first"},
            headers={"X-Tenant": TENANT, "Idempotency-Key": "key-1"},
            timeout=2,
        )
        first.raise_for_status()
        first_data = first.json()
        failed_id = first_data["replica_id"]
        failed = next(r for r in replicas if r["id"] == failed_id)

        fail = client.post(
            failed["url"] + "/admin/fail",
            headers={"X-Admin-Token": ADMIN},
            timeout=2,
        )
        fail.raise_for_status()

        second = client.post(
            router_url + "/infer",
            json={"request_id": "req-2", "payload": "after-failure"},
            headers={"X-Tenant": TENANT, "Idempotency-Key": "key-2"},
            timeout=3,
        )
        second.raise_for_status()
        second_data = second.json()
        if second_data["replica_id"] == failed_id:
            raise AssertionError("router reused failed replica")

        state = client.get(
            router_url + "/state",
            headers={"X-Admin-Token": ADMIN},
            timeout=2,
        ).json()
        if failed_id not in state["fenced"]:
            raise AssertionError("failed replica was not fenced")
        if not state["scale_events"]:
            raise AssertionError("replacement replica was not activated")
        if int(state["generation"]) <= 100:
            raise AssertionError("router generation did not advance")
        if any(r["request_id"] == "req-2" and r["replica_id"] == failed_id for r in state["routes"]):
            raise AssertionError("stale replica received a post-failure route")

        replay = client.post(
            router_url + "/infer",
            json={"request_id": "req-2", "payload": "replay"},
            headers={"X-Tenant": TENANT, "Idempotency-Key": "key-2"},
            timeout=2,
        )
        if replay.status_code != 409:
            raise AssertionError(f"idempotency replay was not rejected: {replay.status_code}")

        additional = []
        for i in range(6):
            rr = client.post(
                router_url + "/infer",
                json={"request_id": f"req-extra-{i}", "payload": "load"},
                headers={"X-Tenant": TENANT, "Idempotency-Key": f"key-extra-{i}"},
                timeout=2,
            )
            rr.raise_for_status()
            additional.append(rr.json()["replica_id"])
        if failed_id in additional:
            raise AssertionError("fenced replica re-entered routing")
        if len(set(additional)) < 2:
            raise AssertionError("ready replicas did not both receive traffic")

        final_state = client.get(
            router_url + "/state",
            headers={"X-Admin-Token": ADMIN},
            timeout=2,
        ).json()
        report = {
            "phase": "P10-H",
            "lab": "localhost-multiprocess-replica-failover",
            "cross_tenant_denied": True,
            "failed_replica_id": failed_id,
            "failover_successor_id": second_data["replica_id"],
            "stale_replica_fenced": failed_id in final_state["fenced"],
            "router_generation_before": 100,
            "router_generation_after": final_state["generation"],
            "replacement_scale_event_count": len(final_state["scale_events"]),
            "failover_event_count": len(final_state["failovers"]),
            "post_failover_routes_to_failed": 0,
            "replay_status": replay.status_code,
            "ready_replicas_observed": sorted(set(additional)),
            "process_count": 4,
            "production_orchestrator_validated": False,
            "distributed_consensus_validated": False,
            "cross_zone_failover_validated": False,
            "network_partition_resistance_validated": False,
        }
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
        print(json.dumps(report, sort_keys=True))
        return 0
    finally:
        client.close()
        for p in reversed(procs):
            if p.is_alive():
                p.terminate()
        for p in reversed(procs):
            p.join(timeout=3)
            if p.is_alive():
                p.kill()
                p.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
