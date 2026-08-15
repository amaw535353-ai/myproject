#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
STREAM_ID = "stream-acme-lab-0001"
TENANT_ID = "acme"
SESSION_ID = "tenant/acme/session/lab-001"
HEADERS = {"x-tenant-id": TENANT_ID, "x-session-id": SESSION_ID}


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait(base: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            response = httpx.get(base + "/healthz", timeout=0.5)
            if response.status_code == 200:
                return
        except Exception as exc:  # pragma: no cover - diagnostic path
            last = exc
        time.sleep(0.05)
    raise RuntimeError(f"lab server did not start: {last}")


def _parse_events(raw: str) -> list[dict]:
    events = []
    for block in raw.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        lines = block.splitlines()
        event = next((line[7:] for line in lines if line.startswith("event: ")), "")
        data_line = next((line[6:] for line in lines if line.startswith("data: ")), "")
        data = json.loads(data_line)
        events.append({"event": event, "data": data})
    return events


def run_lab(output: Path) -> dict:
    port = _port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "apps.p10g_streaming_lab:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait(base)
        with httpx.Client(base_url=base, timeout=5.0) as client:
            client.post("/lab/reset").raise_for_status()
            wrong = client.get(
                f"/v1/stream/{STREAM_ID}",
                headers={"x-tenant-id": "beta", "x-session-id": "tenant/beta/session/lab-009"},
            )
            cross_tenant_denied = wrong.status_code == 403

            first_event = threading.Event()
            done = threading.Event()
            result: dict[str, object] = {"raw": "", "error": ""}

            def reader() -> None:
                try:
                    chunks: list[str] = []
                    with httpx.Client(base_url=base, timeout=10.0) as stream_client:
                        with stream_client.stream(
                            "GET", f"/v1/stream/{STREAM_ID}", headers=HEADERS
                        ) as response:
                            response.raise_for_status()
                            buffer = ""
                            for text in response.iter_text():
                                chunks.append(text)
                                buffer += text
                                if "\n\n" in buffer and not first_event.is_set():
                                    first_event.set()
                    result["raw"] = "".join(chunks)
                except Exception as exc:  # pragma: no cover - diagnostic path
                    result["error"] = repr(exc)
                finally:
                    done.set()

            thread = threading.Thread(target=reader, daemon=True)
            thread.start()
            if not first_event.wait(timeout=5.0):
                raise RuntimeError("stream did not emit first frame")
            cancel = client.post(f"/v1/stream/{STREAM_ID}/cancel", headers=HEADERS)
            cancel.raise_for_status()
            if not done.wait(timeout=10.0):
                raise RuntimeError("stream did not terminate after cancellation")
            thread.join(timeout=1.0)
            if result["error"]:
                raise RuntimeError(str(result["error"]))
            raw = str(result["raw"])
            events = _parse_events(raw)
            event_names = [item["event"] for item in events]
            cancellation_enforced = bool(event_names) and event_names[-1] == "cancelled" and "final" not in event_names
            framing_injection_contained = "\n\nevent: injected" not in raw and any(
                "event: injected" in item["data"]["payload"] for item in events
            )

            metrics = client.get(f"/v1/stream/{STREAM_ID}/metrics", headers=HEADERS)
            metrics.raise_for_status()
            metric_data = metrics.json()
            backpressure_observed = (
                metric_data["producer_pause_count"] > 0
                and metric_data["max_queue_depth"] <= metric_data["queue_limit"]
                and metric_data["queue_drained"] is True
            )
            replay = client.get(f"/v1/stream/{STREAM_ID}", headers=HEADERS)
            replay_denied = replay.status_code == 409

        report = {
            "schema_version": "aegis-p10g-loopback-streaming-lab-report-v1",
            "loopback_network_exercised": True,
            "cross_tenant_denied": cross_tenant_denied,
            "cancellation_enforced": cancellation_enforced,
            "framing_injection_contained": framing_injection_contained,
            "backpressure_observed": backpressure_observed,
            "replay_denied": replay_denied,
            "event_names": event_names,
            "metrics": metric_data,
            "production_validation_claimed": False,
            "kernel_tcp_backpressure_validated": False,
            "distributed_cancellation_linearizability_validated": False,
        }
        report["report_sha256"] = hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if not all(
            report[name]
            for name in (
                "cross_tenant_denied",
                "cancellation_enforced",
                "framing_injection_contained",
                "backpressure_observed",
                "replay_denied",
            )
        ):
            raise RuntimeError("one or more loopback mastery checks failed")
        return report
    finally:
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the P10-G real loopback streaming-security lab")
    parser.add_argument(
        "--output",
        default="/tmp/p10g-loopback-report.json",
        help="Path for the machine-readable lab report.",
    )
    args = parser.parse_args()
    report = run_lab(Path(args.output))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
