from __future__ import annotations

import argparse
import asyncio
from collections import OrderedDict
from dataclasses import dataclass, field
import time
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
import uvicorn

LAB_TOKEN = "p10i-authorized-lab"
TENANT = "acme"


def _require_lab(token: str | None) -> None:
    if token != LAB_TOKEN:
        raise HTTPException(status_code=403, detail="lab control denied")


def replica_app(replica_id: str, generation: int) -> FastAPI:
    app = FastAPI()
    state = {"compromised": False, "requests": 0}

    @app.get("/health")
    async def health():
        return {
            "replica_id": replica_id,
            "generation": generation,
            "healthy": True,
            "integrity_ok": not state["compromised"],
            "requests": state["requests"],
        }

    @app.post("/infer")
    async def infer(payload: dict[str, Any]):
        if payload.get("tenant_id") != TENANT:
            raise HTTPException(status_code=403, detail="tenant denied")
        state["requests"] += 1
        return {
            "replica_id": replica_id,
            "generation": generation,
            "integrity_ok": not state["compromised"],
            "model_revision": "tampered-revision" if state["compromised"] else "rev-2026-08-p9h",
            "answer": "ticket-status-ok" if not state["compromised"] else "tainted-output",
        }

    @app.post("/lab/compromise")
    async def compromise(x_lab_control: str | None = Header(default=None)):
        _require_lab(x_lab_control)
        state["compromised"] = True
        return {"replica_id": replica_id, "compromised": True}

    return app


@dataclass
class RouterState:
    endpoints: OrderedDict[str, str]
    generations: dict[str, int]
    fenced: set[str] = field(default_factory=set)
    router_generation: int = 200
    idempotency: set[str] = field(default_factory=set)
    events: list[dict[str, Any]] = field(default_factory=list)
    rr_index: int = 0

    def emit(self, kind: str, **data: Any) -> None:
        self.events.append({"sequence": len(self.events) + 1, "kind": kind, "at_ns": time.time_ns(), **data})


def router_app(initial: dict[str, tuple[str, int]]) -> FastAPI:
    app = FastAPI()
    state = RouterState(OrderedDict((rid, endpoint) for rid, (endpoint, _gen) in initial.items()), {rid: gen for rid, (_endpoint, gen) in initial.items()})

    async def probe(client: httpx.AsyncClient, rid: str) -> bool:
        try:
            r = await client.get(state.endpoints[rid] + "/health", timeout=0.7)
            data = r.json()
            if r.status_code != 200 or not data.get("healthy") or not data.get("integrity_ok"):
                state.fenced.add(rid)
                state.router_generation += 1
                state.emit("integrity_failure_detected", replica_id=rid, router_generation=state.router_generation)
                state.emit("replica_fenced", replica_id=rid, router_generation=state.router_generation)
                return False
            return True
        except Exception:
            state.fenced.add(rid)
            state.router_generation += 1
            state.emit("replica_unreachable", replica_id=rid, router_generation=state.router_generation)
            state.emit("replica_fenced", replica_id=rid, router_generation=state.router_generation)
            return False

    async def choose(client: httpx.AsyncClient) -> str:
        ids = list(state.endpoints)
        if not ids:
            raise HTTPException(status_code=503, detail="no replicas")
        for offset in range(len(ids)):
            rid = ids[(state.rr_index + offset) % len(ids)]
            if rid in state.fenced:
                continue
            if await probe(client, rid):
                state.rr_index = (ids.index(rid) + 1) % len(ids)
                return rid
        raise HTTPException(status_code=503, detail="no safe replicas")

    @app.post("/infer")
    async def infer(payload: dict[str, Any]):
        tenant = payload.get("tenant_id")
        key = str(payload.get("idempotency_key", ""))
        if tenant != TENANT:
            state.emit("cross_tenant_request_denied", tenant_id=tenant)
            raise HTTPException(status_code=403, detail="tenant denied")
        if not key:
            raise HTTPException(status_code=400, detail="missing idempotency key")
        if key in state.idempotency:
            state.emit("idempotency_replay_detected", idempotency_key=key)
            raise HTTPException(status_code=409, detail="replay denied")
        state.idempotency.add(key)
        async with httpx.AsyncClient() as client:
            rid = await choose(client)
            r = await client.post(state.endpoints[rid] + "/infer", json=payload, timeout=1.0)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail="replica error")
            data = r.json()
            if not data.get("integrity_ok") or data.get("model_revision") != "rev-2026-08-p9h":
                state.fenced.add(rid)
                state.router_generation += 1
                state.emit("post_route_integrity_failure", replica_id=rid, router_generation=state.router_generation)
                raise HTTPException(status_code=502, detail="integrity failure")
            state.emit("request_routed", replica_id=rid, idempotency_key=key, router_generation=state.router_generation)
            return {**data, "router_generation": state.router_generation}

    @app.post("/lab/scan")
    async def scan(x_lab_control: str | None = Header(default=None)):
        _require_lab(x_lab_control)
        results = {}
        async with httpx.AsyncClient() as client:
            for rid in list(state.endpoints):
                if rid in state.fenced:
                    results[rid] = False
                    continue
                results[rid] = await probe(client, rid)
        return {"results": results, "router_generation": state.router_generation, "fenced": sorted(state.fenced)}

    @app.post("/lab/register")
    async def register(payload: dict[str, Any], x_lab_control: str | None = Header(default=None)):
        _require_lab(x_lab_control)
        rid = str(payload["replica_id"])
        endpoint = str(payload["endpoint"])
        generation = int(payload["generation"])
        state.endpoints[rid] = endpoint
        state.generations[rid] = generation
        state.fenced.discard(rid)
        state.router_generation += 1
        state.emit("clean_replacement_registered", replica_id=rid, generation=generation, router_generation=state.router_generation)
        return {"registered": rid, "router_generation": state.router_generation}

    @app.get("/lab/status")
    async def status(x_lab_control: str | None = Header(default=None)):
        _require_lab(x_lab_control)
        return {
            "router_generation": state.router_generation,
            "replicas": list(state.endpoints),
            "fenced": sorted(state.fenced),
            "events": state.events,
            "idempotency_count": len(state.idempotency),
        }

    return app


def parse_initial(value: str) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    if not value:
        return out
    for item in value.split(","):
        rid, endpoint, generation = item.split("|", 2)
        out[rid] = (endpoint, int(generation))
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("replica", "router"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--replica-id", default="")
    parser.add_argument("--generation", type=int, default=1)
    parser.add_argument("--initial", default="")
    args = parser.parse_args()
    if args.role == "replica":
        app = replica_app(args.replica_id, args.generation)
    else:
        app = router_app(parse_initial(args.initial))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
