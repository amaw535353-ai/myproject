from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

ROLE = os.getenv("P10H_ROLE", "replica")
ADMIN_TOKEN = os.getenv("P10H_ADMIN_TOKEN", "p10h-local-admin")
TENANT = os.getenv("P10H_TENANT", "acme")


class InferenceBody(BaseModel):
    request_id: str
    payload: str


replica_state: dict[str, Any] = {
    "replica_id": os.getenv("P10H_REPLICA_ID", "replica-local"),
    "generation": int(os.getenv("P10H_REPLICA_GENERATION", "1")),
    "healthy": True,
    "accepting": True,
    "requests": 0,
}

router_state: dict[str, Any] = {
    "router_id": os.getenv("P10H_ROUTER_ID", "router-local"),
    "generation": int(os.getenv("P10H_ROUTER_GENERATION", "100")),
    "replicas": json.loads(os.getenv("P10H_REPLICAS_JSON", "[]")),
    "min_ready": int(os.getenv("P10H_MIN_READY", "2")),
    "fenced": [],
    "seen_keys": [],
    "routes": [],
    "scale_events": [],
    "failovers": [],
    "cursor": 0,
}

app = FastAPI(title="AegisDesk P10-H local replica lab")


def _admin_ok(token: str | None) -> None:
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin authorization required")


@app.get("/health")
async def health():
    if ROLE == "router":
        return {"role": "router", "router_id": router_state["router_id"], "generation": router_state["generation"]}
    return {
        "role": "replica",
        "replica_id": replica_state["replica_id"],
        "generation": replica_state["generation"],
        "healthy": replica_state["healthy"],
        "accepting": replica_state["accepting"],
    }


@app.post("/admin/fail")
async def fail_replica(x_admin_token: str | None = Header(default=None)):
    if ROLE != "replica":
        raise HTTPException(status_code=404)
    _admin_ok(x_admin_token)
    replica_state["healthy"] = False
    replica_state["accepting"] = False
    return {"failed": replica_state["replica_id"], "generation": replica_state["generation"]}


@app.post("/infer")
async def infer(
    body: InferenceBody,
    x_tenant: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    if x_tenant != TENANT:
        raise HTTPException(status_code=403, detail="tenant mismatch")
    if ROLE == "replica":
        if not replica_state["healthy"] or not replica_state["accepting"]:
            raise HTTPException(status_code=503, detail="replica unavailable")
        replica_state["requests"] += 1
        await asyncio.sleep(0.01)
        return {
            "request_id": body.request_id,
            "replica_id": replica_state["replica_id"],
            "replica_generation": replica_state["generation"],
            "payload": body.payload,
        }
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="idempotency key required")
    if idempotency_key in router_state["seen_keys"]:
        raise HTTPException(status_code=409, detail="request replay")
    return await _route_request(body, idempotency_key)


async def _probe(client: httpx.AsyncClient, replica: dict[str, Any]) -> bool:
    try:
        response = await client.get(replica["url"] + "/health", timeout=0.5)
        data = response.json()
        return (
            response.status_code == 200
            and data.get("healthy") is True
            and data.get("accepting") is True
            and int(data.get("generation", -1)) == int(replica["generation"])
        )
    except Exception:
        return False


def _fence(replica_id: str, *, reason: str) -> None:
    if replica_id not in router_state["fenced"]:
        router_state["fenced"].append(replica_id)
        router_state["generation"] += 1
        router_state["failovers"].append(
            {
                "failed_replica_id": replica_id,
                "reason": reason,
                "new_router_generation": router_state["generation"],
            }
        )


async def _ensure_min_ready(client: httpx.AsyncClient) -> None:
    active = [r for r in router_state["replicas"] if r.get("active") and r["id"] not in router_state["fenced"]]
    ready = [r for r in active if await _probe(client, r)]
    if len(ready) >= router_state["min_ready"]:
        return
    for candidate in router_state["replicas"]:
        if candidate.get("active") or candidate["id"] in router_state["fenced"]:
            continue
        candidate["active"] = True
        router_state["generation"] += 1
        router_state["scale_events"].append(
            {
                "replica_id": candidate["id"],
                "reason": "ready_capacity_below_floor",
                "new_router_generation": router_state["generation"],
            }
        )
        ready.append(candidate)
        if len(ready) >= router_state["min_ready"]:
            break


async def _route_request(body: InferenceBody, key: str):
    async with httpx.AsyncClient(trust_env=False) as client:
        for replica in [r for r in router_state["replicas"] if r.get("active")]:
            if replica["id"] in router_state["fenced"]:
                continue
            if not await _probe(client, replica):
                _fence(replica["id"], reason="health_probe_failed")
        await _ensure_min_ready(client)
        candidates = [
            r
            for r in router_state["replicas"]
            if r.get("active") and r["id"] not in router_state["fenced"] and await _probe(client, r)
        ]
        if not candidates:
            raise HTTPException(status_code=503, detail="no ready replica")
        start = router_state["cursor"] % len(candidates)
        ordered = candidates[start:] + candidates[:start]
        last_error = None
        for replica in ordered:
            try:
                response = await client.post(
                    replica["url"] + "/infer",
                    json=body.model_dump(),
                    headers={"X-Tenant": TENANT},
                    timeout=1.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    router_state["cursor"] += 1
                    router_state["seen_keys"].append(key)
                    route = {
                        "request_id": body.request_id,
                        "idempotency_key": key,
                        "replica_id": replica["id"],
                        "replica_generation": replica["generation"],
                        "router_generation": router_state["generation"],
                    }
                    router_state["routes"].append(route)
                    return {**data, "router_generation": router_state["generation"]}
                last_error = f"status={response.status_code}"
                _fence(replica["id"], reason="forward_failed")
            except Exception as exc:
                last_error = type(exc).__name__
                _fence(replica["id"], reason="transport_failed")
        raise HTTPException(status_code=503, detail=f"all replicas failed: {last_error}")


@app.get("/state")
async def state(x_admin_token: str | None = Header(default=None)):
    if ROLE != "router":
        raise HTTPException(status_code=404)
    _admin_ok(x_admin_token)
    return router_state
