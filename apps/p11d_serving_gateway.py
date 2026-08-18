from __future__ import annotations

import json
import os
import ssl

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from aegis.platform.serving_security import FixedWindowLimiter, RequestContext, RequestPolicy, ServingDenied

app = FastAPI(title="AegisDesk P11-D hardened gateway")
policy = RequestPolicy(); limiter = FixedWindowLimiter(limit=3, window=2, concurrency=2)
BACKEND = os.environ.get("P11D_BACKEND", "https://backend.p11d.svc.cluster.local:8443")
CA = "/pki/ca.crt"; CERT = ("/pki/tls.crt", "/pki/tls.key")
SECURITY_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


@app.middleware("http")
async def headers(request: Request, call_next):
    try: response = await call_next(request)
    except Exception: response = JSONResponse({"detail": "serving request failed"}, status_code=502)
    response.headers.update(SECURITY_HEADERS)
    return response


@app.get("/healthz")
async def healthz(): return {"healthy": True}


@app.get("/readyz")
async def readyz(): return {"ready": True}


@app.post("/v1/infer")
async def infer(request: Request, x_client_id: str | None = Header(default=None)):
    if x_client_id != "client-acme": raise HTTPException(401, "identity required")
    raw = await request.body()
    try:
        body = json.loads(raw)
        context = RequestContext("client-acme", "acme", body.get("request_id", ""))
        policy.validate(method=request.method, route=request.url.path,
                        content_type=request.headers.get("content-type", ""), body=raw,
                        headers=dict(request.headers), claimed_tenant=body.get("tenant", ""), context=context)
        limiter.acquire(context.principal)
    except json.JSONDecodeError: raise HTTPException(400, "malformed request") from None
    except ServingDenied as exc:
        code = 413 if str(exc) == "BODY_TOO_LARGE" else 429 if "LIMITED" in str(exc) else 403
        raise HTTPException(code, "request denied") from None
    try:
        tls = ssl.create_default_context(cafile=CA); tls.load_cert_chain(*CERT)
        async with httpx.AsyncClient(verify=tls, trust_env=False, timeout=5) as client:
            response = await client.post(BACKEND + "/v1/infer", json=body,
                                         headers={"X-Aegis-Internal-Principal": context.principal})
        if response.status_code != 200: raise HTTPException(503, "backend unavailable")
        return response.json()
    except httpx.HTTPError as exc:
        print(f"backend transport denied: {type(exc).__name__}: {exc}", flush=True)
        raise HTTPException(502, "backend unavailable") from None
    finally: limiter.release(context.principal)
