from __future__ import annotations

import asyncio
import os
import ssl

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from aegis.platform.serving_security import DrainState, ServingDenied

app = FastAPI(title="AegisDesk P11-D mTLS backend")
state = DrainState()
ADMIN_TOKEN = os.environ.get("P11D_DRAIN_TOKEN", "local-drain-capability")


class Infer(BaseModel):
    request_id: str
    tenant: str
    prompt: str
    delay_ms: int = 0


@app.get("/healthz")
async def healthz():
    if not state.healthy: raise HTTPException(503, "unhealthy")
    return {"healthy": True}


@app.get("/readyz")
async def readyz():
    if not state.ready: raise HTTPException(503, "not ready")
    return {"ready": True}


@app.post("/v1/infer")
async def infer(body: Infer, x_aegis_internal_principal: str | None = Header(default=None)):
    if x_aegis_internal_principal != "client-acme": raise HTTPException(403, "identity denied")
    try: state.enter()
    except ServingDenied: raise HTTPException(503, "backend unavailable") from None
    try:
        await asyncio.sleep(min(max(body.delay_ms, 0), 3000) / 1000)
        return {"request_id": body.request_id, "tenant": body.tenant, "output": "synthetic-ok"}
    finally: state.leave()


@app.post("/internal/drain")
async def drain(x_drain_token: str | None = Header(default=None)):
    if x_drain_token != ADMIN_TOKEN: raise HTTPException(403, "denied")
    before = state.in_flight; state.drain()
    return {"draining": True, "in_flight": before}


@app.get("/internal/state")
async def internal_state(x_drain_token: str | None = Header(default=None)):
    if x_drain_token != ADMIN_TOKEN: raise HTTPException(403, "denied")
    return {"healthy": state.healthy, "ready": state.ready, "draining": state.draining, "in_flight": state.in_flight}


async def _proxy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    ssl_object = writer.get_extra_info("ssl_object")
    cert = ssl_object.getpeercert() if ssl_object else {}
    identities = {value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"}
    if "gateway.p11d.internal" not in identities:
        writer.close(); await writer.wait_closed(); return
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", 8081)
        async def copy(source, target):
            try:
                while data := await source.read(65536):
                    target.write(data); await target.drain()
            finally:
                target.close()
        await asyncio.gather(copy(reader, upstream_writer), copy(upstream_reader, writer))
    except (ConnectionError, asyncio.CancelledError):
        writer.close()


async def _serve() -> None:
    import uvicorn
    config = uvicorn.Config(app, host="127.0.0.1", port=8081, log_level="warning", proxy_headers=False)
    server = uvicorn.Server(config)
    app_task = asyncio.create_task(server.serve())
    while not server.started: await asyncio.sleep(0.05)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("/pki/tls.crt", "/pki/tls.key")
    context.load_verify_locations("/pki/ca.crt"); context.verify_mode = ssl.CERT_REQUIRED
    tls_server = await asyncio.start_server(_proxy, "0.0.0.0", 8443, ssl=context)
    async with tls_server: await tls_server.serve_forever()
    await app_task


if __name__ == "__main__": asyncio.run(_serve())
