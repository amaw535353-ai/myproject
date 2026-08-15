from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse

from aegis.inference.streaming_security_types import StreamFrameKind, canonical_json_text, encode_sse_event

APP_TITLE = "AegisDesk P10-G Streaming Mastery Lab"
STREAM_ID = "stream-acme-lab-0001"
TENANT_ID = "acme"
SESSION_ID = "tenant/acme/session/lab-001"
QUEUE_LIMIT = 2


@dataclass
class LabStreamState:
    started: bool = False
    cancelled: asyncio.Event = field(default_factory=asyncio.Event)
    producer_pause_count: int = 0
    max_queue_depth: int = 0
    emitted_frames: int = 0
    terminal_kind: str = ""
    queue_drained: bool = False


app = FastAPI(title=APP_TITLE)
_state = LabStreamState()
_state_lock = asyncio.Lock()


def _authorize(tenant: str | None, session: str | None) -> None:
    if tenant != TENANT_ID or session != SESSION_ID:
        raise HTTPException(status_code=403, detail="tenant/session route mismatch")


def _plan() -> tuple[tuple[StreamFrameKind, str], ...]:
    injected_text = "safe payload\n\nevent: injected\ndata: pwn"
    tool = canonical_json_text(
        {"tool": "lookup_ticket", "arguments": {"ticket_id": "INC-1042"}}
    )
    return (
        (StreamFrameKind.TOKEN, injected_text),
        (StreamFrameKind.TOKEN, "status: open"),
        (StreamFrameKind.TOOL_CALL, tool),
        (StreamFrameKind.FINAL, canonical_json_text({"status": "complete"})),
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "lab": "p10g"}


@app.post("/lab/reset")
async def reset_lab():
    global _state
    async with _state_lock:
        _state = LabStreamState()
    return {"reset": True, "stream_id": STREAM_ID}


@app.get("/v1/stream/{stream_id}")
async def stream_output(
    stream_id: str,
    x_tenant_id: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
):
    global _state
    _authorize(x_tenant_id, x_session_id)
    if stream_id != STREAM_ID:
        raise HTTPException(status_code=404, detail="unknown stream")
    async with _state_lock:
        if _state.started:
            raise HTTPException(status_code=409, detail="stream replay denied")
        _state.started = True
        state = _state

    queue: asyncio.Queue[tuple[StreamFrameKind, str] | None] = asyncio.Queue(
        maxsize=QUEUE_LIMIT
    )

    async def producer() -> None:
        for item in _plan():
            if queue.full():
                state.producer_pause_count += 1
            await queue.put(item)
            state.max_queue_depth = max(state.max_queue_depth, queue.qsize())
        if queue.full():
            state.producer_pause_count += 1
        await queue.put(None)
        state.max_queue_depth = max(state.max_queue_depth, queue.qsize())

    async def body():
        producer_task = asyncio.create_task(producer())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    state.queue_drained = True
                    break
                if state.cancelled.is_set():
                    cancelled_payload = canonical_json_text({"reason": "client_cancelled"})
                    yield encode_sse_event(StreamFrameKind.CANCELLED, cancelled_payload)
                    state.emitted_frames += 1
                    state.terminal_kind = StreamFrameKind.CANCELLED.value
                    while True:
                        try:
                            queued = queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        if queued is None:
                            break
                    state.queue_drained = True
                    producer_task.cancel()
                    try:
                        await producer_task
                    except asyncio.CancelledError:
                        pass
                    return
                kind, payload = item
                yield encode_sse_event(kind, payload)
                state.emitted_frames += 1
                if kind in (StreamFrameKind.CANCELLED, StreamFrameKind.FINAL):
                    state.terminal_kind = kind.value
                await asyncio.sleep(0.20)
            await producer_task
        finally:
            if not producer_task.done():
                producer_task.cancel()

    return StreamingResponse(
        body(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Aegis-Stream-ID": stream_id,
        },
    )


@app.post("/v1/stream/{stream_id}/cancel")
async def cancel_stream(
    stream_id: str,
    x_tenant_id: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
):
    global _state
    _authorize(x_tenant_id, x_session_id)
    if stream_id != STREAM_ID:
        raise HTTPException(status_code=404, detail="unknown stream")
    if not _state.started:
        raise HTTPException(status_code=409, detail="stream has not started")
    _state.cancelled.set()
    return {"cancelled": True, "stream_id": stream_id}


@app.get("/v1/stream/{stream_id}/metrics")
async def stream_metrics(
    stream_id: str,
    x_tenant_id: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
):
    global _state
    _authorize(x_tenant_id, x_session_id)
    if stream_id != STREAM_ID:
        raise HTTPException(status_code=404, detail="unknown stream")
    return JSONResponse(
        {
            "stream_id": stream_id,
            "producer_pause_count": _state.producer_pause_count,
            "max_queue_depth": _state.max_queue_depth,
            "queue_limit": QUEUE_LIMIT,
            "emitted_frames": _state.emitted_frames,
            "terminal_kind": _state.terminal_kind,
            "cancelled": _state.cancelled.is_set(),
            "queue_drained": _state.queue_drained,
        }
    )
