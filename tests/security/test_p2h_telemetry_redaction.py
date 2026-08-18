import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from pydantic import ValidationError

from aegis.approvals.models import ApprovalDecision
from aegis.downstream.auth import MCP_ALICE_TOKEN
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.models import ToolCallProposal, ToolName
from aegis.observability.security_events import (
    InMemorySecurityEventSink,
    SecurityTelemetryEvent,
    SecurityTelemetryRecorder,
    TelemetryPseudonymizer,
)
from apps.api.dependencies import get_security_event_sink
from apps.api import dependencies as api_dependencies
from apps.api.main import app


_TEST_KEY = b"p2h-unit-test-key-material-that-is-at-least-32-bytes"
_DYNAMICS_HEADERS = {"X-Aegis-User": "alice@northstar-dynamics.test"}
_APPROVER_HEADERS = {"X-Aegis-User": "carol.approver@northstar-dynamics.test"}
_CANARY = "AEGIS-NORTH-7Q4M"


def _post(base_url: str, path: str, *, headers: dict, json: dict) -> httpx.Response:
    return httpx.post(base_url+path,headers=headers,json=json,timeout=10)


@pytest.fixture
def p2h_http_state(tmp_path, monkeypatch):
    for name, filename in (
        ("AEGISDESK_STATE_DB","state.sqlite3"),
        ("AEGISDESK_EFFECT_DB","synthetic-effects.sqlite3"),
        ("AEGISDESK_MEMORY_DB","memory.sqlite3"),
        ("AEGISDESK_AGENT_CHECKPOINT_DB","agent-checkpoints.sqlite3"),
        ("AEGISDESK_AGENT_CHECKPOINT_ANCHOR_DB","agent-checkpoint-anchor.sqlite3"),
    ):
        monkeypatch.setenv(name,str(tmp_path/filename))
    cached=[value for value in vars(api_dependencies).values() if callable(value) and hasattr(value,"cache_clear")]
    for dependency in cached: dependency.cache_clear()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1",0)); port=probe.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=port,log_level="error",access_log=False))
    thread=threading.Thread(target=server.run,daemon=True); thread.start()
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz",timeout=.5).status_code==200: break
        except httpx.HTTPError: time.sleep(.05)
    else: raise RuntimeError("P2-H loopback test server failed to start")
    yield f"http://127.0.0.1:{port}"
    server.should_exit=True; thread.join(timeout=10)
    assert not thread.is_alive()
    for dependency in cached: dependency.cache_clear()


def _recorder() -> tuple[SecurityTelemetryRecorder, InMemorySecurityEventSink]:
    sink = InMemorySecurityEventSink()
    return (
        SecurityTelemetryRecorder(
            sink=sink,
            pseudonymizer=TelemetryPseudonymizer(
                key=_TEST_KEY,
                key_id="unit-test-v1",
            ),
        ),
        sink,
    )


def test_secure_tool_event_omits_raw_sensitive_values() -> None:
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None
    recorder, sink = _recorder()

    approval_id = "APR-SYNTH-P2H-001"
    proposal = ToolCallProposal(
        name=ToolName.REQUEST_ACCESS,
        arguments={
            "resource": "finance-admin",
            "justification": f"use {MCP_ALICE_TOKEN} with {_CANARY}",
        },
    )
    recorder.record_tool_execution(
        trace_id="a" * 32,
        principal=principal,
        message=f"private prompt {MCP_ALICE_TOKEN} {_CANARY}",
        proposal=proposal,
        result={
            "approval_id": approval_id,
            "action": "request_access",
            "status": "pending",
            "expires_at": "2026-08-12T23:59:00+00:00",
        },
        duration_ms=7,
    )

    event = sink.snapshot()[0]
    rendered = event.model_dump_json()
    assert MCP_ALICE_TOKEN not in rendered
    assert _CANARY not in rendered
    assert approval_id not in rendered
    assert principal.user_id not in rendered
    assert principal.tenant_id not in rendered
    assert event.approval_ref is not None
    assert event.subject_ref.startswith("hmac-sha256:")
    assert event.tenant_ref.startswith("hmac-sha256:")
    assert event.argument_names == ("justification", "resource")
    assert event.result_keys == ("action", "approval_id", "expires_at", "status")


def test_secure_search_event_keeps_document_ids_not_document_text() -> None:
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None
    recorder, sink = _recorder()

    recorder.record_tool_execution(
        trace_id="b" * 32,
        principal=principal,
        message="search: vpn private-note",
        proposal=ToolCallProposal(
            name=ToolName.SEARCH_KNOWLEDGE_BASE,
            arguments={"query": "vpn private-note", "limit": 3},
        ),
        result={
            "results": [
                {
                    "document_id": 101,
                    "title": "Northstar Dynamics VPN Setup",
                    "text": f"Sensitive retrieved text {_CANARY}",
                }
            ]
        },
        duration_ms=2,
    )

    event = sink.snapshot()[0]
    assert event.retrieved_document_ids == (101,)
    rendered = event.model_dump_json()
    assert _CANARY not in rendered
    assert "Sensitive retrieved text" not in rendered
    assert event.result_keys == ("results",)


def test_pseudonymizer_is_keyed_and_deterministic() -> None:
    first = TelemetryPseudonymizer(key=_TEST_KEY, key_id="unit-test-v1")
    second = TelemetryPseudonymizer(
        key=b"different-unit-test-key-material-at-least-32-bytes",
        key_id="unit-test-v2",
    )

    a = first.fingerprint_text("usr_dyn_alice")
    b = first.fingerprint_text("usr_dyn_alice")
    c = second.fingerprint_text("usr_dyn_alice")
    assert a == b
    assert a != c
    assert "usr_dyn_alice" not in a


def test_pseudonymizer_rejects_short_key() -> None:
    with pytest.raises(ValueError):
        TelemetryPseudonymizer(key=b"too-short", key_id="unit-test-v1")


def test_security_event_schema_rejects_extra_raw_field() -> None:
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None
    recorder, sink = _recorder()
    recorder.record_tool_execution(
        trace_id="c" * 32,
        principal=principal,
        message="assets",
        proposal=ToolCallProposal(name=ToolName.GET_MY_ASSETS, arguments={}),
        result={"assets": []},
        duration_ms=1,
    )
    payload = sink.snapshot()[0].model_dump(mode="json")
    payload["raw_prompt"] = "should never be accepted"
    with pytest.raises(ValidationError):
        SecurityTelemetryEvent.model_validate(payload)


def test_default_agent_path_records_redacted_security_event(
    p2h_http_state,
) -> None:
    secret_note = "SYNTH-P2H-HTTP-PRIVATE-7X9Q"
    response = _post(
        p2h_http_state, "/v1/agent/run",
        headers=_DYNAMICS_HEADERS,
        json={"message": f"search: vpn vpn vpn {secret_note}"},
    )
    assert response.status_code == 200
    assert _CANARY in response.text

    events = get_security_event_sink().snapshot()
    assert len(events) == 1
    event = events[0]
    assert event.tool_name is ToolName.SEARCH_KNOWLEDGE_BASE
    assert 101 in event.retrieved_document_ids
    rendered = event.model_dump_json()
    assert secret_note not in rendered
    assert _CANARY not in rendered


def test_approval_decision_event_uses_refs_not_raw_approval_id(
    p2h_http_state,
) -> None:
    create_response = _post(
        p2h_http_state, "/v1/agent/run",
        headers=_DYNAMICS_HEADERS,
        json={"message": "access: finance-admin | Synthetic reporting access"},
    )
    assert create_response.status_code == 200
    approval_id = create_response.json()["approval_id"]

    decide_response = _post(
        p2h_http_state, f"/v1/approvals/{approval_id}/decision",
        headers=_APPROVER_HEADERS,
        json={"decision": ApprovalDecision.APPROVE.value},
    )
    assert decide_response.status_code == 200

    events = get_security_event_sink().snapshot()
    assert len(events) == 2
    decision_event = events[1]
    assert decision_event.event_name == "approval.decision"
    assert decision_event.approval_ref is not None
    assert decision_event.actor_ref is not None
    assert decision_event.decision is ApprovalDecision.APPROVE
    rendered = json.dumps(
        [event.model_dump(mode="json") for event in events],
        sort_keys=True,
    )
    assert approval_id not in rendered
