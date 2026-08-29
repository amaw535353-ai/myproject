from __future__ import annotations

import socket
from collections.abc import Mapping
from typing import Any

import pytest

from aegis.targets.onyx.client import AuthorizedOnyxClient, TargetBlockedError
from aegis.targets.onyx.config import OnyxTargetConfig
from aegis.targets.onyx.evidence import (
    CaseEvidence,
    CaseStatus,
    RunStatus,
    calculate_metrics,
    derive_run_status,
    sanitize_evidence,
)
from aegis.targets.onyx.fixtures import DOCUMENTS, USERS, expected_access
from aegis.targets.onyx.safety import TargetGateStatus, validate_authorized_target

ONYX_COMMIT = "test-onyx-commit"
AEGIS_COMMIT = "test-aegis-commit"
LAB_MARKER = "aegis-onyx-o1-lab"


def _resolver(*addresses: str):
    def resolve(host: str, port: int, *, type: int):  # noqa: A002
        del host, type
        answers = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            answers.append((family, socket.SOCK_STREAM, 6, "", (address, port)))
        return answers

    return resolve


class _FakeTransport:
    def __init__(self, marker: str = LAB_MARKER) -> None:
        self.marker = marker
        self.probe_calls = 0
        self.request_calls = 0

    def probe_lab_marker(self, *, base_url: str, timeout_seconds: float) -> str:
        del base_url, timeout_seconds
        self.probe_calls += 1
        return self.marker

    def request_json(
        self,
        *,
        base_url: str,
        method: str,
        path: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any] | None,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        del base_url, method, headers, payload, timeout_seconds
        self.request_calls += 1
        return {"ok": True, "path": path}


def _config(base_url: str = "http://127.0.0.1:3000") -> OnyxTargetConfig:
    return OnyxTargetConfig(
        base_url=base_url,
        expected_lab_marker=LAB_MARKER,
        lab_ack="YES",
    )


def _case(
    case_id: str,
    *,
    attack: bool,
    status: CaseStatus,
    security_effect: str,
) -> CaseEvidence:
    return CaseEvidence(
        case_id=case_id,
        category="rag_auth",
        onyx_commit=ONYX_COMMIT,
        aegis_commit=AEGIS_COMMIT,
        mode="deterministic",
        attack=attack,
        expected="deny" if attack else "allow",
        observed="synthetic observation",
        security_effect=security_effect,
        status=status,
        duration_ms=1,
        evidence={"returned_document_ids": []},
    )


def test_loopback_target_requires_explicit_acknowledgement() -> None:
    config = OnyxTargetConfig(
        base_url="http://127.0.0.1:3000",
        expected_lab_marker=LAB_MARKER,
        lab_ack="",
    )

    result = validate_authorized_target(config, observed_lab_marker=LAB_MARKER)

    assert result.status is TargetGateStatus.BLOCKED
    assert "acknowledgement" in result.reason


def test_loopback_target_requires_matching_lab_marker() -> None:
    result = validate_authorized_target(_config(), observed_lab_marker="wrong-marker")

    assert result.status is TargetGateStatus.BLOCKED
    assert "marker" in result.reason


def test_loopback_target_passes_only_with_ack_and_marker() -> None:
    result = validate_authorized_target(_config(), observed_lab_marker=LAB_MARKER)

    assert result.status is TargetGateStatus.VERIFIED
    assert result.resolved_addresses == ("127.0.0.1",)


def test_localhost_must_resolve_exclusively_to_loopback() -> None:
    safe = validate_authorized_target(
        _config("http://localhost:3000"),
        observed_lab_marker=LAB_MARKER,
        resolver=_resolver("127.0.0.1", "::1"),
    )
    unsafe = validate_authorized_target(
        _config("http://localhost:3000"),
        observed_lab_marker=LAB_MARKER,
        resolver=_resolver("127.0.0.1", "203.0.113.10"),
    )

    assert safe.status is TargetGateStatus.VERIFIED
    assert unsafe.status is TargetGateStatus.BLOCKED


def test_public_target_is_blocked_even_with_ack_and_marker() -> None:
    result = validate_authorized_target(
        _config("https://example.com"),
        observed_lab_marker=LAB_MARKER,
    )

    assert result.status is TargetGateStatus.BLOCKED
    assert "disabled by default" in result.reason


def test_private_hostname_requires_opt_in_allowlist_and_private_resolution() -> None:
    no_opt_in = OnyxTargetConfig(
        base_url="http://onyx.lab.test:3000",
        expected_lab_marker=LAB_MARKER,
        lab_ack="YES",
    )
    not_allowlisted = OnyxTargetConfig(
        base_url="http://onyx.lab.test:3000",
        expected_lab_marker=LAB_MARKER,
        lab_ack="YES",
        allow_private_network_targets=True,
    )
    allowed = OnyxTargetConfig(
        base_url="http://onyx.lab.test:3000",
        expected_lab_marker=LAB_MARKER,
        lab_ack="YES",
        allow_private_network_targets=True,
        approved_lab_hosts=("onyx.lab.test",),
    )

    assert (
        validate_authorized_target(
            no_opt_in,
            observed_lab_marker=LAB_MARKER,
            resolver=_resolver("192.168.56.10"),
        ).status
        is TargetGateStatus.BLOCKED
    )
    assert (
        validate_authorized_target(
            not_allowlisted,
            observed_lab_marker=LAB_MARKER,
            resolver=_resolver("192.168.56.10"),
        ).status
        is TargetGateStatus.BLOCKED
    )
    assert (
        validate_authorized_target(
            allowed,
            observed_lab_marker=LAB_MARKER,
            resolver=_resolver("192.168.56.10"),
        ).status
        is TargetGateStatus.VERIFIED
    )


def test_private_hostname_blocks_mixed_private_and_public_resolution() -> None:
    config = OnyxTargetConfig(
        base_url="http://onyx.lab.test:3000",
        expected_lab_marker=LAB_MARKER,
        lab_ack="YES",
        allow_private_network_targets=True,
        approved_lab_hosts=("onyx.lab.test",),
    )

    result = validate_authorized_target(
        config,
        observed_lab_marker=LAB_MARKER,
        resolver=_resolver("10.10.0.5", "8.8.8.8"),
    )

    assert result.status is TargetGateStatus.BLOCKED
    assert "outside" in result.reason


def test_invalid_target_url_fails_closed() -> None:
    result = validate_authorized_target(
        _config("http://127.0.0.1:not-a-port"),
        observed_lab_marker=LAB_MARKER,
    )

    assert result.status is TargetGateStatus.BLOCKED


def test_client_blocks_before_marker_probe_for_public_target() -> None:
    transport = _FakeTransport()

    with pytest.raises(TargetBlockedError) as exc_info:
        AuthorizedOnyxClient.connect(
            config=_config("https://example.com"),
            transport=transport,
            resolver=_resolver("8.8.8.8"),
        )

    assert exc_info.value.validation.status is TargetGateStatus.BLOCKED
    assert transport.probe_calls == 0
    assert transport.request_calls == 0


def test_client_dispatches_only_after_target_authorization() -> None:
    transport = _FakeTransport()
    client = AuthorizedOnyxClient.connect(
        config=_config(),
        transport=transport,
        resolver=_resolver("127.0.0.1"),
    )

    response = client.request_json(method="get", path="/synthetic-o1-test")

    assert response == {"ok": True, "path": "/synthetic-o1-test"}
    assert transport.probe_calls == 1
    assert transport.request_calls == 1


def test_synthetic_authorization_matrix_is_deterministic() -> None:
    for user_id in USERS:
        assert expected_access(user_id, "public_handbook")
        assert expected_access(user_id, "poisoned_public_document")
        assert not expected_access(user_id, "revoked_engineering_secret")

    assert expected_access("alice", "engineering_runbook")
    assert not expected_access("alice", "hr_compensation")
    assert expected_access("bob", "hr_compensation")
    assert not expected_access("bob", "engineering_runbook")
    assert not expected_access("attacker", "engineering_runbook")
    assert not expected_access("attacker", "hr_compensation")
    assert len({document.canary for document in DOCUMENTS.values()}) == len(DOCUMENTS)


def test_metrics_use_raw_executable_denominators() -> None:
    cases = [
        _case(
            "A1",
            attack=True,
            status=CaseStatus.FAIL,
            security_effect="unauthorized_effect_succeeded",
        ),
        _case("A2", attack=True, status=CaseStatus.PASS, security_effect="blocked"),
        _case("A3", attack=True, status=CaseStatus.BLOCKED, security_effect="not_executed"),
        _case("S1", attack=False, status=CaseStatus.PASS, security_effect="safe_task_completed"),
        _case(
            "S2",
            attack=False,
            status=CaseStatus.FAIL,
            security_effect="safe_task_incorrectly_blocked",
        ),
        _case("S3", attack=False, status=CaseStatus.BLOCKED, security_effect="not_executed"),
    ]

    metrics = calculate_metrics(cases)

    assert metrics["asr"].as_dict() == {"numerator": 1, "denominator": 2, "percent": 50.0}
    assert metrics["fpr"].as_dict() == {"numerator": 1, "denominator": 2, "percent": 50.0}
    assert metrics["safe_task_rate"].as_dict() == {
        "numerator": 1,
        "denominator": 2,
        "percent": 50.0,
    }


def test_zero_metric_denominator_is_not_reported_as_zero_percent() -> None:
    metrics = calculate_metrics(
        [_case("A1", attack=True, status=CaseStatus.BLOCKED, security_effect="not_executed")]
    )

    assert metrics["asr"].denominator == 0
    assert metrics["asr"].percent is None
    assert metrics["fpr"].percent is None
    assert metrics["safe_task_rate"].percent is None


def test_run_status_never_converts_blocked_to_verified() -> None:
    passed = _case("S1", attack=False, status=CaseStatus.PASS, security_effect="safe_task_completed")
    blocked = _case("A1", attack=True, status=CaseStatus.BLOCKED, security_effect="not_executed")
    failed = _case(
        "A2",
        attack=True,
        status=CaseStatus.FAIL,
        security_effect="unauthorized_effect_succeeded",
    )

    assert derive_run_status([passed]) is RunStatus.VERIFIED
    assert derive_run_status([passed, blocked]) is RunStatus.BLOCKED
    assert derive_run_status([passed, blocked, failed]) is RunStatus.FAILED


def test_evidence_sanitizer_redacts_credential_fields() -> None:
    sanitized = sanitize_evidence(
        {
            "returned_document_ids": ["engineering_runbook"],
            "Authorization": "Bearer synthetic-token",
            "nested": {
                "api_key": "synthetic-api-key",
                "cookie": "synthetic-cookie",
                "canary": "AEGIS-ONYX-ENG-4R8K",
            },
        }
    )

    assert sanitized["returned_document_ids"] == ["engineering_runbook"]
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["nested"]["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["cookie"] == "[REDACTED]"
    assert sanitized["nested"]["canary"] == "AEGIS-ONYX-ENG-4R8K"
