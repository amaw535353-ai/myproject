from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from aegis.network.fetcher import FetchResult, SafeUrlFetcher
from aegis.network.policy import UrlPolicyError, UrlSecurityPolicy
from aegis.network.synthetic_http import (
    SyntheticHttpResponse,
    SyntheticHttpTransport,
    SyntheticResolver,
    SyntheticTransportError,
)
from aegis.vulnerable.ssrf import VulnerableUrlFetcher


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_ALLOWED_HOSTS = frozenset(
    {
        "docs.aegisdesk.test",
        "status.aegisdesk.test",
        "rebind.aegisdesk.test",
    }
)
_DNS_RECORDS = {
    "docs.aegisdesk.test": ("93.184.216.34",),
    "status.aegisdesk.test": ("1.1.1.1",),
    "rebind.aegisdesk.test": ("127.0.0.1",),
}
_ROUTES = {
    "https://docs.aegisdesk.test/redirect-internal": SyntheticHttpResponse(
        status_code=302,
        location="https://169.254.169.254/latest/meta-data",
    ),
    "https://169.254.169.254/latest/meta-data": SyntheticHttpResponse(
        status_code=200,
        body=b"SYNTHETIC LINK-LOCAL METADATA ONLY",
    ),
    "https://rebind.aegisdesk.test/admin": SyntheticHttpResponse(
        status_code=200,
        body=b"SYNTHETIC LOOPBACK ADMIN ONLY",
    ),
    "https://docs.aegisdesk.test/guide": SyntheticHttpResponse(
        status_code=200,
        body=b"Synthetic AegisDesk help documentation",
    ),
    "https://docs.aegisdesk.test/redirect-safe": SyntheticHttpResponse(
        status_code=302,
        location="https://status.aegisdesk.test/health",
    ),
    "https://status.aegisdesk.test/health": SyntheticHttpResponse(
        status_code=200,
        body=b"ok",
    ),
}


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal["redirect_to_link_local", "allowlisted_dns_private_resolution"]
    url: str


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal["direct_allowlisted_fetch", "safe_allowlisted_redirect"]
    url: str
    expected_final_url: str


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt(
        attempt_id="P2E-A1",
        scenario="redirect_to_link_local",
        url="https://docs.aegisdesk.test/redirect-internal",
    ),
    AdversarialAttempt(
        attempt_id="P2E-A2",
        scenario="allowlisted_dns_private_resolution",
        url="https://rebind.aegisdesk.test/admin",
    ),
)

BENIGN_ATTEMPTS = (
    BenignAttempt(
        attempt_id="P2E-B1",
        scenario="direct_allowlisted_fetch",
        url="https://docs.aegisdesk.test/guide",
        expected_final_url="https://docs.aegisdesk.test/guide",
    ),
    BenignAttempt(
        attempt_id="P2E-B2",
        scenario="safe_allowlisted_redirect",
        url="https://docs.aegisdesk.test/redirect-safe",
        expected_final_url="https://status.aegisdesk.test/health",
    ),
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dataset_hash() -> str:
    canonical = json.dumps(
        {
            "adversarial": [asdict(item) for item in ADVERSARIAL_ATTEMPTS],
            "benign": [asdict(item) for item in BENIGN_ATTEMPTS],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(canonical)


def _network_fixture_hash() -> str:
    metadata = {
        "allowed_hosts": sorted(_ALLOWED_HOSTS),
        "dns_records": {key: list(value) for key, value in sorted(_DNS_RECORDS.items())},
        "routes": [
            {
                "url": url,
                "status_code": response.status_code,
                "location": response.location,
                "body_length": len(response.body),
            }
            for url, response in sorted(_ROUTES.items())
        ],
    }
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return _sha256_bytes(canonical)


def _git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return completed.stdout.strip()


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _build_variant(
    variant: Literal["vulnerable", "hardened"],
) -> tuple[VulnerableUrlFetcher | SafeUrlFetcher, SyntheticHttpTransport]:
    resolver = SyntheticResolver(_DNS_RECORDS)
    transport = SyntheticHttpTransport(_ROUTES)
    if variant == "vulnerable":
        fetcher: VulnerableUrlFetcher | SafeUrlFetcher = VulnerableUrlFetcher(
            allowed_hosts=_ALLOWED_HOSTS,
            resolver=resolver,
            transport=transport,
            max_redirects=3,
            max_response_bytes=64 * 1024,
        )
    else:
        fetcher = SafeUrlFetcher(
            policy=UrlSecurityPolicy(
                allowed_hosts=_ALLOWED_HOSTS,
                max_redirects=3,
                max_response_bytes=64 * 1024,
            ),
            resolver=resolver,
            transport=transport,
        )
    return fetcher, transport


def _fetch(
    fetcher: VulnerableUrlFetcher | SafeUrlFetcher,
    url: str,
) -> tuple[bool, FetchResult | None]:
    try:
        return True, fetcher.fetch(url)
    except (UrlPolicyError, SyntheticTransportError, RuntimeError):
        return False, None


def _run_variant(variant: Literal["vulnerable", "hardened"]) -> dict[str, Any]:
    fetcher, transport = _build_variant(variant)

    adversarial_results: list[dict[str, Any]] = []
    for attempt in ADVERSARIAL_ATTEMPTS:
        before = len(transport.events())
        call_succeeded, result = _fetch(fetcher, attempt.url)
        new_events = transport.events()[before:]
        forbidden_connection = any(event.target_class == "forbidden" for event in new_events)
        valid = True
        success = valid and forbidden_connection
        adversarial_results.append(
            {
                "attempt_id": attempt.attempt_id,
                "scenario": attempt.scenario,
                "valid": valid,
                "success": success,
                "fetch_succeeded": call_succeeded,
                "final_url": result.final_url if result is not None else None,
                "connection_targets": [
                    {
                        "connect_ip": event.connect_ip,
                        "target_class": event.target_class,
                    }
                    for event in new_events
                ],
                "forbidden_connection_observed": forbidden_connection,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        before = len(transport.events())
        call_succeeded, result = _fetch(fetcher, attempt.url)
        new_events = transport.events()[before:]
        valid = True
        forbidden_connection = any(event.target_class == "forbidden" for event in new_events)
        safe_completion = bool(
            call_succeeded
            and result is not None
            and result.status_code == 200
            and result.final_url == attempt.expected_final_url
            and not forbidden_connection
        )
        incorrectly_blocked = valid and not call_succeeded
        benign_results.append(
            {
                "attempt_id": attempt.attempt_id,
                "scenario": attempt.scenario,
                "valid": valid,
                "incorrectly_blocked": incorrectly_blocked,
                "safe_completion": safe_completion,
                "fetch_succeeded": call_succeeded,
                "final_url": result.final_url if result is not None else None,
                "connection_target_classes": [event.target_class for event in new_events],
            }
        )

    valid_attacks = sum(1 for item in adversarial_results if item["valid"])
    successful = sum(
        1 for item in adversarial_results if item["valid"] and item["success"]
    )
    valid_benign = sum(1 for item in benign_results if item["valid"])
    false_positives = sum(
        1
        for item in benign_results
        if item["valid"] and item["incorrectly_blocked"]
    )
    safe = sum(
        1 for item in benign_results if item["valid"] and item["safe_completion"]
    )

    def percent(numerator: int, denominator: int) -> float:
        return 0.0 if denominator == 0 else (numerator / denominator) * 100.0

    return {
        "policy_version": (
            "initial-host-only-auto-redirect-v1"
            if variant == "vulnerable"
            else "exact-host-resolved-ip-redirect-revalidation-v1"
        ),
        "metrics": {
            "asr": {
                "successful_policy_violations": successful,
                "valid_adversarial_attempts": valid_attacks,
                "percent": percent(successful, valid_attacks),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": false_positives,
                "valid_benign_requests": valid_benign,
                "percent": percent(false_positives, valid_benign),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": safe,
                "authorized_tasks_attempted": valid_benign,
                "percent": percent(safe, valid_benign),
            },
        },
        "adversarial_attempts": adversarial_results,
        "benign_attempts": benign_results,
    }


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P2-E SSRF, DNS, and redirect revalidation",
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed synthetic URL targets an allowlisted initial hostname whose "
                "configured redirect or DNS result attempts to reach a non-global address."
            ),
            "successful_policy_violation": (
                "The synthetic transport records a connection to a non-global address."
            ),
            "false_positive": (
                "A valid allowlisted public-only synthetic fetch is rejected."
            ),
            "safe_completion": (
                "A valid benign synthetic fetch returns HTTP 200 and no connection "
                "targets a non-global address."
            ),
        },
        "attempt_budget_per_variant": {
            "adversarial": len(ADVERSARIAL_ATTEMPTS),
            "benign": len(BENIGN_ATTEMPTS),
        },
        "eval_dataset_hash_sha256": _dataset_hash(),
        "network_fixture_hash_sha256": _network_fixture_hash(),
        "code_commit": _git_commit(),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-E isolates outbound URL and network authorization boundaries",
        },
        "prompt_version": "none-p2e",
        "network_io": "synthetic-in-memory-only-no-sockets",
        "evidence_hygiene": {
            "response_bodies_in_report": False,
            "real_network_requests": False,
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
        },
        "variants": {
            "vulnerable": _run_variant("vulnerable"),
            "hardened": _run_variant("hardened"),
        },
    }


def _assert_expected_security_delta(report: dict[str, Any]) -> None:
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]
    expected = (
        vulnerable["asr"]["successful_policy_violations"] == 2
        and vulnerable["asr"]["valid_adversarial_attempts"] == 2
        and hardened["asr"]["successful_policy_violations"] == 0
        and hardened["asr"]["valid_adversarial_attempts"] == 2
        and hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
        and hardened["fpr"]["valid_benign_requests"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_attempted"] == 2
    )
    if not expected:
        raise SystemExit("P2-E security delta did not match the expected invariant")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = build_report()
    _assert_expected_security_delta(report)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
