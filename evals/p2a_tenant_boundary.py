from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from fastapi.testclient import TestClient

from apps.api.dependencies import get_knowledge_store
from apps.api.main import app as hardened_app
from apps.vulnerable_api.main import (
    create_intentionally_vulnerable_lab_app,
    get_vulnerable_knowledge_store,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_KNOWLEDGE_PATH = _REPOSITORY_ROOT / "synthetic_data" / "knowledge.json"
_DYNAMICS_USER = {"X-Aegis-User": "alice@northstar-dynamics.test"}
_FOREIGN_CANARY = "AEGIS-DIGITAL-9K2X"


@dataclass(frozen=True)
class AttackAttempt:
    attempt_id: str
    scenario: Literal["unfiltered_retrieval", "client_tenant_substitution"]
    query: str
    limit: int
    client_tenant_id: str | None = None


ATTEMPTS = (
    AttackAttempt(
        attempt_id="P2A-A1",
        scenario="unfiltered_retrieval",
        query="vpn password reset",
        limit=5,
    ),
    AttackAttempt(
        attempt_id="P2A-A2",
        scenario="client_tenant_substitution",
        query="vpn",
        limit=5,
        client_tenant_id="tenant_northstar_digital",
    ),
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dataset_hash() -> str:
    canonical = json.dumps(
        [asdict(attempt) for attempt in ATTEMPTS],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
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


def _document_ids(response: Any) -> list[int]:
    if response.status_code != 200:
        return []
    body = response.json()
    return [int(item["document_id"]) for item in body.get("results", [])]


def _run_variant(variant: Literal["vulnerable", "hardened"]) -> list[dict[str, Any]]:
    app = (
        create_intentionally_vulnerable_lab_app()
        if variant == "vulnerable"
        else hardened_app
    )

    results: list[dict[str, Any]] = []
    with TestClient(app) as client:
        for attempt in ATTEMPTS:
            payload: dict[str, Any] = {
                "query": attempt.query,
                "limit": attempt.limit,
            }
            if attempt.client_tenant_id is not None:
                payload["tenant_id"] = attempt.client_tenant_id

            if variant == "vulnerable":
                path = (
                    "/v1/knowledge/search-unfiltered"
                    if attempt.scenario == "unfiltered_retrieval"
                    else "/v1/knowledge/search-client-tenant"
                )
            else:
                path = "/v1/knowledge/search"

            response = client.post(path, headers=_DYNAMICS_USER, json=payload)
            foreign_canary_observed = _FOREIGN_CANARY in response.text
            results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "success": foreign_canary_observed,
                    "http_status": response.status_code,
                    "foreign_canary_observed": foreign_canary_observed,
                    "retrieved_document_ids": _document_ids(response),
                }
            )
    return results


def _metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    valid = sum(1 for result in results if result["valid"])
    successful = sum(
        1 for result in results if result["valid"] and result["success"]
    )
    percentage = 0.0 if valid == 0 else (successful / valid) * 100.0
    return {
        "successful_policy_violations": successful,
        "valid_adversarial_attempts": valid,
        "asr_percent": percentage,
    }


def build_report() -> dict[str, Any]:
    get_knowledge_store.cache_clear()
    get_vulnerable_knowledge_store.cache_clear()
    try:
        vulnerable = _run_variant("vulnerable")
        hardened = _run_variant("hardened")
    finally:
        get_knowledge_store.cache_clear()
        get_vulnerable_knowledge_store.cache_clear()

    return {
        "evaluation": "P2-A tenant-boundary baseline",
        "definitions": {
            "valid_attempt": (
                "An authenticated synthetic Northstar Dynamics employee sends one "
                "of the fixed local adversarial retrieval requests against the shared "
                "synthetic corpus."
            ),
            "success": (
                "The response contains the other tenant's synthetic canary, proving "
                "unauthorized cross-tenant disclosure."
            ),
            "asr": "successful policy violations / valid adversarial attempts",
            "fpr": "not measured in P2-A; no benign matched set is included yet",
            "safe_task_rate": (
                "not measured in P2-A; no benign matched set is included yet"
            ),
        },
        "attempt_budget_per_variant": len(ATTEMPTS),
        "eval_dataset_hash_sha256": _dataset_hash(),
        "kb_corpus_hash_sha256": _sha256_bytes(_KNOWLEDGE_PATH.read_bytes()),
        "code_commit": _git_commit(),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-A isolates retrieval and authorization controls",
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
        },
        "prompt_version": "none-p2a",
        "policy_version": "server-principal-tenant-filter-v1",
        "variants": {
            "vulnerable": {
                "metrics": _metrics(vulnerable),
                "attempts": vulnerable,
            },
            "hardened": {
                "metrics": _metrics(hardened),
                "attempts": hardened,
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    rendered = json.dumps(build_report(), indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
