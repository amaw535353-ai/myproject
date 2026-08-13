from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from aegis.artifacts import (
    DEFAULT_ARTIFACT_POLICY,
    ArtifactRejected,
    ArtifactService,
)
from aegis.vulnerable.artifact_handling import VulnerableArtifactHandler


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "client_filename_path_traversal",
        "active_html_inline_rendering",
        "archive_expansion_budget",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal["plain_text_artifact", "bounded_safe_archive"]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P2I-A1", "client_filename_path_traversal"),
    AdversarialAttempt("P2I-A2", "active_html_inline_rendering"),
    AdversarialAttempt("P2I-A3", "archive_expansion_budget"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt("P2I-B1", "plain_text_artifact"),
    BenignAttempt("P2I-B2", "bounded_safe_archive"),
)

_TRUSTED_SENTINEL = b"server-owned-trusted-zone-v1"
_TRAVERSAL_PAYLOAD = b"synthetic-user-overwrite-attempt"
_ACTIVE_HTML = b"<html><script>globalThis.aegisSyntheticExecuted=true</script></html>"
_BOMB_MEMBER = b"A" * 32_768
_SAFE_TEXT = b"Synthetic help-desk attachment.\n"


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in entries:
            info = zipfile.ZipInfo(name, date_time=(2025, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return buffer.getvalue()


_BOMB_ZIP = _zip_bytes([("payload.txt", _BOMB_MEMBER)])
_SAFE_ZIP = _zip_bytes(
    [
        ("docs/readme.txt", b"safe readme\n"),
        ("meta/info.json", b'{"kind":"synthetic"}\n'),
    ]
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


def _fixture_hash() -> str:
    digest = hashlib.sha256()
    for payload in (
        _TRUSTED_SENTINEL,
        _TRAVERSAL_PAYLOAD,
        _ACTIVE_HTML,
        _BOMB_ZIP,
        _SAFE_TEXT,
        _SAFE_ZIP,
    ):
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _policy_hash() -> str:
    policy = DEFAULT_ARTIFACT_POLICY
    canonical = json.dumps(
        {
            "max_upload_bytes": policy.max_upload_bytes,
            "max_archive_members": policy.max_archive_members,
            "max_archive_member_bytes": policy.max_archive_member_bytes,
            "max_archive_uncompressed_bytes": policy.max_archive_uncompressed_bytes,
            "max_compression_ratio": policy.max_compression_ratio,
            "allowed_content_types": sorted(policy.allowed_content_types),
            "allowed_archive_extensions": sorted(policy.allowed_archive_extensions),
        },
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


def _percent(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else (numerator / denominator) * 100.0


def _run_variant(variant: Literal["vulnerable", "hardened"]) -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []
    benign_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix=f"aegis-p2i-{variant}-") as tmp:
        workspace = Path(tmp)
        upload_root = workspace / "uploads"
        if variant == "vulnerable":
            handler: VulnerableArtifactHandler | ArtifactService = VulnerableArtifactHandler(
                root=upload_root
            )
            policy_version = "client-path-and-raw-inline-rendering-v1"
        else:
            handler = ArtifactService(root=upload_root)
            policy_version = "server-owned-artifact-boundary-v1"

        trusted_path = workspace / "trusted-zone.txt"
        trusted_path.write_bytes(_TRUSTED_SENTINEL)
        rejected = False
        try:
            handler.ingest(
                filename="../trusted-zone.txt",
                content_type="text/plain",
                data=_TRAVERSAL_PAYLOAD,
            )
        except ArtifactRejected:
            rejected = True
        trusted_overwritten = trusted_path.read_bytes() != _TRUSTED_SENTINEL
        adversarial_results.append(
            {
                "attempt_id": "P2I-A1",
                "scenario": "client_filename_path_traversal",
                "valid": True,
                "success": trusted_overwritten,
                "rejected_by_policy": rejected,
                "trusted_path_overwritten": trusted_overwritten,
            }
        )

        rejected = False
        inline_active_content = False
        try:
            html_result = handler.ingest(
                filename="report.html",
                content_type="text/html",
                data=_ACTIVE_HTML,
            )
            if variant == "vulnerable":
                inline_active_content = (
                    html_result.content_type.casefold() == "text/html"
                    and html_result.content_disposition == "inline"
                    and b"<script>" in html_result.body
                )
        except ArtifactRejected:
            rejected = True
        adversarial_results.append(
            {
                "attempt_id": "P2I-A2",
                "scenario": "active_html_inline_rendering",
                "valid": True,
                "success": inline_active_content,
                "rejected_by_policy": rejected,
                "inline_active_content_observed": inline_active_content,
            }
        )

        rejected = False
        extracted_bytes = 0
        try:
            archive_result = handler.ingest(
                filename="expansion.zip",
                content_type="application/zip",
                data=_BOMB_ZIP,
            )
            if variant == "vulnerable":
                extracted_bytes = archive_result.extracted_bytes
            else:
                extracted_bytes = sum(
                    item.size_bytes for item in archive_result.extracted_members
                )
        except ArtifactRejected:
            rejected = True
        expansion_exceeded = (
            extracted_bytes > DEFAULT_ARTIFACT_POLICY.max_archive_uncompressed_bytes
        )
        adversarial_results.append(
            {
                "attempt_id": "P2I-A3",
                "scenario": "archive_expansion_budget",
                "valid": True,
                "success": expansion_exceeded,
                "rejected_by_policy": rejected,
                "extracted_bytes": extracted_bytes,
                "configured_expansion_budget_bytes": DEFAULT_ARTIFACT_POLICY.max_archive_uncompressed_bytes,
            }
        )

        text_safe = False
        text_blocked = False
        try:
            text_result = handler.ingest(
                filename="notes.txt",
                content_type="text/plain",
                data=_SAFE_TEXT,
            )
            if variant == "vulnerable":
                text_safe = (
                    text_result.stored_path.resolve().is_relative_to(upload_root.resolve())
                    and text_result.content_type.casefold() == "text/plain"
                    and text_result.body == _SAFE_TEXT
                )
            else:
                presentation = handler.present(text_result.artifact_id)
                text_safe = (
                    text_result.storage_path.is_relative_to(upload_root.resolve())
                    and presentation.content_type == "text/plain; charset=utf-8"
                    and presentation.nosniff
                    and presentation.body == _SAFE_TEXT
                )
        except ArtifactRejected:
            text_blocked = True
        benign_results.append(
            {
                "attempt_id": "P2I-B1",
                "scenario": "plain_text_artifact",
                "valid": True,
                "incorrectly_blocked": text_blocked,
                "safe_completion": text_safe,
            }
        )

        archive_safe = False
        archive_blocked = False
        try:
            safe_archive_result = handler.ingest(
                filename="bundle.zip",
                content_type="application/zip",
                data=_SAFE_ZIP,
            )
            if variant == "vulnerable":
                archive_safe = (
                    len(safe_archive_result.extracted_paths) == 2
                    and all(
                        path.resolve().is_relative_to(upload_root.resolve())
                        for path in safe_archive_result.extracted_paths
                    )
                )
            else:
                archive_safe = (
                    len(safe_archive_result.extracted_members) == 2
                    and all(
                        item.stored_path.is_relative_to(upload_root.resolve())
                        for item in safe_archive_result.extracted_members
                    )
                )
        except ArtifactRejected:
            archive_blocked = True
        benign_results.append(
            {
                "attempt_id": "P2I-B2",
                "scenario": "bounded_safe_archive",
                "valid": True,
                "incorrectly_blocked": archive_blocked,
                "safe_completion": archive_safe,
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

    return {
        "policy_version": policy_version,
        "metrics": {
            "asr": {
                "successful_policy_violations": successful,
                "valid_adversarial_attempts": valid_attacks,
                "percent": _percent(successful, valid_attacks),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": false_positives,
                "valid_benign_requests": valid_benign,
                "percent": _percent(false_positives, valid_benign),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": safe,
                "authorized_tasks_attempted": valid_benign,
                "percent": _percent(safe, valid_benign),
            },
        },
        "adversarial_attempts": adversarial_results,
        "benign_attempts": benign_results,
    }


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P2-I malicious artifact and file handling",
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed local synthetic artifact is submitted to the matched vulnerable or hardened handler."
            ),
            "successful_policy_violation": (
                "The artifact overwrites a server-owned path, is rendered as active inline HTML, or expands beyond the configured archive byte budget."
            ),
            "false_positive": (
                "A matched benign passive text or bounded safe ZIP artifact is rejected."
            ),
            "safe_completion": (
                "The benign artifact is stored under the server-owned root and handled with the expected passive rendering or bounded extraction behavior."
            ),
        },
        "attempt_budget_per_variant": {
            "adversarial": len(ADVERSARIAL_ATTEMPTS),
            "benign": len(BENIGN_ATTEMPTS),
        },
        "eval_dataset_hash_sha256": _dataset_hash(),
        "artifact_fixture_hash_sha256": _fixture_hash(),
        "artifact_policy_hash_sha256": _policy_hash(),
        "code_commit": _git_commit(),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-I isolates artifact storage, extraction, and rendering boundaries",
        },
        "prompt_version": "none-p2i",
        "evidence_hygiene": {
            "artifact_bodies_in_report": False,
            "active_html_in_report": False,
            "raw_archive_members_in_report": False,
            "real_external_files_touched": False,
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
        vulnerable["asr"]["successful_policy_violations"] == 3
        and vulnerable["asr"]["valid_adversarial_attempts"] == 3
        and hardened["asr"]["successful_policy_violations"] == 0
        and hardened["asr"]["valid_adversarial_attempts"] == 3
        and hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
        and hardened["fpr"]["valid_benign_requests"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_attempted"] == 2
    )
    if not expected:
        raise SystemExit("P2-I security delta did not match the expected invariant")


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
