from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import zipfile
from email.parser import BytesParser
from importlib.metadata import version
from pathlib import Path, PurePosixPath

PROJECT_NAME = "aegisdesk"
REQUIRED_SDIST_FILES = ("LICENSE", "README.md", "SECURITY.md", "CHANGELOG.md", "pyproject.toml")
REQUIRED_WHEEL_FILES = (
    "real_model_evals/data/real_model_rag_mcp_cases.json",
    "synthetic_data/assets.json",
    "synthetic_data/knowledge.json",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def _require_single(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {pattern} artifact, found {len(matches)}")
    return matches[0]


def _validate_wheel(path: Path, project_version: str) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if any(not _safe_archive_name(name) for name in names):
            raise ValueError("wheel contains an unsafe archive path")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError("wheel must contain exactly one METADATA file")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        missing = [required for required in REQUIRED_WHEEL_FILES if required not in names]
        if missing:
            raise ValueError(f"wheel is missing required runtime fixtures: {missing}")
    observed = {
        "name": metadata.get("Name", ""),
        "version": metadata.get("Version", ""),
        "license": metadata.get("License-Expression", metadata.get("License", "")),
    }
    expected = {"name": PROJECT_NAME, "version": project_version, "license": "Apache-2.0"}
    if observed != expected:
        raise ValueError(f"wheel metadata mismatch: expected {expected}, observed {observed}")
    return observed


def _validate_sdist(path: Path, project_version: str) -> None:
    expected_root = f"{PROJECT_NAME}-{project_version}"
    with tarfile.open(path, mode="r:gz") as archive:
        names = archive.getnames()
        if any(not _safe_archive_name(name) for name in names):
            raise ValueError("source distribution contains an unsafe archive path")
        roots = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
        if roots != {expected_root}:
            raise ValueError(f"source distribution root mismatch: {sorted(roots)}")
        missing = [
            required
            for required in REQUIRED_SDIST_FILES
            if f"{expected_root}/{required}" not in names
        ]
        if missing:
            raise ValueError(f"source distribution is missing required files: {missing}")


def prepare_release_candidate(directory: Path) -> dict[str, object]:
    project_version = version(PROJECT_NAME)
    wheel = _require_single(directory, "*.whl")
    sdist = _require_single(directory, "*.tar.gz")
    sbom = _require_single(directory, "*.cdx.json")
    metadata = _validate_wheel(wheel, project_version)
    _validate_sdist(sdist, project_version)

    subjects = [wheel, sdist, sbom]
    artifacts = [
        {"name": subject.name, "sha256": _sha256(subject), "size_bytes": subject.stat().st_size}
        for subject in sorted(subjects)
    ]
    manifest: dict[str, object] = {
        "schema": "aegis.release-candidate.v1",
        "project": metadata,
        "artifacts": artifacts,
        "claim_boundary": "release candidate only; not a production-readiness claim",
    }
    manifest_path = directory / "release-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    checksum_subjects = [*subjects, manifest_path]
    checksums = "".join(
        f"{_sha256(subject)}  {subject.name}\n" for subject in sorted(checksum_subjects)
    )
    (directory / "SHA256SUMS").write_text(checksums, encoding="ascii")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate and bind AegisDesk release-candidate artifacts"
    )
    parser.add_argument("dist_dir", type=Path)
    args = parser.parse_args()
    manifest = prepare_release_candidate(args.dist_dir)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
