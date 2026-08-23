import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import prepare_release_candidate as release_candidate

VERSION = "0.101.0"


def _write_wheel(directory: Path, *, unsafe: bool = False) -> None:
    path = directory / f"aegisdesk-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr(
            f"aegisdesk-{VERSION}.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: aegisdesk\nVersion: 0.101.0\nLicense: Apache-2.0\n",
        )
        for required in release_candidate.REQUIRED_WHEEL_FILES:
            archive.writestr(required, "{}\n")
        if unsafe:
            archive.writestr("../escape", "unsafe")


def _write_sdist(directory: Path) -> None:
    path = directory / f"aegisdesk-{VERSION}.tar.gz"
    with tarfile.open(path, mode="w:gz") as archive:
        for required in release_candidate.REQUIRED_SDIST_FILES:
            payload = b"synthetic release fixture\n"
            info = tarfile.TarInfo(name=f"aegisdesk-{VERSION}/{required}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def test_release_candidate_manifest_binds_validated_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(release_candidate, "version", lambda name: VERSION)
    _write_wheel(tmp_path)
    _write_sdist(tmp_path)
    (tmp_path / "aegisdesk-dependencies.cdx.json").write_text("{}\n", encoding="utf-8")

    manifest = release_candidate.prepare_release_candidate(tmp_path)

    assert manifest["schema"] == "aegis.release-candidate.v1"
    assert manifest["project"] == {
        "name": "aegisdesk",
        "version": VERSION,
        "license": "Apache-2.0",
    }
    assert len(manifest["artifacts"]) == 3
    assert json.loads((tmp_path / "release-manifest.json").read_text()) == manifest
    checksums = (tmp_path / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    assert len(checksums) == 4
    assert all("  " in checksum for checksum in checksums)


def test_release_candidate_rejects_unsafe_wheel_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(release_candidate, "version", lambda name: VERSION)
    _write_wheel(tmp_path, unsafe=True)
    _write_sdist(tmp_path)
    (tmp_path / "aegisdesk-dependencies.cdx.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe archive path"):
        release_candidate.prepare_release_candidate(tmp_path)
