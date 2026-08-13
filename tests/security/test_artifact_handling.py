from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path

import pytest

from aegis.artifacts import ArtifactRejected, ArtifactService
from aegis.vulnerable.artifact_handling import VulnerableArtifactHandler


def _zip_bytes(entries: list[tuple[zipfile.ZipInfo | str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name_or_info, payload in entries:
            if isinstance(name_or_info, zipfile.ZipInfo):
                info = name_or_info
            else:
                info = zipfile.ZipInfo(
                    name_or_info,
                    date_time=(2025, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return buffer.getvalue()


def test_hardened_storage_ignores_client_path_traversal(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted.txt"
    trusted.write_bytes(b"trusted")
    service = ArtifactService(root=tmp_path / "uploads")

    receipt = service.ingest(
        filename="../trusted.txt",
        content_type="text/plain",
        data=b"user content",
    )

    assert trusted.read_bytes() == b"trusted"
    assert receipt.display_name == "trusted.txt"
    assert receipt.storage_path.is_relative_to(service.root)
    assert receipt.storage_path.name == "payload.bin"


def test_vulnerable_storage_overwrites_parent_path(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted.txt"
    trusted.write_bytes(b"trusted")
    handler = VulnerableArtifactHandler(root=tmp_path / "uploads")

    handler.ingest(
        filename="../trusted.txt",
        content_type="text/plain",
        data=b"overwritten",
    )

    assert trusted.read_bytes() == b"overwritten"


def test_hardened_rejects_active_html_content_type(tmp_path: Path) -> None:
    service = ArtifactService(root=tmp_path / "uploads")

    with pytest.raises(ArtifactRejected, match="content type"):
        service.ingest(
            filename="report.html",
            content_type="text/html",
            data=b"<script>alert(1)</script>",
        )


def test_hardened_html_like_text_is_presented_as_plain_text_with_nosniff(
    tmp_path: Path,
) -> None:
    service = ArtifactService(root=tmp_path / "uploads")
    body = b"<script>alert(1)</script>"
    receipt = service.ingest(
        filename="notes.txt",
        content_type="text/plain",
        data=body,
    )

    presentation = service.present(receipt.artifact_id)

    assert presentation.content_type == "text/plain; charset=utf-8"
    assert presentation.content_disposition == "inline"
    assert presentation.nosniff is True
    assert presentation.body == body


def test_hardened_rejects_zip_member_path_traversal(tmp_path: Path) -> None:
    service = ArtifactService(root=tmp_path / "uploads")
    archive = _zip_bytes([("../escape.txt", b"escape")])

    with pytest.raises(ArtifactRejected, match="traversal"):
        service.ingest(
            filename="bad.zip",
            content_type="application/zip",
            data=archive,
        )

    assert not (tmp_path / "escape.txt").exists()


def test_hardened_rejects_zip_symlink_member(tmp_path: Path) -> None:
    service = ArtifactService(root=tmp_path / "uploads")
    info = zipfile.ZipInfo("link.txt", date_time=(2025, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive = _zip_bytes([(info, b"target.txt")])

    with pytest.raises(ArtifactRejected, match="symlinks"):
        service.ingest(
            filename="symlink.zip",
            content_type="application/zip",
            data=archive,
        )


def test_hardened_rejects_archive_expansion_budget(tmp_path: Path) -> None:
    service = ArtifactService(root=tmp_path / "uploads")
    archive = _zip_bytes([("large.txt", b"A" * 32_768)])

    with pytest.raises(ArtifactRejected, match="byte budget|expansion|compression ratio"):
        service.ingest(
            filename="large.zip",
            content_type="application/zip",
            data=archive,
        )


def test_hardened_rejects_content_type_mismatch(tmp_path: Path) -> None:
    service = ArtifactService(root=tmp_path / "uploads")
    archive = _zip_bytes([("readme.txt", b"safe")])

    with pytest.raises(ArtifactRejected, match="does not match ZIP"):
        service.ingest(
            filename="looks-like-text.txt",
            content_type="text/plain",
            data=archive,
        )


def test_hardened_rejects_duplicate_casefolded_archive_names(tmp_path: Path) -> None:
    service = ArtifactService(root=tmp_path / "uploads")
    archive = _zip_bytes(
        [
            ("Docs/Readme.txt", b"one"),
            ("docs/readme.TXT", b"two"),
        ]
    )

    with pytest.raises(ArtifactRejected, match="duplicate normalized"):
        service.ingest(
            filename="duplicates.zip",
            content_type="application/zip",
            data=archive,
        )


def test_hardened_accepts_bounded_safe_archive(tmp_path: Path) -> None:
    service = ArtifactService(root=tmp_path / "uploads")
    archive = _zip_bytes(
        [
            ("docs/readme.txt", b"readme\n"),
            ("meta/info.json", b'{"ok":true}\n'),
        ]
    )

    receipt = service.ingest(
        filename="bundle.zip",
        content_type="application/zip",
        data=archive,
    )

    assert len(receipt.extracted_members) == 2
    assert {item.member_name for item in receipt.extracted_members} == {
        "docs/readme.txt",
        "meta/info.json",
    }
    assert all(item.stored_path.is_relative_to(service.root) for item in receipt.extracted_members)
    presentation = service.present(receipt.artifact_id)
    assert presentation.content_type == "application/zip"
    assert presentation.content_disposition == "attachment"
    assert presentation.nosniff is True
