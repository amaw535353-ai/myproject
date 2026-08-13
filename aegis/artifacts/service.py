from __future__ import annotations

import io
import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal
from uuid import uuid4


P2I_POLICY_VERSION = "server-owned-artifact-boundary-v1"
P2I_RENDER_POLICY_VERSION = "passive-content-nosniff-v1"


class ArtifactRejected(RuntimeError):
    """Raised when untrusted artifact input violates a server-owned policy."""


@dataclass(frozen=True)
class ArtifactPolicy:
    max_upload_bytes: int = 32_768
    max_archive_members: int = 8
    max_archive_member_bytes: int = 8_192
    max_archive_uncompressed_bytes: int = 16_384
    max_compression_ratio: float = 20.0
    allowed_content_types: frozenset[str] = frozenset(
        {"text/plain", "application/zip"}
    )
    allowed_archive_extensions: frozenset[str] = frozenset(
        {".txt", ".md", ".json"}
    )


DEFAULT_ARTIFACT_POLICY = ArtifactPolicy()


@dataclass(frozen=True)
class ExtractedMember:
    member_name: str
    stored_path: Path
    size_bytes: int


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact_id: str
    display_name: str
    content_type: Literal["text/plain", "application/zip"]
    storage_path: Path
    size_bytes: int
    extracted_members: tuple[ExtractedMember, ...]
    policy_version: str = P2I_POLICY_VERSION


@dataclass(frozen=True)
class ArtifactPresentation:
    content_type: str
    content_disposition: Literal["inline", "attachment"]
    nosniff: bool
    body: bytes
    render_policy_version: str = P2I_RENDER_POLICY_VERSION


def _safe_display_name(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    leaf = PurePosixPath(normalized).name
    cleaned = "".join(ch for ch in leaf if ch.isprintable() and ch not in "\r\n\x00")
    cleaned = cleaned.strip().strip(".")
    return (cleaned or "artifact")[:120]


def _is_zip_payload(data: bytes) -> bool:
    try:
        return zipfile.is_zipfile(io.BytesIO(data))
    except OSError:
        return False


def _normalized_member_parts(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name or "\\" in name:
        raise ArtifactRejected("archive member path is invalid")
    path = PurePosixPath(name)
    if path.is_absolute():
        raise ArtifactRejected("archive member path is absolute")
    parts = path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ArtifactRejected("archive member path traversal is forbidden")
    if ":" in parts[0]:
        raise ArtifactRejected("archive member drive-like path is forbidden")
    return tuple(parts)


def _zip_entry_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return bool(mode and stat.S_ISLNK(mode))


class ArtifactService:
    """Hardened local artifact service.

    Client filenames are display metadata only. Storage paths and archive extraction
    destinations are assigned by the server. Only passive text and bounded ZIP
    archives are accepted by this lab milestone.
    """

    def __init__(
        self,
        *,
        root: Path,
        policy: ArtifactPolicy = DEFAULT_ARTIFACT_POLICY,
    ) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._policy = policy
        self._records: dict[str, ArtifactReceipt] = {}

    @property
    def policy(self) -> ArtifactPolicy:
        return self._policy

    @property
    def root(self) -> Path:
        return self._root

    def ingest(
        self,
        *,
        filename: str,
        content_type: str,
        data: bytes,
    ) -> ArtifactReceipt:
        normalized_type = content_type.strip().casefold()
        if normalized_type not in self._policy.allowed_content_types:
            raise ArtifactRejected("content type is not allowlisted")
        if len(data) > self._policy.max_upload_bytes:
            raise ArtifactRejected("artifact exceeds upload byte budget")

        is_zip = _is_zip_payload(data)
        if normalized_type == "application/zip" and not is_zip:
            raise ArtifactRejected("declared ZIP content does not match payload")
        if normalized_type == "text/plain" and is_zip:
            raise ArtifactRejected("declared text content does not match ZIP payload")
        if normalized_type == "text/plain":
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ArtifactRejected("text artifact must be valid UTF-8") from exc

        artifact_id = uuid4().hex
        artifact_dir = (self._root / artifact_id).resolve()
        if not artifact_dir.is_relative_to(self._root):
            raise ArtifactRejected("server-generated artifact path escaped storage root")

        try:
            artifact_dir.mkdir(parents=False, exist_ok=False)
            storage_path = artifact_dir / "payload.bin"
            storage_path.write_bytes(data)
            extracted_members: tuple[ExtractedMember, ...] = ()
            if normalized_type == "application/zip":
                extracted_members = self._extract_zip(
                    data=data,
                    extraction_root=artifact_dir / "extracted",
                )
            receipt = ArtifactReceipt(
                artifact_id=artifact_id,
                display_name=_safe_display_name(filename),
                content_type=normalized_type,  # type: ignore[arg-type]
                storage_path=storage_path.resolve(),
                size_bytes=len(data),
                extracted_members=extracted_members,
            )
            self._records[artifact_id] = receipt
            return receipt
        except Exception:
            shutil.rmtree(artifact_dir, ignore_errors=True)
            raise

    def present(self, artifact_id: str) -> ArtifactPresentation:
        receipt = self._records.get(artifact_id)
        if receipt is None:
            raise KeyError("unknown artifact")
        body = receipt.storage_path.read_bytes()
        if receipt.content_type == "text/plain":
            return ArtifactPresentation(
                content_type="text/plain; charset=utf-8",
                content_disposition="inline",
                nosniff=True,
                body=body,
            )
        return ArtifactPresentation(
            content_type="application/zip",
            content_disposition="attachment",
            nosniff=True,
            body=body,
        )

    def _extract_zip(
        self,
        *,
        data: bytes,
        extraction_root: Path,
    ) -> tuple[ExtractedMember, ...]:
        extraction_root = extraction_root.resolve()
        infos: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []
        seen_names: set[str] = set()
        declared_total = 0

        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            raise ArtifactRejected("ZIP archive is malformed") from exc

        with archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if len(infos) >= self._policy.max_archive_members:
                    raise ArtifactRejected("archive member-count budget exceeded")
                if info.flag_bits & 0x1:
                    raise ArtifactRejected("encrypted archive members are forbidden")
                if _zip_entry_is_symlink(info):
                    raise ArtifactRejected("archive symlinks are forbidden")

                parts = _normalized_member_parts(info.filename)
                suffix = PurePosixPath(*parts).suffix.casefold()
                if suffix not in self._policy.allowed_archive_extensions:
                    raise ArtifactRejected("archive member type is not allowlisted")
                normalized_key = "/".join(parts).casefold()
                if normalized_key in seen_names:
                    raise ArtifactRejected("duplicate normalized archive member")
                seen_names.add(normalized_key)

                if info.file_size > self._policy.max_archive_member_bytes:
                    raise ArtifactRejected("archive member byte budget exceeded")
                declared_total += info.file_size
                if declared_total > self._policy.max_archive_uncompressed_bytes:
                    raise ArtifactRejected("archive expansion byte budget exceeded")
                if info.file_size > 0:
                    if info.compress_size <= 0:
                        raise ArtifactRejected("archive member compression metadata is invalid")
                    ratio = info.file_size / info.compress_size
                    if ratio > self._policy.max_compression_ratio:
                        raise ArtifactRejected("archive compression ratio budget exceeded")
                infos.append((info, parts))

            extraction_root.mkdir(parents=False, exist_ok=False)
            extracted: list[ExtractedMember] = []
            actual_total = 0
            for info, parts in infos:
                destination = (extraction_root / Path(*parts)).resolve()
                if not destination.is_relative_to(extraction_root):
                    raise ArtifactRejected("archive member escaped extraction root")
                destination.parent.mkdir(parents=True, exist_ok=True)

                member_bytes = 0
                with archive.open(info, "r") as source, destination.open("xb") as target:
                    while True:
                        chunk = source.read(4096)
                        if not chunk:
                            break
                        member_bytes += len(chunk)
                        actual_total += len(chunk)
                        if member_bytes > self._policy.max_archive_member_bytes:
                            raise ArtifactRejected("archive member exceeded byte budget while reading")
                        if actual_total > self._policy.max_archive_uncompressed_bytes:
                            raise ArtifactRejected("archive exceeded expansion budget while reading")
                        target.write(chunk)
                extracted.append(
                    ExtractedMember(
                        member_name="/".join(parts),
                        stored_path=destination,
                        size_bytes=member_bytes,
                    )
                )
            return tuple(extracted)
