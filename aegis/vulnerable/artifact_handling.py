from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path


VULNERABLE_ARTIFACT_POLICY_VERSION = "client-path-and-raw-inline-rendering-v1"


@dataclass(frozen=True)
class VulnerableArtifactResult:
    stored_path: Path
    content_type: str
    content_disposition: str
    body: bytes
    extracted_paths: tuple[Path, ...]
    extracted_bytes: int
    policy_version: str = VULNERABLE_ARTIFACT_POLICY_VERSION


class VulnerableArtifactHandler:
    """Intentionally unsafe local-only artifact baseline for P2-I.

    This code trusts the client filename for storage, trusts the declared content
    type for inline rendering, and extracts ZIP members without path or size
    validation. Never wire this class into the hardened application.
    """

    def __init__(self, *, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    def ingest(
        self,
        *,
        filename: str,
        content_type: str,
        data: bytes,
    ) -> VulnerableArtifactResult:
        destination = self._root / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

        extracted_paths: list[Path] = []
        extracted_bytes = 0
        if content_type.casefold() == "application/zip" or filename.casefold().endswith(".zip"):
            extraction_root = destination.parent / f"{destination.stem}-extracted"
            extraction_root.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    member_data = archive.read(info)
                    member_path = extraction_root / info.filename
                    member_path.parent.mkdir(parents=True, exist_ok=True)
                    member_path.write_bytes(member_data)
                    extracted_paths.append(member_path)
                    extracted_bytes += len(member_data)

        return VulnerableArtifactResult(
            stored_path=destination,
            content_type=content_type,
            content_disposition="inline",
            body=data,
            extracted_paths=tuple(extracted_paths),
            extracted_bytes=extracted_bytes,
        )
