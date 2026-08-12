from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from aegis.identity.models import Principal
from aegis.memory.models import MemoryRecord, MemorySource, RememberNote


_SCHEMA_VERSION = "sqlite-user-memory-v1"


class SqliteMemoryStore:
    """Durable user memory that stores content as data, never as identity or policy."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @property
    def schema_version(self) -> str:
        return _SCHEMA_VERSION

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_notes (
                    memory_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_notes_principal
                ON memory_notes (tenant_id, user_id, memory_id)
                """
            )
            connection.commit()

    def remember(self, *, principal: Principal, content: str) -> MemoryRecord:
        note = RememberNote(content=content)
        created_at = datetime.now(timezone.utc)
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO memory_notes (tenant_id, user_id, content, source, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    principal.tenant_id,
                    principal.user_id,
                    note.content,
                    MemorySource.USER.value,
                    created_at.isoformat(),
                ),
            )
            connection.commit()
            memory_id = int(cursor.lastrowid)
        return MemoryRecord(
            memory_id=memory_id,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            content=note.content,
            source=MemorySource.USER,
            created_at=created_at,
        )

    def list_for_principal(
        self,
        *,
        principal: Principal,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        if limit < 1 or limit > 100:
            raise ValueError("memory limit must be between 1 and 100")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT memory_id, tenant_id, user_id, content, source, created_at
                FROM memory_notes
                WHERE tenant_id = ? AND user_id = ?
                ORDER BY memory_id ASC
                LIMIT ?
                """,
                (principal.tenant_id, principal.user_id, limit),
            ).fetchall()
        return [
            MemoryRecord(
                memory_id=int(row["memory_id"]),
                tenant_id=str(row["tenant_id"]),
                user_id=str(row["user_id"]),
                content=str(row["content"]),
                source=MemorySource(str(row["source"])),
                created_at=datetime.fromisoformat(str(row["created_at"])),
            )
            for row in rows
        ]
