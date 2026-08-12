from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Header, HTTPException, status

from aegis.identity.models import Principal
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.rag.store import KnowledgeStore


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_KNOWLEDGE_PATH = _REPOSITORY_ROOT / "synthetic_data" / "knowledge.json"


async def get_current_principal(
    x_aegis_user: Annotated[str | None, Header(alias="X-Aegis-User")] = None,
) -> Principal:
    if not x_aegis_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing synthetic authentication handle",
        )

    principal = resolve_synthetic_principal(x_aegis_user)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown synthetic authentication handle",
        )
    return principal


@lru_cache(maxsize=1)
def get_knowledge_store() -> KnowledgeStore:
    return KnowledgeStore.from_json(_KNOWLEDGE_PATH)
