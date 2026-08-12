import hashlib
import json
import math
import re
from pathlib import Path

from qdrant_client import QdrantClient, models

from aegis.identity.models import Principal
from aegis.rag.models import KnowledgeDocument, RetrievedDocument


_VECTOR_SIZE = 32
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def deterministic_embedding(text: str, *, size: int = _VECTOR_SIZE) -> list[float]:
    """Small deterministic lexical embedding for zero-cost CI and security tests."""

    vector = [0.0] * size
    for token in _TOKEN_RE.findall(text.casefold()):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:2], "big") % size
        sign = 1.0 if digest[2] & 1 else -1.0
        vector[index] += sign

    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return vector
    return [value / norm for value in vector]


class KnowledgeStore:
    COLLECTION = "knowledge_base"

    def __init__(self, documents: list[KnowledgeDocument]) -> None:
        self._client = QdrantClient(":memory:")
        self._client.create_collection(
            collection_name=self.COLLECTION,
            vectors_config=models.VectorParams(
                size=_VECTOR_SIZE,
                distance=models.Distance.COSINE,
            ),
        )
        self._client.upsert(
            collection_name=self.COLLECTION,
            points=[
                models.PointStruct(
                    id=document.id,
                    vector=deterministic_embedding(f"{document.title} {document.text}"),
                    payload=document.model_dump(),
                )
                for document in documents
            ],
        )

    @classmethod
    def from_json(cls, path: Path) -> "KnowledgeStore":
        raw_documents = json.loads(path.read_text(encoding="utf-8"))
        documents = [KnowledgeDocument.model_validate(item) for item in raw_documents]
        return cls(documents)

    def search(
        self,
        *,
        principal: Principal,
        query: str,
        limit: int = 3,
    ) -> list[RetrievedDocument]:
        """Search with a mandatory tenant filter derived only from the principal."""

        response = self._client.query_points(
            collection_name=self.COLLECTION,
            query=deterministic_embedding(query),
            query_filter=models.Filter(
                must=[
                    models.FieldCondition(
                        key="tenant_id",
                        match=models.MatchValue(value=principal.tenant_id),
                    )
                ]
            ),
            limit=limit,
            with_payload=True,
        )

        results: list[RetrievedDocument] = []
        for point in response.points:
            payload = point.payload or {}
            results.append(
                RetrievedDocument(
                    document_id=int(point.id),
                    tenant_id=str(payload["tenant_id"]),
                    title=str(payload["title"]),
                    text=str(payload["text"]),
                    score=float(point.score),
                )
            )
        return results
