import json
from pathlib import Path

from qdrant_client import QdrantClient, models

from aegis.rag.models import KnowledgeDocument, RetrievedDocument
from aegis.rag.store import _VECTOR_SIZE, deterministic_embedding


class VulnerableKnowledgeStore:
    """INTENTIONALLY VULNERABLE retrieval store for local synthetic attacks only.

    This class exists to make authorization failures reproducible. Production code
    must use ``aegis.rag.store.KnowledgeStore`` instead.
    """

    COLLECTION = "vulnerable_knowledge_base"

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
    def from_json(cls, path: Path) -> "VulnerableKnowledgeStore":
        raw_documents = json.loads(path.read_text(encoding="utf-8"))
        documents = [KnowledgeDocument.model_validate(item) for item in raw_documents]
        return cls(documents)

    @staticmethod
    def _to_documents(points: list[object]) -> list[RetrievedDocument]:
        results: list[RetrievedDocument] = []
        for point in points:
            payload = getattr(point, "payload", None) or {}
            results.append(
                RetrievedDocument(
                    document_id=int(getattr(point, "id")),
                    tenant_id=str(payload["tenant_id"]),
                    title=str(payload["title"]),
                    text=str(payload["text"]),
                    score=float(getattr(point, "score")),
                )
            )
        return results

    def search_unfiltered(self, *, query: str, limit: int = 3) -> list[RetrievedDocument]:
        """VULNERABILITY: query the shared collection without tenant authorization."""

        response = self._client.query_points(
            collection_name=self.COLLECTION,
            query=deterministic_embedding(query),
            limit=limit,
            with_payload=True,
        )
        return self._to_documents(response.points)

    def search_by_client_tenant(
        self,
        *,
        query: str,
        tenant_id: str,
        limit: int = 3,
    ) -> list[RetrievedDocument]:
        """VULNERABILITY: trust a client-supplied tenant identifier as authorization."""

        response = self._client.query_points(
            collection_name=self.COLLECTION,
            query=deterministic_embedding(query),
            query_filter=models.Filter(
                must=[
                    models.FieldCondition(
                        key="tenant_id",
                        match=models.MatchValue(value=tenant_id),
                    )
                ]
            ),
            limit=limit,
            with_payload=True,
        )
        return self._to_documents(response.points)
