from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.rag.models import RetrievedDocument

_CITATION = re.compile(r"\[doc:(\d+)\]")
_HIDDEN_MARKERS = ("system prompt", "hidden metadata", "tool schema", "policy text")


@dataclass(frozen=True)
class GroundednessResult:
    citation_ids: tuple[int, ...]
    missing_citations: tuple[int, ...]
    unbound_citations: tuple[int, ...]
    unsupported_claims: tuple[str, ...]
    conflicting_evidence: bool
    should_abstain: bool


def evaluate_groundedness(
    *, answer: str, claims: tuple[str, ...], documents: list[RetrievedDocument]
) -> GroundednessResult:
    """Check structural support, not factual truth outside supplied evidence."""

    by_id = {document.document_id: document for document in documents}
    citations = tuple(int(value) for value in _CITATION.findall(answer))
    unbound = tuple(sorted(set(citations) - set(by_id)))
    missing = tuple(document_id for document_id in by_id if document_id not in citations)
    corpus = " ".join(document.text.casefold() for document in documents)
    unsupported = tuple(claim for claim in claims if claim.casefold() not in corpus)
    normalized = [set(re.findall(r"\w+", document.text.casefold())) for document in documents]
    conflicting = any(
        first & second and ({"enabled", "allowed"} & first) and ({"disabled", "denied"} & second)
        for index, first in enumerate(normalized)
        for second in normalized[index + 1 :]
    )
    return GroundednessResult(
        citations, missing, unbound, unsupported, conflicting, not documents or bool(unsupported)
    )


def contains_hidden_context_leak(output: str) -> bool:
    folded = output.casefold()
    return any(marker in folded for marker in _HIDDEN_MARKERS)


def validate_tool_output(
    *,
    proposed_name: str,
    arguments: dict[str, object],
    allowed_tools: frozenset[str],
    tenant_id: str,
) -> bool:
    if proposed_name not in allowed_tools or set(arguments) - {"asset_id", "summary", "tenant_id"}:
        return False
    supplied_tenant = arguments.get("tenant_id")
    return supplied_tenant is None or supplied_tenant == tenant_id
