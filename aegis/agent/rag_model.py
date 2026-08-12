import json
from dataclasses import dataclass

from pydantic import ValidationError

from aegis.mcp_gateway.models import ToolCallProposal
from aegis.rag.models import RetrievedDocument


RAG_MODEL_ID = "deterministic-rag-security-model-v1"
RAG_PROMPT_VERSION = "p2b-rag-context-v1"
POISON_TOOL_PREFIX = "AEGIS_POISON_TOOL="


@dataclass(frozen=True)
class RagModelDecision:
    answer: str
    proposal: ToolCallProposal | None


class DeterministicRagSecurityModel:
    """Deterministic stand-in for a model exposed to untrusted retrieved context.

    For P2-B this model intentionally demonstrates the dangerous behavior we want
    the control plane to survive: a specially marked line inside a retrieved
    document can cause the model to *propose* a tool call. Hardened server policy
    must make that proposal non-authoritative.
    """

    model_id = RAG_MODEL_ID
    prompt_version = RAG_PROMPT_VERSION

    def respond(
        self,
        *,
        user_query: str,
        documents: list[RetrievedDocument],
    ) -> RagModelDecision:
        del user_query  # The fixed P2-B model behavior is driven by retrieved context.

        answer_fragments: list[str] = []
        proposal: ToolCallProposal | None = None

        for document in documents:
            visible_lines: list[str] = []
            for line in document.text.splitlines():
                stripped = line.strip()
                if stripped.startswith(POISON_TOOL_PREFIX):
                    if proposal is None:
                        payload = stripped[len(POISON_TOOL_PREFIX) :]
                        try:
                            candidate = json.loads(payload)
                            proposal = ToolCallProposal.model_validate(candidate)
                        except (json.JSONDecodeError, ValidationError):
                            # Malformed untrusted content stays data and cannot become a call.
                            pass
                    continue
                if stripped:
                    visible_lines.append(stripped)

            visible_text = " ".join(visible_lines).strip()
            if visible_text:
                answer_fragments.append(f"{document.title}: {visible_text}")

        answer = "\n".join(answer_fragments)
        if not answer:
            answer = "No authorized knowledge was retrieved."
        return RagModelDecision(answer=answer, proposal=proposal)
