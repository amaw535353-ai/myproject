from __future__ import annotations

from dataclasses import dataclass

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer


P4A_CHECKPOINT_POLICY_VERSION = "strict-exact-checkpoint-deserialization-v1"

# These are the only AegisDesk application types that the default AgentState
# legitimately persists in LangGraph checkpoints. Everything else must remain
# plain data on load rather than triggering arbitrary Python reconstruction.
P4A_ALLOWED_MSGPACK_TYPES: tuple[tuple[str, str], ...] = (
    ("aegis.identity.models", "Role"),
    ("aegis.identity.models", "Principal"),
    ("aegis.mcp_gateway.models", "ToolName"),
    ("aegis.mcp_gateway.models", "ToolCallProposal"),
)


@dataclass(frozen=True)
class CheckpointSerializationPolicy:
    policy_version: str = P4A_CHECKPOINT_POLICY_VERSION
    allowed_msgpack_types: tuple[tuple[str, str], ...] = P4A_ALLOWED_MSGPACK_TYPES
    pickle_fallback: bool = False
    allowed_json_modules: None = None


DEFAULT_CHECKPOINT_SERIALIZATION_POLICY = CheckpointSerializationPolicy()


def build_strict_checkpoint_serializer() -> JsonPlusSerializer:
    """Build the default fail-closed LangGraph checkpoint serializer.

    The serializer uses an exact application-type allowlist, disables pickle
    fallback, and permits no custom JSON constructors. LangGraph's built-in
    SAFE_MSGPACK_TYPES remain available independently of this application list.
    """

    return JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=None,
        allowed_msgpack_modules=P4A_ALLOWED_MSGPACK_TYPES,
    )


def build_strict_in_memory_checkpointer() -> InMemorySaver:
    """Return the local test/runtime checkpointer with the strict serializer."""

    return InMemorySaver(serde=build_strict_checkpoint_serializer())
