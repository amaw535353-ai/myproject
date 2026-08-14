from __future__ import annotations

from typing import Any

from aegis.agent.checkpoint_runtime_contracts import (
    CheckpointAnchorHead,
    CheckpointWriteHead,
    decode_checkpoint_scope,
)


class SyntheticExternalCheckpointAnchorRuntimeBridge:
    """Lab-only bridge from the P4-G anchor contract to P4-H runtime writes.

    P4-G originally modeled only checkpoint-head compare-and-advance. P4-H also
    needs pending-write set heads. This bridge keeps those write heads in-process
    while delegating checkpoint monotonicity to the existing P4-G adapter. It is
    intentionally synthetic and is not a production external anchor adapter.
    """

    synthetic_in_process = True
    operationally_external = False

    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self.provider_id = str(delegate.provider_id)
        self._write_heads: dict[tuple[str, str], CheckpointWriteHead] = {}

    def current_head(self, scope: str) -> CheckpointAnchorHead | None:
        head = self._delegate.current_head(scope)
        if head is None:
            return None
        return CheckpointAnchorHead(
            generation=int(head.generation),
            checkpoint_id=str(head.checkpoint_id),
            checkpoint_digest=str(head.checkpoint_digest),
        )

    def advance(
        self,
        scope: str,
        *,
        generation: int,
        checkpoint_id: str,
        checkpoint_digest: str,
        expected_generation: int | None,
    ) -> CheckpointAnchorHead:
        head = self._delegate.advance(
            scope,
            generation=generation,
            checkpoint_id=checkpoint_id,
            checkpoint_digest=checkpoint_digest,
            expected_generation=expected_generation,
        )
        return CheckpointAnchorHead(
            generation=int(head.generation),
            checkpoint_id=str(head.checkpoint_id),
            checkpoint_digest=str(head.checkpoint_digest),
        )

    def current_write_head(
        self,
        scope: str,
        checkpoint_id: str,
    ) -> CheckpointWriteHead | None:
        return self._write_heads.get((str(scope), str(checkpoint_id)))

    def set_write_head(
        self,
        scope: str,
        *,
        checkpoint_id: str,
        write_count: int,
        aggregate_digest: str,
    ) -> CheckpointWriteHead:
        head = CheckpointWriteHead(
            write_count=int(write_count),
            aggregate_digest=str(aggregate_digest),
        )
        self._write_heads[(str(scope), str(checkpoint_id))] = head
        return head

    def delete_thread(self, thread_id: str) -> None:
        resolved = str(thread_id)
        for key in tuple(self._write_heads):
            scope, _ = key
            try:
                scoped_thread_id, _ = decode_checkpoint_scope(scope)
            except ValueError:
                continue
            if scoped_thread_id == resolved:
                del self._write_heads[key]
        delegate_heads = getattr(self._delegate, "_heads", None)
        if isinstance(delegate_heads, dict):
            for scope in tuple(delegate_heads):
                try:
                    scoped_thread_id, _ = decode_checkpoint_scope(str(scope))
                except ValueError:
                    continue
                if scoped_thread_id == resolved:
                    del delegate_heads[scope]
