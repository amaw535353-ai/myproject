from __future__ import annotations

from typing import Any, Iterable, Mapping

from aegis.agent.checkpoint_external_contracts import ExternalAnchorHead
from aegis.agent.checkpoint_runtime_contracts import (
    CheckpointAnchorHead,
    CheckpointWriteHead,
    decode_checkpoint_scope,
    encode_checkpoint_scope,
)


class SyntheticExternalCheckpointAnchorRuntimeBridge:
    """Lab-only bridge from the P4-G anchor contract to P4-H runtime writes.

    P4-G originally modeled only checkpoint-head compare-and-advance. P4-H also
    needs pending-write set heads. This bridge keeps those write heads in-process
    while delegating checkpoint monotonicity to the existing P4-G adapter. P4-J
    adds explicit state export/import operations used only by the synthetic
    external-style lifecycle contract; those operations do not expose a local
    SQLite anchor path and do not make this bridge operationally external.
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

    def export_heads(self) -> tuple[dict[str, object], ...]:
        """Export checkpoint heads without revealing or requiring a local DB path."""

        delegate_heads = getattr(self._delegate, "_heads", None)
        if not isinstance(delegate_heads, dict):
            raise RuntimeError("synthetic external anchor does not support state export")
        exported: list[dict[str, object]] = []
        for scope, head in sorted(delegate_heads.items(), key=lambda item: str(item[0])):
            thread_id, checkpoint_ns = decode_checkpoint_scope(str(scope))
            exported.append(
                {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "generation": int(head.generation),
                    "checkpoint_id": str(head.checkpoint_id),
                    "checkpoint_digest": str(head.checkpoint_digest),
                }
            )
        return tuple(exported)

    def export_write_heads(self) -> tuple[dict[str, object], ...]:
        exported: list[dict[str, object]] = []
        for (scope, checkpoint_id), head in sorted(
            self._write_heads.items(), key=lambda item: (str(item[0][0]), str(item[0][1]))
        ):
            thread_id, checkpoint_ns = decode_checkpoint_scope(str(scope))
            exported.append(
                {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": str(checkpoint_id),
                    "write_count": int(head.write_count),
                    "aggregate_digest": str(head.aggregate_digest),
                }
            )
        return tuple(exported)

    def replace_state(
        self,
        *,
        checkpoint_heads: Iterable[Mapping[str, object]],
        write_heads: Iterable[Mapping[str, object]],
    ) -> None:
        """Replace synthetic external anchor state for an authorized lifecycle operation."""

        delegate_heads = getattr(self._delegate, "_heads", None)
        if not isinstance(delegate_heads, dict):
            raise RuntimeError("synthetic external anchor does not support state import")

        next_checkpoint_heads: dict[str, ExternalAnchorHead] = {}
        for item in checkpoint_heads:
            thread_id = str(item["thread_id"])
            checkpoint_ns = str(item.get("checkpoint_ns", ""))
            generation = int(item["generation"])
            if generation < 1:
                raise ValueError("checkpoint anchor generation must be positive")
            scope = encode_checkpoint_scope(thread_id, checkpoint_ns)
            if scope in next_checkpoint_heads:
                raise ValueError("duplicate checkpoint anchor scope")
            next_checkpoint_heads[scope] = ExternalAnchorHead(
                generation=generation,
                checkpoint_id=str(item["checkpoint_id"]),
                checkpoint_digest=str(item["checkpoint_digest"]),
            )

        next_write_heads: dict[tuple[str, str], CheckpointWriteHead] = {}
        for item in write_heads:
            thread_id = str(item["thread_id"])
            checkpoint_ns = str(item.get("checkpoint_ns", ""))
            checkpoint_id = str(item["checkpoint_id"])
            write_count = int(item["write_count"])
            if write_count < 0:
                raise ValueError("checkpoint write count must be non-negative")
            scope = encode_checkpoint_scope(thread_id, checkpoint_ns)
            key = (scope, checkpoint_id)
            if key in next_write_heads:
                raise ValueError("duplicate checkpoint write-head scope")
            next_write_heads[key] = CheckpointWriteHead(
                write_count=write_count,
                aggregate_digest=str(item["aggregate_digest"]),
            )

        delegate_heads.clear()
        delegate_heads.update(next_checkpoint_heads)
        self._write_heads = next_write_heads
