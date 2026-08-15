# P10-G threat model — streaming response, cancellation, backpressure, and tool framing

## Security objective

P10-G secures the final streaming-output boundary after P10-F has bound the request to the expected tenant/session, target model, adapter generation, and accelerator partitions. The goal is to prevent a caller, stale stream, framing mutation, cancellation race, or slow consumer from redirecting output, replaying a completed stream, crossing tenant/session boundaries, bypassing tool-call framing, or forcing unbounded application buffering.

## Trusted inputs

The analyzer trusts only policy-owned pins plus the exact P10-F clean assessment evidence SHA-256. The upstream P10-F assessment must be `ALLOW`, carry no risks, preserve every positive P10-F verification flag, keep every live/production nonclaim false, and match the exact P10-F assessment schema and mode. P10-G does not reinterpret GPU or DMA evidence.

## Adversary capabilities

The adversary can forge caller-declared safety booleans; swap request, tenant, session, model, adapter, partition, stream, or output-channel identities; change SSE content type or encoding; reorder, duplicate, drop, or replay frames; tamper payload, SSE, chain, or argument digests; exceed frame/output/buffer/unacked budgets; forge cancellation authorization or delay cancellation; append output after cancellation; inject newline/SSE-looking content into token or tool arguments; substitute an unauthorized tool; replay a prior stream; and inject unexpected network-operation evidence.

## Invariants

1. Exact P10-F assessment binding and exact request/tenant/session/model/adapter/partition lineage.
2. One policy-pinned stream and output channel with exact generation, SSE content type, and UTF-8 encoding.
3. Ordered frame coverage beginning at sequence 1 with a deterministic hash chain seeded from stream route identity.
4. Payload digest, canonical SSE digest, and encoded byte count must recompute for every frame.
5. Per-frame, total-output, buffered-byte, and unacknowledged-frame budgets fail closed.
6. Tool calls are allowed only for policy-approved tool names, JSON-object arguments, bounded argument bytes, canonical payload construction, and canonical SSE encoding that escapes newline-looking payload data.
7. Cancellation authorization is tenant/session/stream bound, cancellation lag is bounded, the expected terminal frame is explicit, and no frame may follow the cancellation terminal boundary.
8. Prior-stream ledger digest must recompute, and the current stream ID may not appear in the replay ledger.
9. The deterministic evidence path performs no external network operation.

## Real loopback professional-mastery exercise

`apps/p10g_streaming_lab.py` and `scripts/run_p10g_streaming_lab.py` exercise a real loopback TCP/HTTP path through Uvicorn and FastAPI. The lab verifies cross-tenant denial before stream start, server-side cancellation after the first streamed event, bounded application queue behavior with observable producer pauses, containment of an SSE-looking newline payload through JSON framing, and one-shot stream replay rejection.

The loopback lab is stronger than a purely synthetic transcript because bytes cross an actual localhost socket and cancellation is issued by a second HTTP request while the first response is in flight. It still does **not** prove production load-balancer behavior, kernel/TCP backpressure under saturation, remote disconnect semantics, distributed cancellation linearizability, tool-dispatch safety, or internet-facing availability.

## Claim boundary

P10-G deterministic hashes are integrity bindings, not authenticity. The analyzer does not prove semantic output safety, tool correctness, or cryptographic client identity. The loopback lab validates a local single-process FastAPI/Uvicorn path only. `kernel_tcp_backpressure_validated`, `distributed_cancellation_linearizability_validated`, `production_streaming_gateway_integrated`, `production_tool_dispatch_integrated`, `semantic_output_safety_validated`, and `remote_client_disconnect_semantics_validated` remain false.
