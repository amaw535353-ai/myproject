# P10-G professional-mastery lab — real loopback streaming runtime

This lab is intentionally runnable without cloud or GPU access. It exercises a real localhost TCP connection instead of only inspecting synthetic evidence.

## Run

```bash
python scripts/run_p10g_streaming_lab.py --output /tmp/p10g-loopback-report.json
cat /tmp/p10g-loopback-report.json
```

The script starts Uvicorn on an ephemeral `127.0.0.1` port, waits for health, and then performs five security checks.

1. **Output-channel isolation:** a `beta` tenant/session attempts to open the `acme` stream and must receive HTTP 403 before the stream is marked started.
2. **Cancellation race:** an authorized client starts the SSE response, waits for the first event, then a second HTTP request cancels the same stream. The final emitted event must be `cancelled`, with no later `final` event.
3. **Framing injection containment:** the first token intentionally contains `\n\nevent: injected\ndata: pwn`. Canonical JSON-in-SSE encoding must preserve it as payload data rather than creating a second SSE event.
4. **Backpressure:** the producer uses an `asyncio.Queue(maxsize=2)`. The report must show `producer_pause_count > 0`, `max_queue_depth <= queue_limit`, and a drained queue at termination.
5. **Replay protection:** reopening the one-shot stream after termination must return HTTP 409.

A passing report sets `loopback_network_exercised=true` and the five check fields to `true`. It deliberately keeps `production_validation_claimed=false`, `kernel_tcp_backpressure_validated=false`, and `distributed_cancellation_linearizability_validated=false`.

## Current reviewed run

The exact P10-G implementation was exercised in the available local environment. The run passed all five checks. The observed terminal event sequence was `token -> cancelled`; queue limit was 2; maximum queue depth was 2; producer pause count was 2; the queue was drained; and the machine-readable report SHA-256 was:

`e0b04581e926baaeff9178629a3209aa0bb5ccb0e05917033663462a64c5cff9`

This closes the **local streaming-runtime professional-mastery gate** for P10-G. It does not close production/distributed streaming mastery. A later production exercise should add reverse-proxy buffering, HTTP/2 or HTTP/3 behavior, remote disconnects, multiple workers/replicas, real tool dispatch, and load-induced kernel/socket backpressure.
