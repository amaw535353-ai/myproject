# P3-C default surface posture

## Security property

The default AegisDesk API and agent tool catalog do not include the P2-E network fetch, P2-I artifact ingestion, or P2-J browser-navigation lab capabilities. Those components remain available only for deterministic local security evaluation until a future integration explicitly reviews and enables them.

The default agent tool catalog is an exact server-owned set. A catalog change fails the P3-C guard until the reviewed policy is updated. Phase-3 evaluation also inventories API routes and rejects a default route that matches the non-default surface markers.

## Trust boundary

The user and model cannot turn a lab component into a default capability. Default capability exposure is controlled by application code and the server-owned posture policy, not prompt text, retrieved content, MCP metadata, or client-supplied configuration.

## Evaluation

P3-C uses three synthetic surface cases and two benign default-tool cases. The implicit baseline treats any present lab implementation as reachable by default. The hardened posture keeps all three non-default while preserving the two benign tools. No real network request, artifact processing, or browser navigation occurs in the P3-C evaluation.

Expected metrics are baseline ASR 3/3, hardened ASR 0/3, hardened FPR 0/2, and hardened SafeTaskRate 2/2.

## Limitations

This milestone deliberately does not promote the lab network, artifact, or browser components to production. If one of those capabilities is later required, it needs an explicit integration milestone that preserves its Phase-2 control boundary, adds authentication and authorization appropriate to the surface, and updates the reviewed default posture. CI posture checks are not a substitute for operating-system sandboxing or network egress controls.
