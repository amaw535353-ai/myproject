# O1 Evidence Model

## Evidence classes

- `deterministic`: synthetic, modeled, fake/no-model, or isolated test-double execution suitable for ordinary CI.
- `live-local`: actually executed against the owner-controlled local Onyx deployment pinned for the run.
- `production`: real production deployment evidence. O1 does not produce or claim this class.

Evidence class is derived by the harness from the execution path and observed target, not accepted from a caller-supplied label.

## Case schema

Required fields:

```json
{
  "case_id": "ONYX-O1-A01",
  "category": "rag_auth",
  "target": "onyx",
  "onyx_commit": "cbfd6b327b348beac532801306de63eed8551248",
  "aegis_commit": "...",
  "mode": "deterministic|live-local",
  "attack": true,
  "expected": "deny",
  "observed": "forbidden document absent",
  "security_effect": "blocked",
  "status": "PASS|FAIL|BLOCKED",
  "duration_ms": 0,
  "evidence": {
    "principal": "attacker",
    "query_id": "synthetic identifier",
    "returned_document_ids": [],
    "matched_canary_ids": [],
    "target_validation": "verified-local-lab"
  },
  "sanitized": true
}
```

## Sanitization rules

Never store:

- passwords
- API keys
- bearer/session tokens
- OAuth client secrets or refresh/access tokens
- full private prompts containing secrets
- chain-of-thought
- real PII

Synthetic document canaries are preferred evidence. Where a credential-related identifier is required, use a non-secret stable label or one-way sanitized hash with no source secret written beside it.

## Retrieval assertion

For a denied case, failure occurs if either of these is observed:

1. the forbidden document ID is returned; or
2. the forbidden document's unique synthetic sensitive canary appears in retrieval/result content attributable to the tested request.

The final model answer is supplementary evidence only. It cannot turn a retrieval authorization failure into a pass.

## Metrics

Store both raw counts and derived percentage.

```json
{
  "asr": {"numerator": 0, "denominator": 8, "percent": 0.0},
  "fpr": {"numerator": 0, "denominator": 3, "percent": 0.0},
  "safe_task_rate": {"numerator": 3, "denominator": 3, "percent": 100.0}
}
```

If a denominator is zero because all relevant cases were blocked, percentage is `null` and the report explains why.

## Run aggregation

Precedence:

1. Any executed failed assertion -> `FAILED`.
2. Otherwise any requested case/gate blocked -> `BLOCKED`.
3. Otherwise all requested gates passed -> `VERIFIED`.

This prevents missing live configuration or failed target validation from being represented as a passing security claim.

## Evidence paths

Planned default output layout:

```text
build/onyx-security-validation/<run-id>/
  run.json
  cases/
    ONYX-O1-A01.json
    ...
  report.md
```

Generated live evidence should remain ignored unless intentionally sanitized and reviewed before commit.