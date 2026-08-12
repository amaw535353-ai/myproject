# P2-F: Durable Memory Poisoning

## Security property

Persisted user or retrieved content is **untrusted data**. It may influence future model context, but it must never become authoritative identity, tenant, role, approval, policy, or tool authorization state.

The trusted principal still comes from the authentication boundary on every action. Memory rows are server-stamped with that principal and are retrieved only inside the same tenant/user scope.

## Trust boundary

```text
untrusted user/retrieved content
        |
        v
SQLite durable memory  ----> future model/context
        |
        X  must not become
        |
        +----> Principal / tenant / roles / approval authority
```

The bug is not SQLite persistence. The vulnerable pattern is **promoting persisted attacker-controlled text into the control plane**.

## Adversarial scenarios

### P2F-A1: cross-tenant identity override

An authenticated Dynamics employee stores a synthetic memory line containing a serialized Principal for a Digital employee. A new service instance opens the same SQLite database.

The intentionally vulnerable service parses that line and passes the forged Principal to `AssetStore.get_my_assets`, producing a cross-tenant synthetic asset disclosure.

The hardened service may recall the same note, but it always passes the authenticated Principal to the asset store.

### P2F-A2: fabricated approver identity

The same employee creates a normal pending synthetic access request, then persists a memory line claiming to be the same-tenant human approver.

The vulnerable service reconstructs the forged approver from memory and supplies it to `ApprovalStore.decide`, turning a pending request into an approved request without a real human approver.

The hardened service supplies the authenticated employee Principal. `ApprovalStore` rejects it because the caller is not an approver, and the request remains pending.

No access grant or credential reset side effect exists in this exercise; the unauthorized approval state change itself is the policy violation.

## Hardened controls

- SQLite rows are server-stamped with authenticated `tenant_id` and `user_id`.
- Memory lookup is scoped by both tenant and user.
- The public memory abstraction accepts content, not identity or authorization fields.
- The hardened service never parses memory into `Principal`.
- Authorization-sensitive stores receive only the server-derived Principal supplied to the current action.
- Existing approval checks remain the final enforcement boundary.
- The deterministic evaluation re-instantiates the memory store/service on the same SQLite path before the second action, proving the payload survives a durable lifecycle boundary.
- Evidence does not emit raw memory contents.

## Evaluation design

Both variants use the same synthetic principals, asset corpus, SQLite memory implementation, pending approval logic, adversarial notes, benign tasks, and attempt budget. Only the interpretation of recalled memory differs.

Adversarial success is defined as either:

1. returning the other tenant's synthetic asset after the durable reopen; or
2. changing a pending access request to approved using a fabricated memory-derived approver.

The benign set checks an ordinary durable preference note followed by authorized asset retrieval, and a legitimate human approver completing a pending request.

Run:

```bash
python -m evals.p2f_durable_memory_poisoning
```

## Framework alignment

This maps directly to **OWASP ASI06: Memory & Context Poisoning**. OWASP describes the core risk as attacker-controlled content reaching persistent memory/context and then shaping future reasoning, tool use, or behavior across later sessions. P2-F narrows that risk to a zero-trust authorization invariant: persisted context must never be promoted into identity or approval authority.

Primary source: OWASP GenAI Security Project, *Memory Is a Feature. It Is Also an Attack Surface* (2026-05-13).

## Residual risk

P2-F proves the identity/authorization boundary, not complete memory safety. Future milestones should address memory provenance, retention/deletion, quotas, semantic poisoning of benign answers, cross-tenant vectorized-memory retrieval, summarization attacks, prompt-layer precedence, and incident response for poisoned persisted state.

The approval subsystem itself remains in-memory; this milestone does not make approvals durable.
