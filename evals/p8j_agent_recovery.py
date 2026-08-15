from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Callable
from types import SimpleNamespace

from aegis.agentic.recovery_security import (
    AgentRecoveryManifest,
    AgentRollbackRecoverySecurityAnalyzer,
    AgentRecoverySecurityRejected,
    CheckpointTrust,
    PersistenceState,
    RecoveryDecision,
    RecoveryMode,
)
from aegis.vulnerable.recovery_security import VulnerableDeclaredRecoverySafety
from evals.p8j_fixture import (
    AUTHORIZATION_IDS,
    CHECKPOINT_IDS,
    ITEM_IDS,
    RECOVERY_IDS,
    NOW,
    SAFE_TARGET_ITEMS,
    build_fixture,
    sha,
)

Mutator = Callable[[dict[str, object]], dict[str, object]]
CASES: list[tuple[str, Mutator]] = []


def _ns(obj: object, **changes):
    return SimpleNamespace(**{**vars(obj), **changes})


def _case(name: str):
    def register(fn: Mutator) -> Mutator:
        CASES.append((name, fn))
        return fn
    return register


def _replace_by_id(values: tuple[object, ...], attr: str, value_id: str, **changes) -> tuple[object, ...]:
    return tuple(replace(v, **changes) if str(getattr(v, attr)) == value_id else v for v in values)


def _rehash(f: dict[str, object], manifest: AgentRecoveryManifest) -> dict[str, object]:
    from aegis.agentic.recovery_security import agent_recovery_manifest_digest
    digest = agent_recovery_manifest_digest(manifest)
    return {
        **f,
        "manifest": manifest,
        "policy": replace(f["policy"], expected_graph_sha256=digest),
        "request": replace(f["request"], graph_sha256=digest),
    }


def _manifest_mutation(component: str, item_id: str, **changes) -> Mutator:
    def mutate(f: dict[str, object]) -> dict[str, object]:
        manifest = f["manifest"]
        values = getattr(manifest, component)
        attr = {
            "items": "item_id",
            "checkpoints": "checkpoint_id",
            "authorizations": "authorization_id",
            "recoveries": "recovery_id",
        }[component]
        new_values = _replace_by_id(values, attr, item_id, **changes)
        return _rehash(f, replace(manifest, **{component: new_values}))
    return mutate


for field, bad in (
    ("graph_id", "other-graph"),
    ("graph_version", "99"),
    ("graph_sha256", sha("wrong-graph")),
    ("p8b_assessment_evidence_sha256", sha("wrong-p8b")),
    ("p8i_assessment_evidence_sha256", sha("wrong-p8i")),
    ("p8h_assessment_evidence_sha256", sha("wrong-p8h")),
    ("evaluated_at_epoch", NOW + 10000),
):
    CASES.append((f"request-{field}-tamper", lambda f, field=field, bad=bad: {**f, "request": replace(f["request"], **{field: bad})}))

CASES.extend(
    [
        ("request-recovery-coverage-drop", lambda f: {**f, "request": replace(f["request"], recovery_ids=RECOVERY_IDS[:-1])}),
        ("declared-denied-lie", lambda f: {**f, "request": replace(f["request"], declared_denied_recovery_ids=("recovery-safe-resume",))}),
        ("declared-risk-lie", lambda f: {**f, "request": replace(f["request"], declared_risks_by_recovery={})}),
        ("declared-target-lie", lambda f: {**f, "request": replace(f["request"], declared_target_checkpoint_by_recovery={"recovery-safe-resume": "checkpoint-root"})}),
    ]
)

for name, key, digest in (
    ("p8b", "p8b", sha("bad-p8b")),
    ("p8i", "p8i", sha("bad-p8i")),
    ("p8h", "p8h", sha("bad-p8h")),
):
    CASES.append((f"upstream-{name}-digest", lambda f, key=key, digest=digest: {**f, key: _ns(f[key], assessment_evidence_sha256=digest)}))

CASES.extend(
    [
        ("upstream-p8b-verification-off", lambda f: {**f, "p8b": _ns(f["p8b"], exact_memory_graph_binding_verified=False)}),
        ("upstream-p8b-revocation-off", lambda f: {**f, "p8b": _ns(f["p8b"], revocation_and_supersession_enforced=False)}),
        ("upstream-p8b-caller-trust", lambda f: {**f, "p8b": _ns(f["p8b"], caller_declared_memory_safety_trusted=True)}),
        ("upstream-p8i-verification-off", lambda f: {**f, "p8i": _ns(f["p8i"], exact_artifact_graph_binding_verified=False)}),
        ("upstream-p8i-persistence-off", lambda f: {**f, "p8i": _ns(f["p8i"], sensitive_persistence_paths_checked=False)}),
        ("upstream-p8i-caller-trust", lambda f: {**f, "p8i": _ns(f["p8i"], caller_declared_artifact_safety_trusted=True)}),
        ("upstream-p8h-verification-off", lambda f: {**f, "p8h": _ns(f["p8h"], exact_state_transition_graph_binding_verified=False)}),
        ("upstream-p8h-rollback-check-off", lambda f: {**f, "p8h": _ns(f["p8h"], cancellation_and_rollback_races_checked=False)}),
        ("upstream-p8h-caller-trust", lambda f: {**f, "p8h": _ns(f["p8h"], caller_declared_state_safety_trusted=True)}),
        ("upstream-memory-denied", lambda f: {**f, "p8b": _ns(f["p8b"], writes=(_ns(f["p8b"].writes[0], decision="deny"),))}),
        ("upstream-artifact-denied", lambda f: {**f, "p8i": _ns(f["p8i"], actions=(_ns(f["p8i"].actions[0], decision="deny"), f["p8i"].actions[1]))}),
        ("upstream-state-denied", lambda f: {**f, "p8h": _ns(f["p8h"], transitions=(_ns(f["p8h"].transitions[0], decision="deny"), f["p8h"].transitions[1]))}),
        ("upstream-memory-provenance-missing", lambda f: {**f, "p8b": _ns(f["p8b"], writes=(), retrievals=())}),
        ("upstream-artifact-provenance-missing", lambda f: {**f, "p8i": _ns(f["p8i"], actions=(f["p8i"].actions[1],))}),
        ("upstream-state-provenance-missing", lambda f: {**f, "p8h": _ns(f["p8h"], transitions=())}),
    ]
)

CASES.extend(
    [
        ("manifest-schema-drift", lambda f: _rehash(f, replace(f["manifest"], schema_version="other"))),
        ("manifest-graph-id-drift", lambda f: _rehash(f, replace(f["manifest"], graph_id="other"))),
        ("manifest-version-drift", lambda f: _rehash(f, replace(f["manifest"], version="99"))),
        ("manifest-too-old", lambda f: _rehash(f, replace(f["manifest"], created_at_epoch=NOW - 200000))),
        ("manifest-future", lambda f: _rehash(f, replace(f["manifest"], created_at_epoch=NOW + 100))),
        ("manifest-item-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], items=f["manifest"].items[:-1]))),
        ("manifest-checkpoint-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], checkpoints=f["manifest"].checkpoints[:-1]))),
        ("manifest-auth-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], authorizations=f["manifest"].authorizations[:-1]))),
        ("manifest-recovery-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], recoveries=f["manifest"].recoveries[:-1]))),
    ]
)
for item_id in ITEM_IDS:
    CASES.append((f"item-owner-{item_id}", _manifest_mutation("items", item_id, owner_id="attacker")))
for cp_id in CHECKPOINT_IDS:
    CASES.append((f"checkpoint-owner-{cp_id}", _manifest_mutation("checkpoints", cp_id, owner_id="attacker")))
for auth_id in AUTHORIZATION_IDS:
    CASES.append((f"authorization-owner-{auth_id}", _manifest_mutation("authorizations", auth_id, owner_id="attacker")))
for recovery_id in RECOVERY_IDS:
    CASES.append((f"recovery-owner-{recovery_id}", _manifest_mutation("recoveries", recovery_id, owner_id="attacker")))

for item_id in SAFE_TARGET_ITEMS:
    CASES.append((f"item-hash-drift-{item_id}", _manifest_mutation("items", item_id, content_sha256=sha(f"tampered-{item_id}"))))
    CASES.append((f"item-tenant-drift-{item_id}", _manifest_mutation("items", item_id, tenant_id="tenant-B")))
for state, item_id in (
    (PersistenceState.REVOKED, "item-memory-current"),
    (PersistenceState.QUARANTINED, "item-artifact-config"),
    (PersistenceState.SUPERSEDED, "item-message-safe"),
):
    CASES.append((f"item-state-{state.value}-{item_id}", _manifest_mutation("items", item_id, persistence_state=state)))

CASES.extend(
    [
        ("checkpoint-parent-missing", _manifest_mutation("checkpoints", "checkpoint-safe-2", parent_checkpoint_id="missing")),
        ("checkpoint-cycle", _manifest_mutation("checkpoints", "checkpoint-root", parent_checkpoint_id="checkpoint-safe-2")),
        ("checkpoint-generation-regression", _manifest_mutation("checkpoints", "checkpoint-safe-2", generation=0)),
        ("checkpoint-state-hash-drift", _manifest_mutation("checkpoints", "checkpoint-safe-2", state_sha256=sha("tampered-cp"))),
        ("checkpoint-trust-compromised", _manifest_mutation("checkpoints", "checkpoint-safe-2", trust=CheckpointTrust.COMPROMISED)),
        ("checkpoint-expired", _manifest_mutation("checkpoints", "checkpoint-safe-2", expires_at_epoch=NOW - 1)),
        ("checkpoint-unknown-item", _manifest_mutation("checkpoints", "checkpoint-safe-2", item_ids=SAFE_TARGET_ITEMS + ("missing-item",))),
        ("checkpoint-future-item", _manifest_mutation("items", "item-artifact-config", generation=3)),
    ]
)

for recovery_id in RECOVERY_IDS:
    CASES.extend(
        [
            (f"recovery-tenant-{recovery_id}", _manifest_mutation("recoveries", recovery_id, tenant_id="tenant-B")),
            (f"recovery-session-{recovery_id}", _manifest_mutation("recoveries", recovery_id, session_id="session-b")),
            (f"recovery-principal-{recovery_id}", _manifest_mutation("recoveries", recovery_id, original_principal_id="user-b")),
            (f"recovery-source-hash-{recovery_id}", _manifest_mutation("recoveries", recovery_id, expected_source_state_sha256=sha("wrong-source"))),
            (f"recovery-target-hash-{recovery_id}", _manifest_mutation("recoveries", recovery_id, expected_target_state_sha256=sha("wrong-target"))),
            (f"recovery-restore-drop-{recovery_id}", _manifest_mutation("recoveries", recovery_id, restore_item_ids=SAFE_TARGET_ITEMS[:-1])),
            (f"recovery-restore-credential-{recovery_id}", _manifest_mutation("recoveries", recovery_id, restore_item_ids=SAFE_TARGET_ITEMS + ("item-credential-stale",))),
            (f"recovery-restore-rejected-message-{recovery_id}", _manifest_mutation("recoveries", recovery_id, restore_item_ids=SAFE_TARGET_ITEMS + ("item-message-rejected",))),
            (f"recovery-restore-poisoned-artifact-{recovery_id}", _manifest_mutation("recoveries", recovery_id, restore_item_ids=SAFE_TARGET_ITEMS + ("item-artifact-poisoned",))),
            (f"recovery-overlap-quarantine-{recovery_id}", _manifest_mutation("recoveries", recovery_id, quarantine_item_ids=("item-memory-current",))),
        ]
    )

CASES.extend(
    [
        ("resume-compromised", _manifest_mutation("recoveries", "recovery-safe-resume", source_checkpoint_id="checkpoint-compromised", target_checkpoint_id="checkpoint-compromised", expected_source_state_sha256=sha("checkpoint-compromised"), expected_target_state_sha256=sha("checkpoint-compromised"), restore_item_ids=SAFE_TARGET_ITEMS + ("item-message-rejected", "item-credential-stale", "item-artifact-poisoned"))),
        ("resume-target-mismatch", _manifest_mutation("recoveries", "recovery-safe-resume", target_checkpoint_id="checkpoint-safe-1", expected_target_state_sha256=sha("checkpoint-safe-1"), restore_item_ids=("item-state-task", "item-memory-current"))),
        ("rollback-past-floor", _manifest_mutation("recoveries", "recovery-compromise-rollback", target_checkpoint_id="checkpoint-root", expected_target_state_sha256=sha("checkpoint-root"), restore_item_ids=("item-state-task",), quarantine_item_ids=("item-message-rejected", "item-artifact-poisoned", "item-memory-current", "item-artifact-config", "item-policy-state", "item-message-safe"), revoke_item_ids=("item-credential-stale",))),
        ("rollback-target-newer", _manifest_mutation("recoveries", "recovery-compromise-rollback", source_checkpoint_id="checkpoint-safe-1", target_checkpoint_id="checkpoint-safe-2", expected_source_state_sha256=sha("checkpoint-safe-1"), expected_target_state_sha256=sha("checkpoint-safe-2"), quarantine_item_ids=(), revoke_item_ids=())),
        ("rollback-missing-quarantine", _manifest_mutation("recoveries", "recovery-compromise-rollback", quarantine_item_ids=(), revoke_item_ids=("item-credential-stale",))),
        ("rollback-missing-revocation", _manifest_mutation("recoveries", "recovery-compromise-rollback", revoke_item_ids=())),
        ("rollback-no-authorization", _manifest_mutation("recoveries", "recovery-compromise-rollback", authorization_id=None)),
        ("restore-no-authorization", _manifest_mutation("recoveries", "recovery-safe-restore", authorization_id=None)),
        ("rollback-issued-before-target", _manifest_mutation("recoveries", "recovery-compromise-rollback", issued_at_epoch=NOW - 1000)),
        ("restore-issued-future", _manifest_mutation("recoveries", "recovery-safe-restore", issued_at_epoch=NOW + 100)),
    ]
)

CASES.extend(
    [
        ("auth-rollback-actor", _manifest_mutation("authorizations", "authorization-rollback", actor_agent_id="agent-other")),
        ("auth-rollback-principal", _manifest_mutation("authorizations", "authorization-rollback", original_principal_id="user-b")),
        ("auth-rollback-tenant", _manifest_mutation("authorizations", "authorization-rollback", tenant_id="tenant-B")),
        ("auth-rollback-mode", _manifest_mutation("authorizations", "authorization-rollback", allowed_modes=frozenset({RecoveryMode.RESTORE}))),
        ("auth-rollback-expired", _manifest_mutation("authorizations", "authorization-rollback", expires_at_epoch=NOW - 1)),
        ("auth-rollback-item-scope", _manifest_mutation("authorizations", "authorization-rollback", approved_item_ids=frozenset(SAFE_TARGET_ITEMS))),
        ("auth-rollback-depth", _manifest_mutation("authorizations", "authorization-rollback", max_rollback_generations=0)),
        ("auth-rollback-destructive-off", _manifest_mutation("authorizations", "authorization-rollback", destructive_allowed=False)),
        ("auth-restore-actor", _manifest_mutation("authorizations", "authorization-restore", actor_agent_id="agent-other")),
        ("auth-restore-principal", _manifest_mutation("authorizations", "authorization-restore", original_principal_id="user-b")),
        ("auth-restore-tenant", _manifest_mutation("authorizations", "authorization-restore", tenant_id="tenant-B")),
        ("auth-restore-mode", _manifest_mutation("authorizations", "authorization-restore", allowed_modes=frozenset({RecoveryMode.ROLLBACK}))),
        ("auth-restore-expired", _manifest_mutation("authorizations", "authorization-restore", expires_at_epoch=NOW - 1)),
        ("auth-restore-item-scope", _manifest_mutation("authorizations", "authorization-restore", approved_item_ids=frozenset(SAFE_TARGET_ITEMS[:-1]))),
    ]
)

EXPECTED_ADVERSARIAL_CASES = len(CASES)


def _hardened_accepts(f: dict[str, object]) -> bool:
    try:
        assessment = AgentRollbackRecoverySecurityAnalyzer(f["policy"]).evaluate(
            f["request"], f["manifest"], f["p8b"], f["p8i"], f["p8h"]
        )
        return assessment.denied_recovery_count == 0
    except AgentRecoverySecurityRejected:
        return False


def run() -> dict[str, object]:
    vulnerable_successes = 0
    hardened_successes = 0
    rows: list[dict[str, object]] = []
    for case_id, mutator in CASES:
        base = build_fixture()
        attacked = mutator(base)
        weak = VulnerableDeclaredRecoverySafety().accepts()
        hard = _hardened_accepts(attacked)
        vulnerable_successes += int(weak)
        hardened_successes += int(hard)
        rows.append({"case_id": case_id, "vulnerable_accepted": weak, "hardened_accepted": hard})

    false_positives = 0
    safe_successes = 0
    benign: list[dict[str, object]] = []
    for case_id in ("clean-resume", "clean-compromise-rollback", "clean-restore"):
        fixture = build_fixture()
        try:
            assessment = AgentRollbackRecoverySecurityAnalyzer(fixture["policy"]).evaluate(
                fixture["request"], fixture["manifest"], fixture["p8b"], fixture["p8i"], fixture["p8h"]
            )
            ok = assessment.denied_recovery_count == 0 and assessment.allowed_recovery_count == 3
        except AgentRecoverySecurityRejected:
            ok = False
        false_positives += int(not ok)
        safe_successes += int(ok)
        benign.append({"case_id": case_id, "accepted": ok})

    fixture = build_fixture()
    dataset_sha = hashlib.sha256(
        json.dumps([case_id for case_id, _ in CASES], separators=(",", ":")).encode()
    ).hexdigest()
    fixture_doc = {
        "graph_sha256": fixture["request"].graph_sha256,
        "item_ids": list(ITEM_IDS),
        "checkpoint_ids": list(CHECKPOINT_IDS),
        "authorization_ids": list(AUTHORIZATION_IDS),
        "recovery_ids": list(RECOVERY_IDS),
    }
    fixture_sha = hashlib.sha256(
        json.dumps(fixture_doc, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    clean = AgentRollbackRecoverySecurityAnalyzer(fixture["policy"]).evaluate(
        fixture["request"], fixture["manifest"], fixture["p8b"], fixture["p8i"], fixture["p8h"]
    )
    return {
        "adversarial_cases": len(CASES),
        "vulnerable_asr": f"{vulnerable_successes}/{len(CASES)}",
        "hardened_asr": f"{hardened_successes}/{len(CASES)}",
        "hardened_fpr": f"{false_positives}/3",
        "safe_task_rate": f"{safe_successes}/3",
        "graph_sha256": fixture["request"].graph_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "clean_assessment_sha256": clean.assessment_evidence_sha256,
        "cases": rows,
        "benign": benign,
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    assert result["vulnerable_asr"] == f"{EXPECTED_ADVERSARIAL_CASES}/{EXPECTED_ADVERSARIAL_CASES}"
    assert result["hardened_asr"] == f"0/{EXPECTED_ADVERSARIAL_CASES}"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
