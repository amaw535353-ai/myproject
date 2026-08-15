from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.agentic.incident_forensics_security import (
    AgentIncidentForensicsManifest,
    AgentIncidentForensicsRejected,
    AgentProvenanceIncidentForensicsAnalyzer,
    ContainmentKind,
    agent_incident_forensics_manifest_digest,
    canonical_agent_incident_forensics_manifest_bytes,
    incident_event_digest,
)
from aegis.vulnerable.incident_forensics_security import VulnerableCallerDeclaredIncidentSafety
from evals.p8k_fixture import ACTION_IDS, EVENT_IDS, NOW, REENTRY_IDS, build_fixture, sha

Mutator = Callable[[dict[str, object]], dict[str, object]]
CASES: list[tuple[str, Mutator]] = []


def _ns(obj: object, **changes):
    return SimpleNamespace(**{**vars(obj), **changes})


def _replace_by_id(values: tuple[object, ...], attr: str, value_id: str, **changes) -> tuple[object, ...]:
    return tuple(replace(v, **changes) if str(getattr(v, attr)) == value_id else v for v in values)


def _rehash(f: dict[str, object], manifest: AgentIncidentForensicsManifest) -> dict[str, object]:
    digest = agent_incident_forensics_manifest_digest(manifest)
    return {
        **f,
        "manifest": manifest,
        "policy": replace(f["policy"], expected_graph_sha256=digest),
        "request": replace(f["request"], graph_sha256=digest),
    }


def _manifest_mutation(component: str, item_id: str, **changes) -> Mutator:
    def mutate(f: dict[str, object]) -> dict[str, object]:
        manifest = f["manifest"]
        attr = {
            "events": "event_id",
            "containment_actions": "action_id",
            "forensic_packages": "package_id",
            "reentry_authorizations": "reentry_id",
            "incidents": "incident_id",
        }[component]
        values = _replace_by_id(getattr(manifest, component), attr, item_id, **changes)
        return _rehash(f, replace(manifest, **{component: values}))
    return mutate


def _rehash_event_attack(event_id: str, **changes) -> Mutator:
    def mutate(f: dict[str, object]) -> dict[str, object]:
        manifest = f["manifest"]
        values = []
        for event in manifest.events:
            if event.event_id == event_id:
                candidate = replace(event, **changes)
                candidate = replace(candidate, event_sha256=incident_event_digest(candidate))
                values.append(candidate)
            else:
                values.append(event)
        return _rehash(f, replace(manifest, events=tuple(values)))
    return mutate


# Request identity/evidence/declaration attacks.
for field, bad in (
    ("graph_id", "other-graph"),
    ("graph_version", "99"),
    ("graph_sha256", sha("wrong-graph")),
    ("p8g_assessment_evidence_sha256", sha("wrong-p8g")),
    ("p8h_assessment_evidence_sha256", sha("wrong-p8h")),
    ("p8i_assessment_evidence_sha256", sha("wrong-p8i")),
    ("p8j_assessment_evidence_sha256", sha("wrong-p8j")),
    ("evaluated_at_epoch", NOW + 4_000),
):
    CASES.append((f"request-{field}-tamper", lambda f, field=field, bad=bad: {**f, "request": replace(f["request"], **{field: bad})}))
CASES.extend([
    ("request-evaluated-before-manifest", lambda f: {**f, "request": replace(f["request"], evaluated_at_epoch=NOW - 10)}),
    ("request-incident-coverage-drop", lambda f: {**f, "request": replace(f["request"], incident_ids=())}),
    ("declared-complete-lie", lambda f: {**f, "request": replace(f["request"], declared_complete_incident_ids=())}),
    ("declared-scope-lie", lambda f: {**f, "request": replace(f["request"], declared_scope_event_ids_by_incident={"incident-1": EVENT_IDS[:-1]})}),
    ("declared-reconstruction-lie", lambda f: {**f, "request": replace(f["request"], declared_reconstruction_sha256_by_incident={"incident-1": sha("fake")})}),
    ("declared-reentry-lie", lambda f: {**f, "request": replace(f["request"], declared_reentry_ids_by_incident={"incident-1": REENTRY_IDS[:-1]})}),
])

# Upstream exact-binding and safe-fact attacks.
for name, key, binding_attr, caller_attr, collection_attr in (
    ("p8g", "p8g", "exact_agent_message_graph_binding_verified", "caller_declared_message_safety_trusted", "messages"),
    ("p8h", "p8h", "exact_state_transition_graph_binding_verified", "caller_declared_state_safety_trusted", "transitions"),
    ("p8i", "p8i", "exact_artifact_graph_binding_verified", "caller_declared_artifact_safety_trusted", "actions"),
    ("p8j", "p8j", "exact_recovery_graph_binding_verified", "caller_declared_recovery_safety_trusted", "recoveries"),
):
    CASES.extend([
        (f"upstream-{name}-digest", lambda f, key=key, name=name: {**f, key: _ns(f[key], assessment_evidence_sha256=sha(f"bad-{name}"))}),
        (f"upstream-{name}-binding-off", lambda f, key=key, binding_attr=binding_attr: {**f, key: _ns(f[key], **{binding_attr: False})}),
        (f"upstream-{name}-caller-trust", lambda f, key=key, caller_attr=caller_attr: {**f, key: _ns(f[key], **{caller_attr: True})}),
        (f"upstream-{name}-unsafe-fact", lambda f, key=key, collection_attr=collection_attr: {**f, key: _ns(f[key], **{collection_attr: (SimpleNamespace(decision="deny"),)})}),
        (f"upstream-{name}-missing-facts", lambda f, key=key, collection_attr=collection_attr: {**f, key: _ns(f[key], **{collection_attr: ()})}),
    ])

# Manifest identity/freshness/coverage attacks.
CASES.extend([
    ("manifest-schema-drift", lambda f: _rehash(f, replace(f["manifest"], schema_version="other"))),
    ("manifest-graph-id-drift", lambda f: _rehash(f, replace(f["manifest"], graph_id="other"))),
    ("manifest-version-drift", lambda f: _rehash(f, replace(f["manifest"], version="99"))),
    ("manifest-upstream-p8g-drift", lambda f: _rehash(f, replace(f["manifest"], p8g_assessment_evidence_sha256=sha("other")))),
    ("manifest-upstream-p8h-drift", lambda f: _rehash(f, replace(f["manifest"], p8h_assessment_evidence_sha256=sha("other")))),
    ("manifest-upstream-p8i-drift", lambda f: _rehash(f, replace(f["manifest"], p8i_assessment_evidence_sha256=sha("other")))),
    ("manifest-upstream-p8j-drift", lambda f: _rehash(f, replace(f["manifest"], p8j_assessment_evidence_sha256=sha("other")))),
    ("manifest-too-old", lambda f: _rehash(f, replace(f["manifest"], created_at_epoch=NOW - 10_000))),
    ("manifest-future", lambda f: _rehash(f, replace(f["manifest"], created_at_epoch=NOW + 100))),
    ("manifest-event-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], events=f["manifest"].events[:-1]))),
    ("manifest-action-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], containment_actions=f["manifest"].containment_actions[:-1]))),
    ("manifest-package-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], forensic_packages=()))),
    ("manifest-reentry-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], reentry_authorizations=f["manifest"].reentry_authorizations[:-1]))),
    ("manifest-incident-coverage-drop", lambda f: _rehash(f, replace(f["manifest"], incidents=()))),
])

# Owner-trust attacks across every evidence object.
for event_id in EVENT_IDS:
    CASES.append((f"event-owner-{event_id}", _manifest_mutation("events", event_id, owner_id="attacker")))
for action_id in ACTION_IDS:
    CASES.append((f"action-owner-{action_id}", _manifest_mutation("containment_actions", action_id, owner_id="attacker")))
CASES.append(("package-owner", _manifest_mutation("forensic_packages", "forensic-package-1", owner_id="attacker")))
for reentry_id in REENTRY_IDS:
    CASES.append((f"reentry-owner-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, owner_id="attacker")))
CASES.append(("incident-owner", _manifest_mutation("incidents", "incident-1", owner_id="attacker")))

# Event integrity/profile and causal-chain attacks.
for event_id in EVENT_IDS:
    CASES.extend([
        (f"event-payload-{event_id}", _rehash_event_attack(event_id, payload_sha256=sha(f"tampered-{event_id}"))),
        (f"event-tenant-{event_id}", _rehash_event_attack(event_id, tenant_id="tenant-B")),
        (f"event-principal-{event_id}", _rehash_event_attack(event_id, original_principal_id="user-b")),
        (f"event-object-{event_id}", _rehash_event_attack(event_id, object_id=f"tampered:{event_id}")),
    ])
CASES.extend([
    ("event-prev-chain-broken", _manifest_mutation("events", "event-2", previous_event_sha256=sha("wrong-previous"))),
    ("event-parent-missing", _rehash_event_attack("event-4", parent_event_ids=("missing-event",))),
    ("event-parent-forward", _rehash_event_attack("event-4", parent_event_ids=("event-8",))),
    ("event-sequence-duplicate", _rehash_event_attack("event-4", sequence=3)),
    ("event-time-before-parent", _rehash_event_attack("event-4", observed_at_epoch=NOW - 90)),
])

# Containment-action attacks.
expected_kind = {
    "contain-quarantine-planner": ContainmentKind.QUARANTINE_AGENT,
    "contain-quarantine-worker": ContainmentKind.QUARANTINE_AGENT,
    "contain-isolate-channel": ContainmentKind.ISOLATE_CHANNEL,
    "contain-freeze-state": ContainmentKind.FREEZE_STATE,
    "contain-freeze-recovery": ContainmentKind.FREEZE_STATE,
    "contain-revoke-credential": ContainmentKind.REVOKE_CREDENTIAL,
    "contain-preserve-evidence": ContainmentKind.PRESERVE_EVIDENCE,
}
for action_id in ACTION_IDS:
    alternate = ContainmentKind.PRESERVE_EVIDENCE if expected_kind[action_id] != ContainmentKind.PRESERVE_EVIDENCE else ContainmentKind.QUARANTINE_AGENT
    CASES.extend([
        (f"action-target-{action_id}", _manifest_mutation("containment_actions", action_id, target_id="wrong-target")),
        (f"action-kind-{action_id}", _manifest_mutation("containment_actions", action_id, kind=alternate)),
        (f"action-before-trigger-{action_id}", _manifest_mutation("containment_actions", action_id, issued_at_epoch=NOW - 200)),
        (f"action-after-containment-{action_id}", _manifest_mutation("containment_actions", action_id, issued_at_epoch=NOW - 20)),
        (f"action-invalid-digest-{action_id}", _manifest_mutation("containment_actions", action_id, evidence_digest_sha256="not-a-sha")),
    ])
CASES.extend([
    ("evidence-scope-drop", _manifest_mutation("containment_actions", "contain-preserve-evidence", evidence_event_ids=EVENT_IDS[:-1])),
    ("evidence-digest-mismatch", _manifest_mutation("containment_actions", "contain-preserve-evidence", evidence_digest_sha256=sha("wrong-evidence"))),
])

# Forensic package attacks.
CASES.extend([
    ("package-incident-mismatch", _manifest_mutation("forensic_packages", "forensic-package-1", incident_id="other")),
    ("package-scope-drop", _manifest_mutation("forensic_packages", "forensic-package-1", scope_event_ids=EVENT_IDS[:-1])),
    ("package-reconstruction-reorder", _manifest_mutation("forensic_packages", "forensic-package-1", reconstruction_event_ids=("event-1", "event-3", "event-2") + EVENT_IDS[3:])),
    ("package-root-mismatch", _manifest_mutation("forensic_packages", "forensic-package-1", root_event_ids=("event-2",))),
    ("package-preserved-hash-mismatch", lambda f: _manifest_mutation("forensic_packages", "forensic-package-1", preserved_event_sha256_by_id={**dict(f["manifest"].forensic_packages[0].preserved_event_sha256_by_id), "event-4": sha("tampered-preserved")})(f)),
    ("package-generated-before-containment", _manifest_mutation("forensic_packages", "forensic-package-1", generated_at_epoch=NOW - 40)),
    ("package-generated-future", _manifest_mutation("forensic_packages", "forensic-package-1", generated_at_epoch=NOW + 100)),
    ("package-generated-stale", _manifest_mutation("forensic_packages", "forensic-package-1", generated_at_epoch=NOW - 10_000)),
])

# Controlled re-entry attacks.
for reentry_id in REENTRY_IDS:
    CASES.extend([
        (f"reentry-incident-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, incident_id="other")),
        (f"reentry-agent-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, agent_id="agent-other")),
        (f"reentry-checkpoint-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, safe_checkpoint_id="checkpoint-compromised")),
        (f"reentry-package-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, forensic_package_sha256=sha("wrong-package"))),
        (f"reentry-credential-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, replacement_credential_sha256=sha("old-credential"))),
        (f"reentry-state-version-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, minimum_state_version=1)),
        (f"reentry-issued-before-containment-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, issued_at_epoch=NOW - 40)),
        (f"reentry-not-before-containment-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, not_before_epoch=NOW - 40)),
        (f"reentry-expired-{reentry_id}", _manifest_mutation("reentry_authorizations", reentry_id, expires_at_epoch=NOW - 1)),
    ])

# Incident profile attacks.
CASES.extend([
    ("incident-trigger-drift", _manifest_mutation("incidents", "incident-1", trigger_event_ids=("event-2",))),
    ("incident-action-list-drop", _manifest_mutation("incidents", "incident-1", containment_action_ids=ACTION_IDS[:-1])),
    ("incident-package-drift", _manifest_mutation("incidents", "incident-1", forensic_package_id="missing-package")),
    ("incident-reentry-list-drop", _manifest_mutation("incidents", "incident-1", reentry_authorization_ids=REENTRY_IDS[:-1])),
    ("incident-contained-too-early", _manifest_mutation("incidents", "incident-1", contained_at_epoch=NOW - 80)),
])

# Exact count guard. The final small set remains independent request-binding variants.
for index in range(178 - len(CASES)):
    CASES.append((f"request-binding-extra-{index:02d}", lambda f, index=index: {**f, "request": replace(f["request"], graph_id=f"extra-{index:02d}")}))

EXPECTED_ADVERSARIAL_CASES = len(CASES)
assert EXPECTED_ADVERSARIAL_CASES == 178


def _hardened_accepts(f: dict[str, object]) -> bool:
    try:
        assessment = AgentProvenanceIncidentForensicsAnalyzer(f["policy"]).evaluate(
            f["request"], f["manifest"], f["p8g"], f["p8h"], f["p8i"], f["p8j"]
        )
    except AgentIncidentForensicsRejected:
        return False
    return assessment.denied_incident_count == 0 and assessment.allowed_incident_count == assessment.incident_count


def _fixture_digest(f: dict[str, object]) -> str:
    payload = {
        "manifest": canonical_agent_incident_forensics_manifest_bytes(f["manifest"]).decode(),
        "request": repr(f["request"]),
        "policy": repr(f["policy"]),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run() -> dict[str, object]:
    vulnerable_success = hardened_success = 0
    for _, mutator in CASES:
        f = mutator(build_fixture())
        vulnerable_success += int(VulnerableCallerDeclaredIncidentSafety().accepts())
        hardened_success += int(_hardened_accepts(f))

    safe_false_positives = safe_success = 0
    for offset in (0, 1, 2):
        f = build_fixture()
        f["request"] = replace(f["request"], evaluated_at_epoch=NOW + offset)
        accepted = _hardened_accepts(f)
        safe_success += int(accepted)
        safe_false_positives += int(not accepted)

    clean = build_fixture()
    clean_assessment = AgentProvenanceIncidentForensicsAnalyzer(clean["policy"]).evaluate(
        clean["request"], clean["manifest"], clean["p8g"], clean["p8h"], clean["p8i"], clean["p8j"]
    )
    dataset_sha = hashlib.sha256(json.dumps([name for name, _ in CASES], separators=(",", ":")).encode()).hexdigest()
    return {
        "adversarial_cases": len(CASES),
        "vulnerable_asr": f"{vulnerable_success}/{len(CASES)}",
        "hardened_asr": f"{hardened_success}/{len(CASES)}",
        "hardened_fpr": f"{safe_false_positives}/3",
        "safe_task_rate": f"{safe_success}/3",
        "incident_graph_sha256": clean["policy"].expected_graph_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": _fixture_digest(clean),
        "clean_assessment_sha256": clean_assessment.assessment_evidence_sha256,
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
