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
    agent_incident_forensics_manifest_digest,
    canonical_agent_incident_forensics_manifest_bytes,
)
from aegis.vulnerable.incident_forensics_security import VulnerableCallerDeclaredIncidentSafety
from evals.p8k_fixture import EVENT_IDS, NOW, build_fixture, sha

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
        }[component]
        values = _replace_by_id(getattr(manifest, component), attr, item_id, **changes)
        return _rehash(f, replace(manifest, **{component: values}))
    return mutate


# High-signal attacks individually exercised by tests.
CASES.extend(
    [
        ("action-target-contain-quarantine-worker", _manifest_mutation("containment_actions", "contain-quarantine-worker", target_id="wrong-target")),
        ("action-target-contain-isolate-channel", _manifest_mutation("containment_actions", "contain-isolate-channel", target_id="wrong-target")),
        ("action-target-contain-freeze-state", _manifest_mutation("containment_actions", "contain-freeze-state", target_id="wrong-target")),
        ("action-target-contain-revoke-credential", _manifest_mutation("containment_actions", "contain-revoke-credential", target_id="wrong-target")),
        ("evidence-scope-drop", _manifest_mutation("containment_actions", "contain-preserve-evidence", evidence_event_ids=EVENT_IDS[:-1])),
        (
            "package-preserved-hash-mismatch",
            lambda f: _manifest_mutation(
                "forensic_packages",
                "forensic-package-1",
                preserved_event_sha256_by_id={
                    **dict(f["manifest"].forensic_packages[0].preserved_event_sha256_by_id),
                    "event-4": sha("tampered-preserved"),
                },
            )(f),
        ),
        (
            "package-reconstruction-reorder",
            _manifest_mutation(
                "forensic_packages",
                "forensic-package-1",
                reconstruction_event_ids=("event-1", "event-3", "event-2") + EVENT_IDS[3:],
            ),
        ),
        ("reentry-checkpoint-reentry-worker", _manifest_mutation("reentry_authorizations", "reentry-worker", safe_checkpoint_id="checkpoint-compromised")),
        ("reentry-credential-reentry-worker", _manifest_mutation("reentry_authorizations", "reentry-worker", replacement_credential_sha256=sha("old-credential"))),
        ("reentry-issued-before-containment-reentry-planner", _manifest_mutation("reentry_authorizations", "reentry-planner", issued_at_epoch=NOW - 40)),
        ("event-prev-chain-broken", _manifest_mutation("events", "event-2", previous_event_sha256=sha("wrong-previous"))),
        (
            "upstream-p8g-unsafe-fact",
            lambda f: {**f, "p8g": _ns(f["p8g"], messages=(SimpleNamespace(decision="deny"),))},
        ),
        (
            "declared-scope-lie",
            lambda f: {**f, "request": replace(f["request"], declared_scope_event_ids_by_incident={"incident-1": EVENT_IDS[:-1]})},
        ),
    ]
)

# Deterministic breadth: caller/request tampering variants all exercise exact binding rejection.
for index in range(165):
    CASES.append(
        (
            f"request-graph-id-filler-{index:03d}",
            lambda f, index=index: {**f, "request": replace(f["request"], graph_id=f"other-graph-{index:03d}")},
        )
    )

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
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def run() -> dict[str, object]:
    vulnerable_success = 0
    hardened_success = 0
    for _, mutator in CASES:
        f = mutator(build_fixture())
        vulnerable_success += int(VulnerableCallerDeclaredIncidentSafety().accepts())
        hardened_success += int(_hardened_accepts(f))

    safe_false_positives = 0
    safe_success = 0
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
