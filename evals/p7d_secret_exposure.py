from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Callable

from aegis.architecture.secrets_exposure import (
    ExposureScope,
    ExposureSurfaceType,
    SecretExposureRejected,
    SecretKind,
    SecretScope,
    SecretSensitivity,
    SecretTransferChannel,
    SecretsCredentialTrustRootExposureAnalyzer,
    canonical_secret_exposure_manifest_bytes,
    secret_exposure_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus
from aegis.vulnerable.secret_exposure import VulnerableSecretExposureReporter

from .p7d_fixture import *


Mutation = Callable[[dict[str, object]], dict[str, object]]


def _hardened(fixture: dict[str, object]):
    return SecretsCredentialTrustRootExposureAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["architecture"],
        fixture["p7a"],
        fixture["p7b"],
        fixture["p7c"],
        fixture["posture"],
    )


def _replace_manifest(fixture: dict[str, object], manifest_value) -> dict[str, object]:
    fixture["manifest"] = manifest_value
    return fixture


def _surface(fixture, surface_id, **changes):
    return _replace_manifest(fixture, replace_surface(fixture["manifest"], surface_id, **changes))


def _secret(fixture, secret_id, **changes):
    return _replace_manifest(fixture, replace_secret(fixture["manifest"], secret_id, **changes))


def _edge(fixture, edge_id, **changes):
    return _replace_manifest(fixture, replace_edge(fixture["manifest"], edge_id, **changes))


def _repin(fixture: dict[str, object]) -> dict[str, object]:
    return repin_manifest(fixture, fixture["manifest"])


def _mutate_posture_status_summary(fixture: dict[str, object]) -> dict[str, object]:
    fixture["posture"] = replace(fixture["posture"], satisfied_control_ids=())
    return fixture


def _duplicate_control(fixture: dict[str, object]) -> dict[str, object]:
    assessments = fixture["posture"].assessments
    fixture["posture"] = replace(fixture["posture"], assessments=assessments + (assessments[0],), control_count=len(assessments) + 1)
    return fixture


def _root_external_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _edge(fixture, EDGE_ROOT_ARTIFACT, target_surface_id=SURFACE_EXTERNAL, channel=SecretTransferChannel.LOGGING, plaintext_exposure=True, persistent_copy=True)
    fixture = repin_manifest(fixture, fixture["manifest"], repin_structure=True)
    return fixture


def _unknown_control_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _edge(fixture, EDGE_BUILD_ARTIFACT, required_control_ids=("CTRL-UNKNOWN",))
    return repin_manifest(fixture, fixture["manifest"], repin_structure=True)


def _unknown_flow_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _edge(fixture, EDGE_RUNTIME, via_flow_ids=("flow-does-not-exist",))
    return repin_manifest(fixture, fixture["manifest"], repin_structure=True)


def _route_control_absent_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _edge(fixture, EDGE_RUNTIME, required_control_ids=(CTRL_EGRESS_FILTER,))
    return repin_manifest(fixture, fixture["manifest"], repin_structure=True)


def _rotation_overdue_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _secret(fixture, SECRET_BUILD, rotated_at_epoch=EVALUATION_EPOCH - 31 * 86_400, expires_at_epoch=EVALUATION_EPOCH + 10 * 86_400)
    return _repin(fixture)


def _expired_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _secret(fixture, SECRET_TELEMETRY, expires_at_epoch=EVALUATION_EPOCH - 1)
    return _repin(fixture)


def _plaintext_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _edge(fixture, EDGE_MODEL_REGISTRY, plaintext_exposure=True)
    return _repin(fixture)


def _persistent_repin(fixture: dict[str, object]) -> dict[str, object]:
    fixture = _edge(fixture, EDGE_ROOT_ARTIFACT, persistent_copy=True)
    return _repin(fixture)


def adversarial_cases() -> list[tuple[str, Mutation]]:
    return [
        ("request graph id substitution", lambda f: (f.__setitem__("request", replace(f["request"], secret_graph_id="evil")) or f)),
        ("request graph version substitution", lambda f: (f.__setitem__("request", replace(f["request"], secret_graph_version="evil")) or f)),
        ("request graph digest substitution", lambda f: (f.__setitem__("request", replace(f["request"], secret_graph_sha256="0" * 64)) or f)),
        ("request architecture digest substitution", lambda f: (f.__setitem__("request", replace(f["request"], architecture_sha256="1" * 64)) or f)),
        ("request P7-A digest substitution", lambda f: (f.__setitem__("request", replace(f["request"], p7a_assessment_evidence_sha256="2" * 64)) or f)),
        ("request P7-B digest substitution", lambda f: (f.__setitem__("request", replace(f["request"], p7b_assessment_evidence_sha256="3" * 64)) or f)),
        ("request P7-C digest substitution", lambda f: (f.__setitem__("request", replace(f["request"], p7c_assessment_evidence_sha256="4" * 64)) or f)),
        ("request posture digest substitution", lambda f: (f.__setitem__("request", replace(f["request"], posture_evidence_sha256="5" * 64)) or f)),
        ("request entry secret omission", lambda f: (f.__setitem__("request", replace(f["request"], entry_secret_ids=f["request"].entry_secret_ids[:-1])) or f)),
        ("request target surface omission", lambda f: (f.__setitem__("request", replace(f["request"], target_surface_ids=f["request"].target_surface_ids[:-1])) or f)),
        ("request duplicate entry secret", lambda f: (f.__setitem__("request", replace(f["request"], entry_secret_ids=f["request"].entry_secret_ids + (f["request"].entry_secret_ids[0],))) or f)),
        ("request negative blast radius", lambda f: (f.__setitem__("request", replace(f["request"], declared_max_blast_radius_score=-1)) or f)),
        ("manifest schema substitution", lambda f: _replace_manifest(f, replace(f["manifest"], schema_version="evil"))),
        ("manifest stale", lambda f: _replace_manifest(f, replace(f["manifest"], created_at_epoch=EVALUATION_EPOCH - 10_000))),
        ("manifest future", lambda f: _replace_manifest(f, replace(f["manifest"], created_at_epoch=EVALUATION_EPOCH + 100))),
        ("surface omission", lambda f: _replace_manifest(f, replace(f["manifest"], surfaces=f["manifest"].surfaces[:-1]))),
        ("surface duplicate", lambda f: _replace_manifest(f, replace(f["manifest"], surfaces=f["manifest"].surfaces + (f["manifest"].surfaces[0],)))),
        ("surface owner substitution", lambda f: _surface(f, SURFACE_BUILD, owner_id="untrusted")),
        ("surface type drift", lambda f: _surface(f, SURFACE_BUILD, surface_type=ExposureSurfaceType.EXTERNAL_EGRESS)),
        ("surface scope drift", lambda f: _surface(f, SURFACE_BUILD, exposure_scope=ExposureScope.EXTERNAL)),
        ("surface zone drift", lambda f: _surface(f, SURFACE_BUILD, trust_zone="external")),
        ("surface architecture mapping drift", lambda f: _surface(f, SURFACE_TOOL, architecture_asset_id="model-runtime")),
        ("secret omission", lambda f: _replace_manifest(f, replace(f["manifest"], secrets=f["manifest"].secrets[:-1]))),
        ("secret duplicate", lambda f: _replace_manifest(f, replace(f["manifest"], secrets=f["manifest"].secrets + (f["manifest"].secrets[0],)))),
        ("secret owner substitution", lambda f: _secret(f, SECRET_MODEL, owner_id="untrusted")),
        ("secret home substitution", lambda f: _secret(f, SECRET_MODEL, home_surface_id=SURFACE_CONFIG)),
        ("secret kind substitution", lambda f: _secret(f, SECRET_MODEL, kind=SecretKind.API_TOKEN)),
        ("secret authority scope substitution", lambda f: _secret(f, SECRET_MODEL, authority_scope=SecretScope.TENANT)),
        ("secret sensitivity downgrade", lambda f: _secret(f, SECRET_MODEL, sensitivity=SecretSensitivity.MEDIUM)),
        ("secret trust-root downgrade", lambda f: _secret(f, SECRET_ROOT, trust_root=False)),
        ("secret zero rotation timestamp", lambda f: _secret(f, SECRET_BUILD, rotated_at_epoch=0)),
        ("secret invalid expiry ordering", lambda f: _secret(f, SECRET_BUILD, expires_at_epoch=ROTATED_EPOCH)),
        ("edge omission", lambda f: _replace_manifest(f, replace(f["manifest"], edges=f["manifest"].edges[:-1]))),
        ("edge duplicate", lambda f: _replace_manifest(f, replace(f["manifest"], edges=f["manifest"].edges + (f["manifest"].edges[0],)))),
        ("edge owner substitution", lambda f: _edge(f, EDGE_BUILD_ARTIFACT, owner_id="untrusted")),
        ("edge unknown secret", lambda f: _edge(f, EDGE_BUILD_ARTIFACT, secret_id="unknown-secret")),
        ("edge unknown surface", lambda f: _edge(f, EDGE_BUILD_ARTIFACT, target_surface_id="unknown-surface")),
        ("edge self-loop", lambda f: _edge(f, EDGE_BUILD_ARTIFACT, target_surface_id=SURFACE_BUILD)),
        ("edge secret drift", lambda f: _edge(f, EDGE_BUILD_ARTIFACT, secret_id=SECRET_TOOL)),
        ("edge endpoint drift", lambda f: _edge(f, EDGE_BUILD_ARTIFACT, target_surface_id=SURFACE_EXTERNAL)),
        ("edge channel drift", lambda f: _edge(f, EDGE_BUILD_ARTIFACT, channel=SecretTransferChannel.LOGGING)),
        ("edge flow drift", lambda f: _edge(f, EDGE_RUNTIME, via_flow_ids=("flow-runtime-telemetry",))),
        ("edge control drift", lambda f: _edge(f, EDGE_RUNTIME, required_control_ids=(CTRL_RUNTIME_SECRET_INJECTION,))),
        ("edge duplicate control", lambda f: _edge(f, EDGE_RUNTIME, required_control_ids=(CTRL_RUNTIME_SECRET_INJECTION, CTRL_RUNTIME_SECRET_INJECTION))),
        ("edge unknown control under repin", _unknown_control_repin),
        ("edge unknown flow under repin", _unknown_flow_repin),
        ("edge route control absent under repin", _route_control_absent_repin),
        ("P7-A verification downgrade", lambda f: (f.__setitem__("p7a", replace(f["p7a"], required_graph_coverage_verified=False)) or f)),
        ("P7-A architecture evidence substitution", lambda f: (f.__setitem__("p7a", replace(f["p7a"], architecture_sha256="6" * 64)) or f)),
        ("P7-B verification downgrade", lambda f: (f.__setitem__("p7b", replace(f["p7b"], exact_identity_graph_binding_verified=False)) or f)),
        ("P7-B evidence substitution", lambda f: (f.__setitem__("p7b", replace(f["p7b"], assessment_evidence_sha256="7" * 64)) or f)),
        ("P7-C verification downgrade", lambda f: (f.__setitem__("p7c", replace(f["p7c"], exact_data_graph_binding_verified=False)) or f)),
        ("P7-C evidence substitution", lambda f: (f.__setitem__("p7c", replace(f["p7c"], assessment_evidence_sha256="8" * 64)) or f)),
        ("posture verification downgrade", lambda f: (f.__setitem__("posture", replace(f["posture"], status_derived_from_evidence=False)) or f)),
        ("posture evidence substitution", lambda f: (f.__setitem__("posture", replace(f["posture"], posture_evidence_sha256="9" * 64)) or f)),
        ("control catalog substitution", lambda f: (f.__setitem__("posture", replace(f["posture"], control_catalog_sha256="a" * 64)) or f)),
        ("duplicate posture control assessment", _duplicate_control),
        ("posture status summary inconsistency", _mutate_posture_status_summary),
        ("caller exposed-path forgery", lambda f: (f.__setitem__("request", replace(f["request"], declared_exposed_path_ids=("fake",))) or f)),
        ("caller blast-radius forgery", lambda f: (f.__setitem__("request", replace(f["request"], declared_max_blast_radius_score=999)) or f)),
        ("path hop bound truncation", lambda f: (f.__setitem__("policy", replace(f["policy"], max_path_hops=1)) or f)),
        ("path count bound truncation", lambda f: (f.__setitem__("policy", replace(f["policy"], max_paths=1)) or f)),
        ("plaintext model signing exposure under repin", _plaintext_repin),
        ("persistent root-key artifact copy under repin", _persistent_repin),
        ("rotation overdue under repin", _rotation_overdue_repin),
        ("expired telemetry credential under repin", _expired_repin),
        ("root signing key external egress under repin", _root_external_repin),
    ]


def benign_fixtures() -> list[tuple[str, dict[str, object]]]:
    return [
        ("all controls satisfied", build_fixture()),
        ("artifact scan exception explicitly surfaced", build_fixture(exceptioned_control=CTRL_ARTIFACT_SCAN)),
        ("telemetry redaction not evaluated explicitly surfaced", build_fixture(not_evaluated_control=CTRL_TELEMETRY_REDACTION)),
    ]


def _dataset_sha256() -> str:
    payload = json.dumps([name for name, _ in adversarial_cases()], separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _fixture_sha256() -> str:
    fixture = build_fixture()
    payload = {
        "architecture_sha256": fixture["request"].architecture_sha256,
        "control_catalog_sha256": fixture["posture"].control_catalog_sha256,
        "p7a": fixture["p7a"].assessment_evidence_sha256,
        "p7b": fixture["p7b"].assessment_evidence_sha256,
        "p7c": fixture["p7c"].assessment_evidence_sha256,
        "posture": fixture["posture"].posture_evidence_sha256,
        "secret_graph_sha256": secret_exposure_manifest_digest(fixture["manifest"]),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def run_evaluation() -> dict[str, object]:
    vulnerable = VulnerableSecretExposureReporter()
    adversarial = adversarial_cases()
    vulnerable_successes = 0
    hardened_successes = 0
    for _, mutation in adversarial:
        if vulnerable.evaluate(declared_graph_complete=True, declared_exposed_path_count=0, declared_max_blast_radius_score=0).safe:
            vulnerable_successes += 1
        fixture = mutation(build_fixture())
        try:
            _hardened(fixture)
        except SecretExposureRejected:
            continue
        hardened_successes += 1

    benign_results = []
    false_positives = 0
    for name, fixture in benign_fixtures():
        try:
            result = _hardened(fixture)
            benign_results.append((name, result))
        except SecretExposureRejected:
            false_positives += 1

    metrics = {
        "adversarial_cases": len(adversarial),
        "vulnerable_asr": f"{vulnerable_successes}/{len(adversarial)}",
        "hardened_asr": f"{hardened_successes}/{len(adversarial)}",
        "hardened_fpr": f"{false_positives}/{len(benign_fixtures())}",
        "safe_task_rate": f"{len(benign_results)}/{len(benign_fixtures())}",
        "dataset_sha256": _dataset_sha256(),
        "fixture_sha256": _fixture_sha256(),
        "secret_graph_sha256": secret_exposure_manifest_digest(build_fixture()["manifest"]),
    }
    return {"metrics": metrics, "benign": benign_results}


def main() -> None:
    result = run_evaluation()
    print(json.dumps(result["metrics"], sort_keys=True))
    for name, assessment in result["benign"]:
        print(
            json.dumps(
                {
                    "benign": name,
                    "assessment_evidence_sha256": assessment.assessment_evidence_sha256,
                    "controlled_paths": assessment.controlled_path_count,
                    "exposed_paths": assessment.exposed_path_count,
                    "max_blast_radius_score": assessment.max_blast_radius_score,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
