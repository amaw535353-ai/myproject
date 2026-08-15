from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from typing import Callable

from aegis.architecture.dependency_trust import (
    AuthenticationMode,
    DependencyCriticality,
    DependencyTrustRejected,
    DependencyType,
    EgressDataClass,
    ExternalDependencyTrustAnalyzer,
    TransportMode,
    canonical_dependency_trust_manifest_bytes,
    dependency_trust_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus
from aegis.vulnerable.dependency_trust import VulnerableDependencyTrustReporter

from .p7e_fixture import (
    CTRL_TELEMETRY_EGRESS,
    CTRL_TOOL_EGRESS,
    NOW,
    build_fixture,
)


Mutation = Callable[[dict[str, object]], dict[str, object]]


def _with(fixture: dict[str, object], key: str, value: object) -> dict[str, object]:
    changed = dict(fixture)
    changed[key] = value
    return changed


def _rebind_manifest(fixture: dict[str, object], manifest: object) -> dict[str, object]:
    graph_sha = dependency_trust_manifest_digest(manifest)
    changed = dict(fixture)
    changed["manifest"] = manifest
    changed["policy"] = replace(changed["policy"], expected_dependency_graph_sha256=graph_sha)
    changed["request"] = replace(changed["request"], dependency_graph_sha256=graph_sha)
    return changed


def _replace_dependency(fixture: dict[str, object], dependency_id: str, **changes: object) -> dict[str, object]:
    manifest = fixture["manifest"]
    items = tuple(replace(item, **changes) if item.dependency_id == dependency_id else item for item in manifest.dependencies)
    return _rebind_manifest(fixture, replace(manifest, dependencies=items))


def _replace_route(fixture: dict[str, object], route_id: str, **changes: object) -> dict[str, object]:
    manifest = fixture["manifest"]
    items = tuple(replace(item, **changes) if item.route_id == route_id else item for item in manifest.routes)
    return _rebind_manifest(fixture, replace(manifest, routes=items))


def _copy_upstream(fixture: dict[str, object], key: str, **changes: object) -> dict[str, object]:
    item = copy.copy(fixture[key])
    for name, value in changes.items():
        setattr(item, name, value)
    return _with(fixture, key, item)


def adversarial_cases() -> list[tuple[str, Mutation]]:
    return [
        ("request graph id substitution", lambda f: _with(f, "request", replace(f["request"], dependency_graph_id="attacker-graph"))),
        ("request graph version substitution", lambda f: _with(f, "request", replace(f["request"], dependency_graph_version="0"))),
        ("request graph digest substitution", lambda f: _with(f, "request", replace(f["request"], dependency_graph_sha256="0" * 64))),
        ("request architecture substitution", lambda f: _with(f, "request", replace(f["request"], architecture_sha256="1" * 64))),
        ("request P7-A evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7a_assessment_evidence_sha256="2" * 64))),
        ("request P7-B evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7b_assessment_evidence_sha256="3" * 64))),
        ("request P7-C evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7c_assessment_evidence_sha256="4" * 64))),
        ("request P7-D evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7d_assessment_evidence_sha256="5" * 64))),
        ("request posture evidence substitution", lambda f: _with(f, "request", replace(f["request"], posture_evidence_sha256="6" * 64))),
        ("request entry source shrink", lambda f: _with(f, "request", replace(f["request"], entry_source_asset_ids=f["request"].entry_source_asset_ids[:-1]))),
        ("request target dependency shrink", lambda f: _with(f, "request", replace(f["request"], target_dependency_ids=f["request"].target_dependency_ids[:-1]))),
        ("forged caller exposed path summary", lambda f: _with(f, "request", replace(f["request"], declared_exposed_path_ids=("forged",)))),
        ("forged caller risk summary", lambda f: _with(f, "request", replace(f["request"], declared_max_exposed_risk_score=999))),
        ("manifest schema substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], schema_version="attacker-schema"))),
        ("manifest architecture substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], architecture_sha256="7" * 64))),
        ("stale manifest", lambda f: _rebind_manifest(f, replace(f["manifest"], created_at_epoch=NOW - 200_000))),
        ("future manifest", lambda f: _rebind_manifest(f, replace(f["manifest"], created_at_epoch=NOW + 1_000))),
        ("dependency deletion", lambda f: _rebind_manifest(f, replace(f["manifest"], dependencies=f["manifest"].dependencies[:-1]))),
        ("dependency duplication", lambda f: _rebind_manifest(f, replace(f["manifest"], dependencies=f["manifest"].dependencies + (f["manifest"].dependencies[0],)))),
        ("untrusted dependency owner", lambda f: _replace_dependency(f, "dep-tool-api", owner_id="attacker")),
        ("untrusted provider", lambda f: _replace_dependency(f, "dep-tool-api", provider_id="evil-provider")),
        ("dependency type substitution", lambda f: _replace_dependency(f, "dep-tool-api", dependency_type=DependencyType.TELEMETRY_SINK)),
        ("criticality downgrade", lambda f: _replace_dependency(f, "dep-tool-api", criticality=DependencyCriticality.LOW)),
        ("endpoint host substitution", lambda f: _replace_dependency(f, "dep-tool-api", endpoint_host="evil.example")),
        ("endpoint port substitution", lambda f: _replace_dependency(f, "dep-tool-api", endpoint_port=80)),
        ("transport downgrade", lambda f: _replace_dependency(f, "dep-tool-api", transport_mode=TransportMode.PLAINTEXT)),
        ("authentication downgrade", lambda f: _replace_dependency(f, "dep-tool-api", authentication_mode=AuthenticationMode.NONE)),
        ("server identity substitution", lambda f: _replace_dependency(f, "dep-tool-api", expected_server_identity="evil.example")),
        ("data class scope expansion", lambda f: _replace_dependency(f, "dep-model-provider", egress_data_classes=f["manifest"].dependencies[0].egress_data_classes + (EgressDataClass.SECRET,))),
        ("secret scope expansion", lambda f: _replace_dependency(f, "dep-model-provider", exposed_secret_ids=("secret-root",))),
        ("dependency control deletion", lambda f: _replace_dependency(f, "dep-tool-api", required_control_ids=())),
        ("dependency fail-closed drift", lambda f: _replace_dependency(f, "dep-tool-api", fail_closed=False)),
        ("route deletion", lambda f: _rebind_manifest(f, replace(f["manifest"], routes=f["manifest"].routes[:-1]))),
        ("route duplication", lambda f: _rebind_manifest(f, replace(f["manifest"], routes=f["manifest"].routes + (f["manifest"].routes[0],)))),
        ("untrusted route owner", lambda f: _replace_route(f, "route-tool", owner_id="attacker")),
        ("route source substitution", lambda f: _replace_route(f, "route-tool", source_asset_id="asset-runtime")),
        ("route dependency substitution", lambda f: _replace_route(f, "route-tool", dependency_id="dep-model-provider")),
        ("route flow substitution", lambda f: _replace_route(f, "route-tool", via_flow_ids=("flow-user", "flow-agent", "flow-model"))),
        ("route control deletion", lambda f: _replace_route(f, "route-tool", required_control_ids=())),
        ("non-contiguous architecture route", lambda f: _replace_route(f, "route-tool", via_flow_ids=("flow-user", "flow-tool"))),
        ("P7-A verification downgrade", lambda f: _copy_upstream(f, "p7a", exact_architecture_binding_verified=False)),
        ("P7-A evidence digest substitution", lambda f: _copy_upstream(f, "p7a", assessment_evidence_sha256="8" * 64)),
        ("P7-B verification downgrade", lambda f: _copy_upstream(f, "p7b", exact_p7a_assessment_binding_verified=False)),
        ("P7-C verification downgrade", lambda f: _copy_upstream(f, "p7c", exact_p7b_assessment_binding_verified=False)),
        ("P7-D verification downgrade", lambda f: _copy_upstream(f, "p7d", exact_p7c_assessment_binding_verified=False)),
        ("posture verification downgrade", lambda f: _copy_upstream(f, "posture", status_derived_from_evidence=False)),
        ("posture digest substitution", lambda f: _copy_upstream(f, "posture", posture_evidence_sha256="9" * 64)),
        ("control catalog substitution", lambda f: _copy_upstream(f, "posture", control_catalog_sha256="a" * 64)),
        ("posture satisfied summary forgery", lambda f: _copy_upstream(f, "posture", satisfied_control_ids=())),
    ]


def _evaluate(fixture: dict[str, object]) -> object:
    return ExternalDependencyTrustAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["architecture"],
        fixture["p7a"],
        fixture["p7b"],
        fixture["p7c"],
        fixture["p7d"],
        fixture["posture"],
    )


def run_evaluation() -> dict[str, object]:
    vulnerable = VulnerableDependencyTrustReporter()
    cases = adversarial_cases()
    vulnerable_success = 0
    hardened_success = 0
    for _, mutation in cases:
        fixture = mutation(build_fixture())
        if vulnerable.evaluate(
            declared_graph_complete=True,
            declared_exposed_path_count=0,
            declared_max_risk_score=0,
            declared_all_destinations_trusted=True,
        ).accepted:
            vulnerable_success += 1
        try:
            _evaluate(fixture)
        except DependencyTrustRejected:
            pass
        else:
            hardened_success += 1

    benign_fixtures = (
        build_fixture(),
        build_fixture(exceptioned_control=CTRL_TOOL_EGRESS),
        build_fixture(not_evaluated_control=CTRL_TELEMETRY_EGRESS),
    )
    benign_accepted = 0
    for fixture in benign_fixtures:
        try:
            _evaluate(fixture)
        except DependencyTrustRejected:
            continue
        benign_accepted += 1

    base = build_fixture()
    dataset_sha = hashlib.sha256(
        json.dumps([name for name, _ in cases], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    fixture_sha = hashlib.sha256(
        canonical_dependency_trust_manifest_bytes(base["manifest"])
        + base["policy"].expected_posture_evidence_sha256.encode("ascii")
        + base["policy"].expected_control_catalog_sha256.encode("ascii")
    ).hexdigest()
    metrics = {
        "adversarial_cases": len(cases),
        "vulnerable_asr": f"{vulnerable_success}/{len(cases)}",
        "hardened_asr": f"{hardened_success}/{len(cases)}",
        "hardened_fpr": f"{3 - benign_accepted}/3",
        "safe_task_rate": f"{benign_accepted}/3",
        "dependency_graph_sha256": dependency_trust_manifest_digest(base["manifest"]),
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
    }
    return {"metrics": metrics}


def main() -> int:
    result = run_evaluation()
    print(json.dumps(result, sort_keys=True, indent=2))
    metrics = result["metrics"]
    total = metrics["adversarial_cases"]
    return 0 if (
        metrics["vulnerable_asr"] == f"{total}/{total}"
        and metrics["hardened_asr"] == f"0/{total}"
        and metrics["hardened_fpr"] == "0/3"
        and metrics["safe_task_rate"] == "3/3"
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
