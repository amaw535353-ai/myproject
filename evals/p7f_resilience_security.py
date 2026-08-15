from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from typing import Callable

from aegis.architecture.dependency_trust import AuthenticationMode, EgressDataClass, TransportMode
from aegis.architecture.resilience_security import (
    DependencyFailureSecurityAnalyzer,
    DependencyFailureState,
    FallbackMode,
    ResilienceSecurityRejected,
    canonical_resilience_security_manifest_bytes,
    resilience_security_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus
from aegis.vulnerable.resilience_security import VulnerableAvailabilityRestorationReporter

from .p7f_fixture import (
    CTRL_CACHE_INTEGRITY,
    CTRL_FALLBACK_AUTHZ,
    CTRL_LOCAL_SAFE_MODE,
    NOW,
    build_fixture,
)


Mutation = Callable[[dict[str, object]], dict[str, object]]


def _with(fixture: dict[str, object], key: str, value: object) -> dict[str, object]:
    changed = dict(fixture)
    changed[key] = value
    return changed


def _copy_ns(fixture: dict[str, object], key: str, **changes: object) -> dict[str, object]:
    item = copy.copy(fixture[key])
    for name, value in changes.items():
        setattr(item, name, value)
    return _with(fixture, key, item)


def _rebind_manifest(fixture: dict[str, object], manifest: object) -> dict[str, object]:
    digest = resilience_security_manifest_digest(manifest)
    changed = dict(fixture)
    changed["manifest"] = manifest
    changed["policy"] = replace(changed["policy"], expected_resilience_plan_sha256=digest)
    changed["request"] = replace(changed["request"], resilience_plan_sha256=digest)
    return changed


def _replace_scenario(fixture: dict[str, object], scenario_id: str, **changes: object) -> dict[str, object]:
    manifest = fixture["manifest"]
    scenarios = tuple(replace(item, **changes) if item.scenario_id == scenario_id else item for item in manifest.scenarios)
    return _rebind_manifest(fixture, replace(manifest, scenarios=scenarios))


def _replace_fallback(fixture: dict[str, object], fallback_id: str, **changes: object) -> dict[str, object]:
    manifest = fixture["manifest"]
    fallbacks = tuple(replace(item, **changes) if item.fallback_id == fallback_id else item for item in manifest.fallbacks)
    return _rebind_manifest(fixture, replace(manifest, fallbacks=fallbacks))


def _policy_map(policy: object, field: str, key: str, value: object) -> object:
    mapping = dict(getattr(policy, field))
    mapping[key] = value
    return replace(policy, **{field: mapping})


def _semantic_disable_control(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(
        fixture,
        "fallback-model-local-safe",
        preserved_control_ids=("CTRL-MODEL-EGRESS", "CTRL-FALLBACK-AUTHZ"),
        disabled_control_ids=(CTRL_LOCAL_SAFE_MODE,),
    )
    policy = _policy_map(changed["policy"], "expected_preserved_control_ids_by_fallback", "fallback-model-local-safe", frozenset({"CTRL-MODEL-EGRESS", "CTRL-FALLBACK-AUTHZ"}))
    policy = _policy_map(policy, "expected_disabled_control_ids_by_fallback", "fallback-model-local-safe", frozenset({CTRL_LOCAL_SAFE_MODE}))
    return _with(changed, "policy", policy)


def _semantic_retry_untrusted(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(
        fixture,
        "fallback-model-secondary",
        mode=FallbackMode.RETRY_PRIMARY,
        target_dependency_id="dep-model-primary",
        retry_attempts=1,
    )
    policy = _policy_map(changed["policy"], "expected_mode_by_fallback", "fallback-model-secondary", FallbackMode.RETRY_PRIMARY)
    policy = _policy_map(policy, "expected_target_dependency_by_fallback", "fallback-model-secondary", "dep-model-primary")
    policy = _policy_map(policy, "max_retry_attempts_by_fallback", "fallback-model-secondary", 1)
    return _with(changed, "policy", policy)


def _semantic_stale_cache(fixture: dict[str, object]) -> dict[str, object]:
    return _replace_fallback(fixture, "fallback-telemetry-cache", cached_at_epoch=NOW - 900)


def _semantic_alternate_exposed(fixture: dict[str, object]) -> dict[str, object]:
    p7e = fixture["p7e"]
    paths = tuple(
        replace(item, exposed=True, risk_score=88, exposure_reasons=("synthetic_upstream_exposure",))
        if item.dependency_id == "dep-model-secondary"
        else item
        for item in p7e.paths
    )
    return _with(fixture, "p7e", replace(p7e, paths=paths))


def _semantic_alternate_weaker(fixture: dict[str, object]) -> dict[str, object]:
    p7e = fixture["p7e"]
    paths = tuple(
        replace(item, transport_mode=TransportMode.TLS, authentication_mode=AuthenticationMode.API_KEY)
        if item.dependency_id == "dep-model-secondary"
        else item
        for item in p7e.paths
    )
    return _with(fixture, "p7e", replace(p7e, paths=paths))


def _shape_fail_closed_data(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(fixture, "fallback-tool-closed", egress_data_classes=(EgressDataClass.INTERNAL,))
    policy = _policy_map(changed["policy"], "allowed_data_classes_by_fallback", "fallback-tool-closed", frozenset({EgressDataClass.INTERNAL}))
    return _with(changed, "policy", policy)


def _shape_retry_missing_target(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(fixture, "fallback-model-retry", target_dependency_id=None)
    policy = _policy_map(changed["policy"], "expected_target_dependency_by_fallback", "fallback-model-retry", None)
    return _with(changed, "policy", policy)


def _shape_alternate_same_primary(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(fixture, "fallback-model-secondary", target_dependency_id="dep-model-primary")
    policy = _policy_map(changed["policy"], "expected_target_dependency_by_fallback", "fallback-model-secondary", "dep-model-primary")
    return _with(changed, "policy", policy)


def _shape_local_secret(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(fixture, "fallback-model-local-safe", secret_ids=("secret-forbidden",))
    policy = _policy_map(changed["policy"], "allowed_secret_ids_by_fallback", "fallback-model-local-safe", frozenset({"secret-forbidden"}))
    return _with(changed, "policy", policy)


def _shape_cache_external_target(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(fixture, "fallback-telemetry-cache", target_dependency_id="dep-telemetry")
    policy = _policy_map(changed["policy"], "expected_target_dependency_by_fallback", "fallback-telemetry-cache", "dep-telemetry")
    return _with(changed, "policy", policy)


def _control_overlap(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(fixture, "fallback-model-retry", disabled_control_ids=(CTRL_FALLBACK_AUTHZ,))
    policy = _policy_map(changed["policy"], "expected_disabled_control_ids_by_fallback", "fallback-model-retry", frozenset({CTRL_FALLBACK_AUTHZ}))
    return _with(changed, "policy", policy)


def _control_coverage_gap(fixture: dict[str, object]) -> dict[str, object]:
    changed = _replace_fallback(fixture, "fallback-model-retry", preserved_control_ids=("CTRL-MODEL-EGRESS",))
    policy = _policy_map(changed["policy"], "expected_preserved_control_ids_by_fallback", "fallback-model-retry", frozenset({"CTRL-MODEL-EGRESS"}))
    return _with(changed, "policy", policy)


def _duplicate_p7e_dependency_path(fixture: dict[str, object]) -> dict[str, object]:
    p7e = fixture["p7e"]
    return _with(fixture, "p7e", replace(p7e, paths=p7e.paths + (p7e.paths[0],)))


def _duplicate_posture_control(fixture: dict[str, object]) -> dict[str, object]:
    posture = copy.copy(fixture["posture"])
    posture.assessments = posture.assessments + (posture.assessments[0],)
    return _with(fixture, "posture", posture)


def adversarial_cases() -> list[tuple[str, Mutation]]:
    return [
        ("request plan id substitution", lambda f: _with(f, "request", replace(f["request"], resilience_plan_id="attacker-plan"))),
        ("request plan version substitution", lambda f: _with(f, "request", replace(f["request"], resilience_plan_version="0"))),
        ("request plan digest substitution", lambda f: _with(f, "request", replace(f["request"], resilience_plan_sha256="0" * 64))),
        ("request dependency graph substitution", lambda f: _with(f, "request", replace(f["request"], dependency_graph_sha256="1" * 64))),
        ("request P7-E evidence substitution", lambda f: _with(f, "request", replace(f["request"], p7e_assessment_evidence_sha256="2" * 64))),
        ("request posture evidence substitution", lambda f: _with(f, "request", replace(f["request"], posture_evidence_sha256="3" * 64))),
        ("request scenario scope shrink", lambda f: _with(f, "request", replace(f["request"], scenario_ids=f["request"].scenario_ids[:-1]))),
        ("forged caller exposed-scenario summary", lambda f: _with(f, "request", replace(f["request"], declared_exposed_scenario_ids=("forged",)))),
        ("forged caller maximum risk", lambda f: _with(f, "request", replace(f["request"], declared_max_security_risk_score=999))),
        ("manifest schema substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], schema_version="attacker-schema"))),
        ("manifest plan id substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], resilience_plan_id="attacker-plan"))),
        ("manifest version substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], version="0"))),
        ("manifest dependency graph substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], dependency_graph_sha256="4" * 64))),
        ("manifest P7-E evidence substitution", lambda f: _rebind_manifest(f, replace(f["manifest"], p7e_assessment_evidence_sha256="5" * 64))),
        ("stale resilience manifest", lambda f: _rebind_manifest(f, replace(f["manifest"], created_at_epoch=NOW - 200_000))),
        ("future resilience manifest", lambda f: _rebind_manifest(f, replace(f["manifest"], created_at_epoch=NOW + 1_000))),
        ("scenario deletion", lambda f: _rebind_manifest(f, replace(f["manifest"], scenarios=f["manifest"].scenarios[:-1]))),
        ("scenario duplication", lambda f: _rebind_manifest(f, replace(f["manifest"], scenarios=f["manifest"].scenarios + (f["manifest"].scenarios[0],)))),
        ("scenario untrusted owner", lambda f: _replace_scenario(f, "scenario-model-unavailable", owner_id="attacker")),
        ("scenario unknown dependency", lambda f: _replace_scenario(f, "scenario-model-unavailable", dependency_id="dep-unknown")),
        ("scenario dependency drift", lambda f: _replace_scenario(f, "scenario-model-unavailable", dependency_id="dep-tool-api")),
        ("scenario state drift", lambda f: _replace_scenario(f, "scenario-model-unavailable", failure_state=DependencyFailureState.DEGRADED)),
        ("scenario control deletion", lambda f: _replace_scenario(f, "scenario-model-unavailable", required_control_ids=("CTRL-MODEL-EGRESS", "CTRL-FALLBACK-AUTHZ"))),
        ("scenario unknown control injection", lambda f: _replace_scenario(f, "scenario-model-unavailable", required_control_ids=("CTRL-MODEL-EGRESS", "CTRL-FALLBACK-AUTHZ", "CTRL-UNKNOWN"))),
        ("fallback deletion", lambda f: _rebind_manifest(f, replace(f["manifest"], fallbacks=f["manifest"].fallbacks[:-1]))),
        ("fallback duplication", lambda f: _rebind_manifest(f, replace(f["manifest"], fallbacks=f["manifest"].fallbacks + (f["manifest"].fallbacks[0],)))),
        ("fallback untrusted owner", lambda f: _replace_fallback(f, "fallback-model-local-safe", owner_id="attacker")),
        ("fallback unknown scenario", lambda f: _replace_fallback(f, "fallback-model-local-safe", scenario_id="scenario-unknown")),
        ("fallback scenario drift", lambda f: _replace_fallback(f, "fallback-model-local-safe", scenario_id="scenario-model-degraded")),
        ("fallback mode drift", lambda f: _replace_fallback(f, "fallback-model-local-safe", mode=FallbackMode.FAIL_CLOSED)),
        ("fallback target drift", lambda f: _replace_fallback(f, "fallback-model-secondary", target_dependency_id="dep-registry")),
        ("fallback unknown target", lambda f: _replace_fallback(f, "fallback-model-secondary", target_dependency_id="dep-unknown")),
        ("fallback preserved-control drift", lambda f: _replace_fallback(f, "fallback-model-local-safe", preserved_control_ids=("CTRL-MODEL-EGRESS", "CTRL-FALLBACK-AUTHZ"))),
        ("fallback disabled-control drift", lambda f: _replace_fallback(f, "fallback-model-local-safe", disabled_control_ids=(CTRL_LOCAL_SAFE_MODE,))),
        ("fallback data-scope expansion", lambda f: _replace_fallback(f, "fallback-model-local-safe", egress_data_classes=(EgressDataClass.INTERNAL, EgressDataClass.SECRET))),
        ("fallback secret-scope expansion", lambda f: _replace_fallback(f, "fallback-model-secondary", secret_ids=("secret-root",))),
        ("fallback retry bound exceeded", lambda f: _replace_fallback(f, "fallback-model-retry", retry_attempts=99)),
        ("fallback future cache timestamp", lambda f: _replace_fallback(f, "fallback-telemetry-cache", cached_at_epoch=NOW + 1_000)),
        ("fallback control overlap", _control_overlap),
        ("fallback required-control coverage gap", _control_coverage_gap),
        ("fail-closed fallback attempts data transfer", _shape_fail_closed_data),
        ("retry-primary fallback drops target", _shape_retry_missing_target),
        ("alternate fallback points at primary", _shape_alternate_same_primary),
        ("local safe mode consumes secret", _shape_local_secret),
        ("cache fallback targets external dependency", _shape_cache_external_target),
        ("policy expected plan hash malformed", lambda f: _with(f, "policy", replace(f["policy"], expected_resilience_plan_sha256="bad"))),
        ("policy scenario map incomplete", lambda f: _with(f, "policy", replace(f["policy"], expected_dependency_by_scenario={k: v for k, v in f["policy"].expected_dependency_by_scenario.items() if k != "scenario-registry-unavailable"}))),
        ("policy fallback map incomplete", lambda f: _with(f, "policy", replace(f["policy"], expected_mode_by_fallback={k: v for k, v in f["policy"].expected_mode_by_fallback.items() if k != "fallback-registry-cache"}))),
        ("policy negative retry bound", lambda f: _with(f, "policy", _policy_map(f["policy"], "max_retry_attempts_by_fallback", "fallback-model-retry", -1))),
        ("policy negative cache-age bound", lambda f: _with(f, "policy", _policy_map(f["policy"], "max_cache_age_seconds_by_fallback", "fallback-telemetry-cache", -1))),
        ("P7-E verification downgrade", lambda f: _with(f, "p7e", replace(f["p7e"], exact_dependency_graph_binding_verified=False))),
        ("P7-E evidence digest substitution", lambda f: _with(f, "p7e", replace(f["p7e"], assessment_evidence_sha256="6" * 64))),
        ("P7-E dependency graph substitution", lambda f: _with(f, "p7e", replace(f["p7e"], dependency_graph_sha256="7" * 64))),
        ("P7-E duplicate dependency path", _duplicate_p7e_dependency_path),
        ("posture verification downgrade", lambda f: _copy_ns(f, "posture", status_derived_from_evidence=False)),
        ("posture digest substitution", lambda f: _copy_ns(f, "posture", posture_evidence_sha256="8" * 64)),
        ("control catalog substitution", lambda f: _copy_ns(f, "posture", control_catalog_sha256="9" * 64)),
        ("posture satisfied summary forgery", lambda f: _copy_ns(f, "posture", satisfied_control_ids=())),
        ("posture duplicate control evidence", _duplicate_posture_control),
        ("semantic required-control disable", _semantic_disable_control),
        ("semantic retry of untrusted primary", _semantic_retry_untrusted),
        ("semantic stale cache fallback", _semantic_stale_cache),
        ("semantic exposed alternate dependency", _semantic_alternate_exposed),
        ("semantic weaker alternate transport/auth", _semantic_alternate_weaker),
    ]


def _evaluate(fixture: dict[str, object]) -> object:
    return DependencyFailureSecurityAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["p7e"],
        fixture["posture"],
    )


def run_evaluation() -> dict[str, object]:
    cases = adversarial_cases()
    vulnerable = VulnerableAvailabilityRestorationReporter()
    vulnerable_success = 0
    hardened_success = 0
    for _, mutation in cases:
        fixture = mutation(build_fixture())
        if vulnerable.evaluate(
            declared_all_dependencies_recovered=True,
            declared_fallbacks_safe=True,
            declared_security_degradation_count=0,
            declared_max_security_risk_score=0,
        ).accepted:
            vulnerable_success += 1
        try:
            _evaluate(fixture)
        except ResilienceSecurityRejected:
            pass
        else:
            hardened_success += 1

    benign = (
        build_fixture(),
        build_fixture(exceptioned_control=CTRL_CACHE_INTEGRITY),
        build_fixture(stale_cache_fallback_id="fallback-telemetry-cache"),
    )
    benign_accepted = 0
    for fixture in benign:
        try:
            _evaluate(fixture)
        except ResilienceSecurityRejected:
            continue
        benign_accepted += 1

    base = build_fixture()
    dataset_sha = hashlib.sha256(
        json.dumps([name for name, _ in cases], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    fixture_sha = hashlib.sha256(
        canonical_resilience_security_manifest_bytes(base["manifest"])
        + base["policy"].expected_p7e_assessment_evidence_sha256.encode("ascii")
        + base["policy"].expected_posture_evidence_sha256.encode("ascii")
    ).hexdigest()
    metrics = {
        "adversarial_cases": len(cases),
        "vulnerable_asr": f"{vulnerable_success}/{len(cases)}",
        "hardened_asr": f"{hardened_success}/{len(cases)}",
        "hardened_fpr": f"{3 - benign_accepted}/3",
        "safe_task_rate": f"{benign_accepted}/3",
        "resilience_plan_sha256": resilience_security_manifest_digest(base["manifest"]),
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
