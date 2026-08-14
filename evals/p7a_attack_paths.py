from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from aegis.architecture.attack_paths import (
    ArchitectureAsset,
    ArchitectureFlow,
    ArchitectureManifest,
    AssetSensitivity,
    AssetType,
    AttackPathPolicy,
    AttackPathRejected,
    AttackPathRequest,
    FlowType,
    TrustBoundaryAttackPathAnalyzer,
    architecture_manifest_digest,
    attack_path_identifier,
)
from aegis.assurance.posture_reporting import (
    ControlPostureAssessment,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)
from aegis.assurance.regression import AssuranceSeverity
from aegis.vulnerable.attack_path_reporting import VulnerableAttackPathReporter


EVALUATION_EPOCH = 1_800_000_600
MANIFEST_EPOCH = 1_800_000_000
POSTURE_EVIDENCE_SHA = hashlib.sha256(b"p7a-p6d-posture-evidence").hexdigest()
CONTROL_CATALOG_SHA = hashlib.sha256(b"p7a-p6d-control-catalog").hexdigest()

CTRL_INPUT_SAFETY = "CTRL-INPUT-SAFETY"
CTRL_PROMPT_BOUNDARY = "CTRL-PROMPT-BOUNDARY"
CTRL_RETRIEVAL_INTEGRITY = "CTRL-RETRIEVAL-INTEGRITY"
CTRL_DATA_ACCESS = "CTRL-DATA-ACCESS"
CTRL_TOOL_AUTH = "CTRL-TOOL-AUTH"
CTRL_LEAST_PRIVILEGE = "CTRL-LEAST-PRIVILEGE"
CTRL_MODEL_PROVENANCE = "CTRL-MODEL-PROVENANCE"
CTRL_RUNTIME_ISOLATION = "CTRL-RUNTIME-ISOLATION"
CTRL_INFERENCE_PRIVACY = "CTRL-INFERENCE-PRIVACY"
CTRL_SERVING_ABUSE = "CTRL-SERVING-ABUSE"

ALL_CONTROLS = (
    CTRL_INPUT_SAFETY,
    CTRL_PROMPT_BOUNDARY,
    CTRL_RETRIEVAL_INTEGRITY,
    CTRL_DATA_ACCESS,
    CTRL_TOOL_AUTH,
    CTRL_LEAST_PRIVILEGE,
    CTRL_MODEL_PROVENANCE,
    CTRL_RUNTIME_ISOLATION,
    CTRL_INFERENCE_PRIVACY,
    CTRL_SERVING_ABUSE,
)


def _assets() -> tuple[ArchitectureAsset, ...]:
    return (
        ArchitectureAsset("external-user", AssetType.EXTERNAL_ACTOR, "internet", "external", AssetSensitivity.LOW, "Untrusted help-desk user input origin."),
        ArchitectureAsset("api-gateway", AssetType.API_GATEWAY, "edge", "platform", AssetSensitivity.MEDIUM, "Authenticated API ingress and tenant request boundary."),
        ArchitectureAsset("agent-orchestrator", AssetType.AGENT_ORCHESTRATOR, "application", "platform", AssetSensitivity.HIGH, "Agent planner and server-owned orchestration boundary."),
        ArchitectureAsset("retriever", AssetType.RETRIEVER, "application", "platform", AssetSensitivity.MEDIUM, "Tenant-filtered retrieval service."),
        ArchitectureAsset("vector-store", AssetType.VECTOR_STORE, "data", "data", AssetSensitivity.HIGH, "Multi-tenant retrieval corpus."),
        ArchitectureAsset("tool-gateway", AssetType.TOOL_GATEWAY, "privileged-tools", "ai-security", AssetSensitivity.HIGH, "Typed privileged tool authorization gateway."),
        ArchitectureAsset("secret-store", AssetType.SECRET_STORE, "secrets", "ai-security", AssetSensitivity.CRITICAL, "Synthetic privileged credential and secret boundary."),
        ArchitectureAsset("model-registry", AssetType.MODEL_REGISTRY, "model-supply-chain", "model-security", AssetSensitivity.HIGH, "Model release acquisition and provenance origin."),
        ArchitectureAsset("model-runtime", AssetType.MODEL_RUNTIME, "inference", "model-security", AssetSensitivity.CRITICAL, "Verified inference runtime and model-serving boundary."),
        ArchitectureAsset("security-telemetry", AssetType.SECURITY_TELEMETRY, "security", "ai-security", AssetSensitivity.HIGH, "Serving-abuse telemetry and incident-response evidence sink."),
    )


def _flows() -> tuple[ArchitectureFlow, ...]:
    return (
        ArchitectureFlow("flow-user-api", "external-user", "api-gateway", FlowType.USER_INPUT, "platform", (CTRL_INPUT_SAFETY,), "Untrusted user requests enter the authenticated API boundary."),
        ArchitectureFlow("flow-api-agent", "api-gateway", "agent-orchestrator", FlowType.AGENT_CONTROL, "platform", (CTRL_PROMPT_BOUNDARY,), "Validated requests reach the server-owned agent orchestration boundary."),
        ArchitectureFlow("flow-agent-retriever", "agent-orchestrator", "retriever", FlowType.RETRIEVAL, "platform", (CTRL_RETRIEVAL_INTEGRITY,), "Agent retrieval requests cross the retrieval-integrity boundary."),
        ArchitectureFlow("flow-retriever-vector", "retriever", "vector-store", FlowType.DATA_ACCESS, "data", (CTRL_DATA_ACCESS,), "Retriever accesses tenant-scoped vector data."),
        ArchitectureFlow("flow-agent-tool", "agent-orchestrator", "tool-gateway", FlowType.TOOL_CALL, "ai-security", (CTRL_TOOL_AUTH,), "Agent proposals cross the typed tool-authorization boundary."),
        ArchitectureFlow("flow-tool-secret", "tool-gateway", "secret-store", FlowType.SECRET_ACCESS, "ai-security", (CTRL_TOOL_AUTH, CTRL_LEAST_PRIVILEGE), "Authorized privileged tools request least-privilege synthetic credentials."),
        ArchitectureFlow("flow-registry-runtime", "model-registry", "model-runtime", FlowType.MODEL_ACQUISITION, "model-security", (CTRL_MODEL_PROVENANCE, CTRL_RUNTIME_ISOLATION), "Verified model releases enter the isolated runtime boundary."),
        ArchitectureFlow("flow-agent-runtime", "agent-orchestrator", "model-runtime", FlowType.INFERENCE, "model-security", (CTRL_RUNTIME_ISOLATION, CTRL_INFERENCE_PRIVACY), "Agent inference crosses runtime-isolation and inference-privacy controls."),
        ArchitectureFlow("flow-runtime-telemetry", "model-runtime", "security-telemetry", FlowType.SECURITY_TELEMETRY, "ai-security", (CTRL_SERVING_ABUSE,), "Serving runtime emits minimized abuse telemetry to the security boundary."),
    )


def _assessment(control_id: str, status: ControlStatus) -> ControlPostureAssessment:
    severity = AssuranceSeverity.CRITICAL if control_id in {CTRL_TOOL_AUTH, CTRL_MODEL_PROVENANCE, CTRL_RUNTIME_ISOLATION} else AssuranceSeverity.HIGH
    return ControlPostureAssessment(
        control_id=control_id,
        risk_domain="p7a-architecture",
        severity=severity,
        status=status,
        mapped_case_ids=(f"case-{control_id.casefold()}",),
        exception_case_ids=(f"exception-{control_id.casefold()}",) if status == ControlStatus.EXCEPTIONED else (),
        missing_case_ids=(f"missing-{control_id.casefold()}",) if status == ControlStatus.NOT_EVALUATED else (),
        missing_boundaries=(),
        evidence_sha256=hashlib.sha256(f"assessment:{control_id}:{status.value}".encode()).hexdigest(),
    )


def _posture(tool_status: ControlStatus = ControlStatus.EXCEPTIONED) -> VerifiedSecurityPosture:
    assessments = tuple(
        _assessment(control_id, tool_status if control_id == CTRL_TOOL_AUTH else ControlStatus.SATISFIED)
        for control_id in ALL_CONTROLS
    )
    satisfied = tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.SATISFIED))
    exceptioned = tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.EXCEPTIONED))
    not_evaluated = tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.NOT_EVALUATED))
    rating = PostureRating.GREEN if not exceptioned and not not_evaluated else PostureRating.AMBER
    return VerifiedSecurityPosture(
        candidate_release_id="aegisdesk-0.61.0",
        candidate_commit_sha=hashlib.sha256(b"p7a-candidate-commit").hexdigest(),
        candidate_package_version="0.61.0",
        corpus_id="aegis-cross-boundary-security-regressions",
        corpus_version="6.6",
        corpus_sha256=hashlib.sha256(b"p7a-corpus").hexdigest(),
        control_catalog_id="aegis-ai-security-controls",
        control_catalog_version="7.1",
        control_catalog_sha256=CONTROL_CATALOG_SHA,
        waiver_governance_evidence_sha256=hashlib.sha256(b"p7a-waiver-evidence").hexdigest(),
        corpus_evolution_evidence_sha256=hashlib.sha256(b"p7a-evolution-evidence").hexdigest(),
        overall_rating=rating,
        control_count=len(assessments),
        satisfied_control_ids=satisfied,
        exceptioned_control_ids=exceptioned,
        not_evaluated_control_ids=not_evaluated,
        assessments=assessments,
        posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
    )


def _manifest() -> ArchitectureManifest:
    return ArchitectureManifest(
        architecture_id="aegisdesk-ai-security-architecture",
        version="7.1",
        created_at_epoch=MANIFEST_EPOCH,
        assets=_assets(),
        flows=_flows(),
    )


def _secret_path_id() -> str:
    return attack_path_identifier(
        "external-user",
        "secret-store",
        ("external-user", "api-gateway", "agent-orchestrator", "tool-gateway", "secret-store"),
        ("flow-user-api", "flow-api-agent", "flow-agent-tool", "flow-tool-secret"),
    )


def _policy(manifest: ArchitectureManifest) -> AttackPathPolicy:
    assets = {item.asset_id: item for item in manifest.assets}
    flows = {item.flow_id: item for item in manifest.flows}
    return AttackPathPolicy(
        expected_architecture_id=manifest.architecture_id,
        expected_architecture_version=manifest.version,
        expected_architecture_sha256=architecture_manifest_digest(manifest),
        expected_posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
        expected_control_catalog_sha256=CONTROL_CATALOG_SHA,
        attacker_profile_id="external-user-plus-compromised-registry",
        required_asset_ids=frozenset(assets),
        required_flow_ids=frozenset(flows),
        required_entry_asset_ids=frozenset({"external-user", "model-registry"}),
        required_target_asset_ids=frozenset({"secret-store", "model-runtime"}),
        trusted_owner_ids=frozenset({"external", "platform", "data", "ai-security", "model-security"}),
        allowed_trust_zones=frozenset({"internet", "edge", "application", "data", "privileged-tools", "secrets", "model-supply-chain", "inference", "security"}),
        expected_trust_zone_by_asset={asset_id: asset.trust_zone for asset_id, asset in assets.items()},
        minimum_sensitivity_by_asset={
            "secret-store": AssetSensitivity.CRITICAL,
            "model-runtime": AssetSensitivity.CRITICAL,
        },
        expected_flow_endpoints={flow_id: (flow.source_asset_id, flow.target_asset_id) for flow_id, flow in flows.items()},
        expected_control_ids_by_flow={flow_id: frozenset(flow.required_control_ids) for flow_id, flow in flows.items()},
        max_manifest_age_seconds=3_600,
        max_future_skew_seconds=30,
        max_path_hops=8,
        max_paths=128,
    )


def build_fixture(tool_status: ControlStatus = ControlStatus.EXCEPTIONED):
    manifest = _manifest()
    posture = _posture(tool_status)
    max_risk = {
        ControlStatus.EXCEPTIONED: 106,
        ControlStatus.NOT_EVALUATED: 102,
        ControlStatus.SATISFIED: 0,
    }[tool_status]
    exposed = () if tool_status == ControlStatus.SATISFIED else (_secret_path_id(),)
    request = AttackPathRequest(
        architecture_id=manifest.architecture_id,
        architecture_version=manifest.version,
        architecture_sha256=architecture_manifest_digest(manifest),
        posture_evidence_sha256=posture.posture_evidence_sha256,
        attacker_profile_id="external-user-plus-compromised-registry",
        entry_asset_ids=("external-user", "model-registry"),
        target_asset_ids=("model-runtime", "secret-store"),
        evaluated_at_epoch=EVALUATION_EPOCH,
        declared_exposed_path_ids=exposed,
        declared_max_exposed_risk_score=max_risk,
    )
    return {"manifest": manifest, "posture": posture, "policy": _policy(manifest), "request": request}


def _replace_asset(manifest: ArchitectureManifest, asset_id: str, **changes) -> ArchitectureManifest:
    return replace(manifest, assets=tuple(replace(asset, **changes) if asset.asset_id == asset_id else asset for asset in manifest.assets))


def _replace_flow(manifest: ArchitectureManifest, flow_id: str, **changes) -> ArchitectureManifest:
    return replace(manifest, flows=tuple(replace(flow, **changes) if flow.flow_id == flow_id else flow for flow in manifest.flows))


def _repin_manifest(fixture: dict, manifest: ArchitectureManifest) -> dict:
    digest = architecture_manifest_digest(manifest)
    fixture["manifest"] = manifest
    fixture["policy"] = replace(fixture["policy"], expected_architecture_sha256=digest)
    fixture["request"] = replace(fixture["request"], architecture_sha256=digest)
    return fixture


def _replace_posture_assessments(posture: VerifiedSecurityPosture, assessments: tuple[ControlPostureAssessment, ...]) -> VerifiedSecurityPosture:
    return replace(
        posture,
        control_count=len(assessments),
        satisfied_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.NOT_EVALUATED)),
        assessments=assessments,
    )


def adversarial_variants():
    cases: list[tuple[str, dict]] = []

    def add(name: str, fixture: dict) -> None:
        cases.append((name, fixture))

    f = build_fixture(); add("P7A-A01 request architecture digest substitution", {**f, "request": replace(f["request"], architecture_sha256=hashlib.sha256(b"wrong-architecture").hexdigest())})
    f = build_fixture(); add("P7A-A02 invalid architecture schema", _repin_manifest(f, replace(f["manifest"], schema_version="aegis-ai-security-architecture-v0")))
    f = build_fixture(); add("P7A-A03 stale architecture manifest", _repin_manifest(f, replace(f["manifest"], created_at_epoch=EVALUATION_EPOCH - 10_000)))
    f = build_fixture(); add("P7A-A04 future architecture manifest", _repin_manifest(f, replace(f["manifest"], created_at_epoch=EVALUATION_EPOCH + 1_000)))

    f = build_fixture(); duplicate = f["manifest"].assets[0]; add("P7A-A05 duplicate asset ID", _repin_manifest(f, replace(f["manifest"], assets=f["manifest"].assets + (duplicate,))))
    f = build_fixture(); add("P7A-A06 required asset omitted", _repin_manifest(f, replace(f["manifest"], assets=tuple(a for a in f["manifest"].assets if a.asset_id != "secret-store"))))
    f = build_fixture(); add("P7A-A07 untrusted asset owner", _repin_manifest(f, _replace_asset(f["manifest"], "agent-orchestrator", owner_id="shadow-team")))
    f = build_fixture(); add("P7A-A08 invalid trust zone", _repin_manifest(f, _replace_asset(f["manifest"], "agent-orchestrator", trust_zone="unknown-zone")))
    f = build_fixture(); add("P7A-A09 trust-zone reclassification", _repin_manifest(f, _replace_asset(f["manifest"], "agent-orchestrator", trust_zone="data")))
    f = build_fixture(); add("P7A-A10 sensitive target downgrade", _repin_manifest(f, _replace_asset(f["manifest"], "secret-store", sensitivity=AssetSensitivity.HIGH)))
    f = build_fixture(); add("P7A-A11 invalid asset type", _repin_manifest(f, _replace_asset(f["manifest"], "retriever", asset_type="retriever")))

    f = build_fixture(); duplicate_flow = f["manifest"].flows[0]; add("P7A-A12 duplicate flow ID", _repin_manifest(f, replace(f["manifest"], flows=f["manifest"].flows + (duplicate_flow,))))
    f = build_fixture(); add("P7A-A13 required flow omitted", _repin_manifest(f, replace(f["manifest"], flows=tuple(flow for flow in f["manifest"].flows if flow.flow_id != "flow-agent-tool"))))
    f = build_fixture(); add("P7A-A14 untrusted flow owner", _repin_manifest(f, _replace_flow(f["manifest"], "flow-agent-tool", owner_id="shadow-team")))
    f = build_fixture(); add("P7A-A15 unknown flow source", _repin_manifest(f, _replace_flow(f["manifest"], "flow-agent-tool", source_asset_id="missing-agent")))
    f = build_fixture(); add("P7A-A16 flow self-loop", _repin_manifest(f, _replace_flow(f["manifest"], "flow-agent-tool", target_asset_id="agent-orchestrator")))
    f = build_fixture(); add("P7A-A17 flow endpoint substitution", _repin_manifest(f, _replace_flow(f["manifest"], "flow-agent-tool", target_asset_id="model-runtime")))
    f = build_fixture(); add("P7A-A18 duplicate flow controls", _repin_manifest(f, _replace_flow(f["manifest"], "flow-tool-secret", required_control_ids=(CTRL_TOOL_AUTH, CTRL_TOOL_AUTH))))
    f = build_fixture(); add("P7A-A19 flow control substitution", _repin_manifest(f, _replace_flow(f["manifest"], "flow-agent-tool", required_control_ids=(CTRL_INPUT_SAFETY,))))
    f = build_fixture(); add("P7A-A20 unguarded cross-zone flow", _repin_manifest(f, _replace_flow(f["manifest"], "flow-agent-tool", required_control_ids=())))
    f = build_fixture(); add("P7A-A21 invalid flow type", _repin_manifest(f, _replace_flow(f["manifest"], "flow-agent-tool", flow_type="tool_call")))
    f = build_fixture(); extra = ArchitectureFlow("flow-extra-unknown-control", "retriever", "agent-orchestrator", FlowType.AGENT_CONTROL, "platform", ("CTRL-NOT-IN-POSTURE",), "Synthetic reverse control-flow edge with unknown evidence mapping."); add("P7A-A22 unknown control on additional flow", _repin_manifest(f, replace(f["manifest"], flows=f["manifest"].flows + (extra,))))

    f = build_fixture(); add("P7A-A23 P6-D posture verification removed", {**f, "posture": replace(f["posture"], status_derived_from_evidence=False)})
    f = build_fixture(); add("P7A-A24 P6-D posture network operations nonzero", {**f, "posture": replace(f["posture"], network_operations=1)})
    f = build_fixture(); add("P7A-A25 posture evidence digest substitution", {**f, "posture": replace(f["posture"], posture_evidence_sha256=hashlib.sha256(b"wrong-posture").hexdigest())})
    f = build_fixture(); add("P7A-A26 control catalog substitution", {**f, "posture": replace(f["posture"], control_catalog_sha256=hashlib.sha256(b"wrong-catalog").hexdigest())})
    f = build_fixture(); assessments = f["posture"].assessments + (f["posture"].assessments[0],); add("P7A-A27 duplicate control assessment", {**f, "posture": replace(f["posture"], assessments=assessments, control_count=len(assessments))})
    f = build_fixture(); bad = replace(f["posture"].assessments[0], evidence_sha256="bad"); add("P7A-A28 invalid control evidence digest", {**f, "posture": _replace_posture_assessments(f["posture"], (bad,) + f["posture"].assessments[1:])})
    f = build_fixture(); add("P7A-A29 aggregate status list mismatch", {**f, "posture": replace(f["posture"], satisfied_control_ids=f["posture"].satisfied_control_ids + (CTRL_TOOL_AUTH,))})
    f = build_fixture(); add("P7A-A30 control count mismatch", {**f, "posture": replace(f["posture"], control_count=999)})
    f = build_fixture(); assessments = tuple(item for item in f["posture"].assessments if item.control_id != CTRL_TOOL_AUTH); add("P7A-A31 required control assessment omitted", {**f, "posture": _replace_posture_assessments(f["posture"], assessments)})
    f = build_fixture(); bad = replace(f["posture"].assessments[0], status="satisfied"); add("P7A-A32 non-enum control status", {**f, "posture": replace(f["posture"], assessments=(bad,) + f["posture"].assessments[1:])})

    f = build_fixture(); add("P7A-A33 attacker profile substitution", {**f, "request": replace(f["request"], attacker_profile_id="external-user-only")})
    f = build_fixture(); add("P7A-A34 attacker entry omitted", {**f, "request": replace(f["request"], entry_asset_ids=("external-user",))})
    f = build_fixture(); add("P7A-A35 sensitive target omitted", {**f, "request": replace(f["request"], target_asset_ids=("secret-store",))})
    f = build_fixture(); add("P7A-A36 request architecture ID substitution", {**f, "request": replace(f["request"], architecture_id="other-architecture")})
    f = build_fixture(); add("P7A-A37 request architecture version substitution", {**f, "request": replace(f["request"], architecture_version="7.0")})
    f = build_fixture(); add("P7A-A38 request posture digest substitution", {**f, "request": replace(f["request"], posture_evidence_sha256=hashlib.sha256(b"wrong-request-posture").hexdigest())})
    f = build_fixture(); add("P7A-A39 invalid evaluation epoch", {**f, "request": replace(f["request"], evaluated_at_epoch=0)})
    f = build_fixture(); add("P7A-A40 caller omits exposed path", {**f, "request": replace(f["request"], declared_exposed_path_ids=())})
    f = build_fixture(); add("P7A-A41 caller adds nonexistent exposed path", {**f, "request": replace(f["request"], declared_exposed_path_ids=(_secret_path_id(), "path-forged"))})
    f = build_fixture(); add("P7A-A42 caller duplicates exposed path", {**f, "request": replace(f["request"], declared_exposed_path_ids=(_secret_path_id(), _secret_path_id()))})
    f = build_fixture(); add("P7A-A43 caller forges maximum risk", {**f, "request": replace(f["request"], declared_max_exposed_risk_score=1)})

    f = build_fixture(); add("P7A-A44 path-hop truncation", {**f, "policy": replace(f["policy"], max_path_hops=2)})
    f = build_fixture(); add("P7A-A45 path-count truncation", {**f, "policy": replace(f["policy"], max_paths=1)})
    f = build_fixture(); add("P7A-A46 policy entry-target overlap", {**f, "policy": replace(f["policy"], required_target_asset_ids=frozenset({"external-user", "secret-store"}))})
    f = build_fixture(); zones = dict(f["policy"].expected_trust_zone_by_asset); zones.pop("secret-store"); add("P7A-A47 required asset lacks pinned zone", {**f, "policy": replace(f["policy"], expected_trust_zone_by_asset=zones)})
    f = build_fixture(); endpoints = dict(f["policy"].expected_flow_endpoints); endpoints.pop("flow-agent-tool"); add("P7A-A48 required flow lacks pinned endpoints", {**f, "policy": replace(f["policy"], expected_flow_endpoints=endpoints)})
    f = build_fixture(); controls = dict(f["policy"].expected_control_ids_by_flow); controls.pop("flow-agent-tool"); add("P7A-A49 required flow lacks pinned controls", {**f, "policy": replace(f["policy"], expected_control_ids_by_flow=controls)})
    f = build_fixture(); add("P7A-A50 allowed trust zones omit required zone", {**f, "policy": replace(f["policy"], allowed_trust_zones=frozenset(zone for zone in f["policy"].allowed_trust_zones if zone != "secrets"))})
    return cases


def run_hardened(fixture: dict):
    return TrustBoundaryAttackPathAnalyzer(fixture["policy"]).evaluate(
        fixture["request"], fixture["manifest"], fixture["posture"]
    )


def benign_variants():
    return (
        build_fixture(ControlStatus.EXCEPTIONED),
        build_fixture(ControlStatus.SATISFIED),
        build_fixture(ControlStatus.NOT_EVALUATED),
    )


def run_evaluation():
    adversarial = adversarial_variants()
    vulnerable = VulnerableAttackPathReporter()
    vulnerable_successes = 0
    hardened_successes = 0
    results = []
    for name, fixture in adversarial:
        weak = vulnerable.evaluate(
            architecture_id=fixture["manifest"].architecture_id,
            architecture_complete=True,
            declared_exposed_path_count=1,
            declared_max_risk_score=106,
        )
        if weak.accepted:
            vulnerable_successes += 1
        try:
            run_hardened(fixture)
        except AttackPathRejected as exc:
            results.append({"case": name, "hardened": "blocked", "reason": exc.reason.value})
        else:
            hardened_successes += 1
            results.append({"case": name, "hardened": "accepted", "reason": "none"})

    benign = benign_variants()
    benign_pass = 0
    benign_summaries = []
    for fixture in benign:
        try:
            verified = run_hardened(fixture)
            benign_pass += 1
            benign_summaries.append({
                "exposed": verified.exposed_path_count,
                "controlled": verified.controlled_path_count,
                "max_risk": verified.max_exposed_risk_score,
            })
        except AttackPathRejected:
            benign_summaries.append({"exposed": -1, "controlled": -1, "max_risk": -1})

    base = build_fixture()
    dataset_document = [{"id": name.split()[0], "name": name} for name, _ in adversarial]
    dataset_sha = hashlib.sha256(
        json.dumps(dataset_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    fixture_document = {
        "architecture_sha256": architecture_manifest_digest(base["manifest"]),
        "posture_evidence_sha256": base["posture"].posture_evidence_sha256,
        "control_catalog_sha256": base["posture"].control_catalog_sha256,
        "attacker_profile": base["policy"].attacker_profile_id,
        "entries": sorted(base["policy"].required_entry_asset_ids),
        "targets": sorted(base["policy"].required_target_asset_ids),
        "declared_exposed_paths": sorted(base["request"].declared_exposed_path_ids),
        "declared_max_risk": base["request"].declared_max_exposed_risk_score,
    }
    fixture_sha = hashlib.sha256(
        json.dumps(fixture_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    report = {
        "adversarial_cases": len(adversarial),
        "vulnerable_asr": f"{vulnerable_successes}/{len(adversarial)}",
        "hardened_asr": f"{hardened_successes}/{len(adversarial)}",
        "hardened_fpr": f"{len(benign)-benign_pass}/{len(benign)}",
        "safe_task_rate": f"{benign_pass}/{len(benign)}",
        "architecture_sha256": architecture_manifest_digest(base["manifest"]),
        "posture_evidence_sha256": base["posture"].posture_evidence_sha256,
        "control_catalog_sha256": base["posture"].control_catalog_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "benign_summaries": benign_summaries,
        "results": results,
    }
    return report


def main():
    report = run_evaluation()
    print(json.dumps(report, indent=2, sort_keys=True))
    total = report["adversarial_cases"]
    if report["vulnerable_asr"] != f"{total}/{total}":
        raise SystemExit(1)
    if report["hardened_asr"] != f"0/{total}":
        raise SystemExit(1)
    if report["hardened_fpr"] != "0/3" or report["safe_task_rate"] != "3/3":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
