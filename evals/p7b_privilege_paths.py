from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from aegis.architecture.privilege_paths import (
    CapabilitySensitivity, IdentityPrivilegeCapabilityAnalyzer, PrincipalType, PrivilegePathRejected,
    PrivilegeScope, PrivilegeTier, identity_capability_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus
from aegis.vulnerable.privilege_paths import VulnerablePrivilegePathReporter
from .p7b_fixture_defs import *
from .p7b_fixture_defs import _architecture_digest
from .p7b_fixture_identity import *
from .p7b_fixture_build import *
from .p7b_fixture_build import (
    _repin_identity, _replace_capability, _replace_posture_assessments,
    _replace_principal, _replace_transition,
)

def adversarial_variants():
    cases=[]
    def add(name, fixture): cases.append((name, fixture))

    f=build_fixture(); add("P7B-A01 identity digest substitution", {**f,"request":replace(f["request"],identity_graph_sha256=hashlib.sha256(b"wrong-identity").hexdigest())})
    f=build_fixture(); add("P7B-A02 identity schema substitution", _repin_identity(f, replace(f["identity"],schema_version="aegis-identity-capability-graph-v0")))
    f=build_fixture(); add("P7B-A03 stale identity manifest", _repin_identity(f, replace(f["identity"],created_at_epoch=EVALUATION_EPOCH-10_000)))
    f=build_fixture(); add("P7B-A04 future identity manifest", _repin_identity(f, replace(f["identity"],created_at_epoch=EVALUATION_EPOCH+1_000)))
    f=build_fixture(); add("P7B-A05 architecture binding substitution in identity manifest", _repin_identity(f, replace(f["identity"],architecture_sha256=hashlib.sha256(b"other-architecture").hexdigest())))

    f=build_fixture(); p=f["identity"].principals[0]; add("P7B-A06 duplicate principal", _repin_identity(f, replace(f["identity"],principals=f["identity"].principals+(p,))))
    f=build_fixture(); add("P7B-A07 required principal omitted", _repin_identity(f, replace(f["identity"],principals=tuple(p for p in f["identity"].principals if p.principal_id!="secret-broker-principal"))))
    f=build_fixture(); add("P7B-A08 untrusted principal owner", _repin_identity(f, _replace_principal(f["identity"],"agent-service-principal",owner_id="shadow-team")))
    f=build_fixture(); add("P7B-A09 principal home asset substitution", _repin_identity(f, _replace_principal(f["identity"],"agent-service-principal",home_asset_id="tool-gateway")))
    f=build_fixture(); add("P7B-A10 principal type substitution", _repin_identity(f, _replace_principal(f["identity"],"agent-service-principal",principal_type=PrincipalType.SECURITY_IDENTITY)))
    f=build_fixture(); add("P7B-A11 principal tier downgrade", _repin_identity(f, _replace_principal(f["identity"],"tool-service-principal",privilege_tier=PrivilegeTier.SERVICE)))
    f=build_fixture(); add("P7B-A12 principal scope substitution", _repin_identity(f, _replace_principal(f["identity"],"tool-service-principal",privilege_scope=PrivilegeScope.SECURITY)))
    f=build_fixture(); add("P7B-A13 native capability substitution", _repin_identity(f, _replace_principal(f["identity"],"agent-service-principal",native_capability_ids=(CAP_INVOKE_AGENT,CAP_READ_SECRET))))
    f=build_fixture(); add("P7B-A14 invalid principal enum", _repin_identity(f, _replace_principal(f["identity"],"tenant-user-principal",privilege_tier="tenant")))

    f=build_fixture(); c=f["identity"].capabilities[0]; add("P7B-A15 duplicate capability", _repin_identity(f, replace(f["identity"],capabilities=f["identity"].capabilities+(c,))))
    f=build_fixture(); add("P7B-A16 required capability omitted", _repin_identity(f, replace(f["identity"],capabilities=tuple(c for c in f["identity"].capabilities if c.capability_id!=CAP_READ_SECRET))))
    f=build_fixture(); add("P7B-A17 untrusted capability owner", _repin_identity(f, _replace_capability(f["identity"],CAP_READ_SECRET,owner_id="shadow-team")))
    f=build_fixture(); add("P7B-A18 capability target substitution", _repin_identity(f, _replace_capability(f["identity"],CAP_READ_SECRET,target_asset_id="model-runtime")))
    f=build_fixture(); add("P7B-A19 capability sensitivity downgrade", _repin_identity(f, _replace_capability(f["identity"],CAP_READ_SECRET,sensitivity=CapabilitySensitivity.HIGH)))
    f=build_fixture(); add("P7B-A20 capability tier downgrade", _repin_identity(f, _replace_capability(f["identity"],CAP_READ_SECRET,minimum_privilege_tier=PrivilegeTier.PRIVILEGED)))
    f=build_fixture(); add("P7B-A21 invalid capability sensitivity enum", _repin_identity(f, _replace_capability(f["identity"],CAP_READ_SECRET,sensitivity="critical")))

    f=build_fixture(); e=f["identity"].transitions[0]; add("P7B-A22 duplicate transition", _repin_identity(f, replace(f["identity"],transitions=f["identity"].transitions+(e,))))
    f=build_fixture(); add("P7B-A23 required transition omitted", _repin_identity(f, replace(f["identity"],transitions=tuple(e for e in f["identity"].transitions if e.edge_id!="edge-agent-tool"))))
    f=build_fixture(); add("P7B-A24 untrusted transition owner", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",owner_id="shadow-team")))
    f=build_fixture(); add("P7B-A25 transition source substitution", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",source_principal_id="external-user-principal")))
    f=build_fixture(); add("P7B-A26 transition self-loop", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",target_principal_id="agent-service-principal")))
    f=build_fixture(); add("P7B-A27 transition route substitution", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",via_flow_ids=("flow-agent-runtime",))))
    f=build_fixture(); add("P7B-A28 transition control substitution", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",required_control_ids=(CTRL_SERVER_PRINCIPAL,))))
    f=build_fixture(); add("P7B-A29 transition capability grant substitution", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",granted_capability_ids=(CAP_READ_SECRET,))))
    f=build_fixture(); add("P7B-A30 duplicate transition controls", _repin_identity(f, _replace_transition(f["identity"],"edge-tool-secret",required_control_ids=(CTRL_CREDENTIAL_BROKER,CTRL_CREDENTIAL_BROKER))))
    f=build_fixture(); add("P7B-A31 invalid transition delegation enum", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",delegation_type="tool_authorization")))
    f=build_fixture(); add("P7B-A32 unknown transition flow", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",via_flow_ids=("missing-flow",))))
    f=build_fixture(); add("P7B-A33 unknown transition control", _repin_identity(f, _replace_transition(f["identity"],"edge-agent-tool",required_control_ids=("CTRL-UNKNOWN",))))

    f=build_fixture(); add("P7B-A34 degraded P7-A assessment", {**f,"assessment":replace(f["assessment"],required_graph_coverage_verified=False)})
    f=build_fixture(); add("P7B-A35 P7-A architecture digest substitution", {**f,"assessment":replace(f["assessment"],architecture_sha256=hashlib.sha256(b"wrong-p7a-architecture").hexdigest())})
    f=build_fixture(); add("P7B-A36 P7-A evidence digest substitution", {**f,"assessment":replace(f["assessment"],assessment_evidence_sha256=hashlib.sha256(b"wrong-p7a-evidence").hexdigest())})
    f=build_fixture(); add("P7B-A37 P7-A posture digest mismatch", {**f,"assessment":replace(f["assessment"],posture_evidence_sha256=hashlib.sha256(b"wrong-p7a-posture").hexdigest())})

    f=build_fixture(); add("P7B-A38 degraded P6-D posture", {**f,"posture":replace(f["posture"],status_derived_from_evidence=False)})
    f=build_fixture(); add("P7B-A39 P6-D posture digest substitution", {**f,"posture":replace(f["posture"],posture_evidence_sha256=hashlib.sha256(b"wrong-posture").hexdigest())})
    f=build_fixture(); add("P7B-A40 control catalog substitution", {**f,"posture":replace(f["posture"],control_catalog_sha256=hashlib.sha256(b"wrong-catalog").hexdigest())})
    f=build_fixture(); assessments=f["posture"].assessments+(f["posture"].assessments[0],); add("P7B-A41 duplicate control assessment", {**f,"posture":replace(f["posture"],assessments=assessments,control_count=len(assessments))})
    f=build_fixture(); bad=replace(f["posture"].assessments[0],evidence_sha256="bad"); add("P7B-A42 invalid control evidence digest", {**f,"posture":_replace_posture_assessments(f["posture"],(bad,)+f["posture"].assessments[1:])})
    f=build_fixture(); add("P7B-A43 aggregate control status mismatch", {**f,"posture":replace(f["posture"],satisfied_control_ids=f["posture"].satisfied_control_ids+(CTRL_TOOL_AUTH,))})
    f=build_fixture(); assessments=tuple(a for a in f["posture"].assessments if a.control_id!=CTRL_TOOL_AUTH); add("P7B-A44 route control evidence omitted", {**f,"posture":_replace_posture_assessments(f["posture"],assessments)})

    f=build_fixture(); add("P7B-A45 entry principal omitted", {**f,"request":replace(f["request"],entry_principal_ids=("external-user-principal",))})
    f=build_fixture(); add("P7B-A46 target capability omitted", {**f,"request":replace(f["request"],target_capability_ids=(CAP_READ_SECRET,))})
    f=build_fixture(); add("P7B-A47 request architecture digest substitution", {**f,"request":replace(f["request"],architecture_sha256=hashlib.sha256(b"wrong-request-architecture").hexdigest())})
    f=build_fixture(); add("P7B-A48 request P7-A evidence substitution", {**f,"request":replace(f["request"],p7a_assessment_evidence_sha256=hashlib.sha256(b"wrong-request-p7a").hexdigest())})
    f=build_fixture(); add("P7B-A49 caller omits exposed privilege path", {**f,"request":replace(f["request"],declared_exposed_path_ids=())})
    f=build_fixture(); add("P7B-A50 caller forges max privilege risk", {**f,"request":replace(f["request"],declared_max_exposed_risk_score=1)})
    f=build_fixture(); add("P7B-A51 path-hop truncation", {**f,"policy":replace(f["policy"],max_path_hops=2)})
    f=build_fixture(); add("P7B-A52 path-count truncation", {**f,"policy":replace(f["policy"],max_paths=1)})
    f=build_fixture(); tiers=dict(f["policy"].expected_tier_by_principal); tiers.pop("tool-service-principal"); add("P7B-A53 required principal lacks tier pin", {**f,"policy":replace(f["policy"],expected_tier_by_principal=tiers)})
    f=build_fixture(); grants=dict(f["policy"].expected_granted_capability_ids_by_transition); grants.pop("edge-tool-secret"); add("P7B-A54 required transition lacks grant pin", {**f,"policy":replace(f["policy"],expected_granted_capability_ids_by_transition=grants)})
    return cases


def run_hardened(fixture):
    return IdentityPrivilegeCapabilityAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],fixture["identity"],fixture["architecture"],fixture["assessment"],fixture["posture"]
    )


def benign_variants():
    return (build_fixture(ControlStatus.EXCEPTIONED),build_fixture(ControlStatus.SATISFIED),build_fixture(ControlStatus.NOT_EVALUATED))


def run_evaluation():
    adversarial=adversarial_variants(); weak=VulnerablePrivilegePathReporter(); vulnerable_successes=0; hardened_successes=0; results=[]
    for name,fixture in adversarial:
        if weak.evaluate(identity_graph_id=fixture["identity"].identity_graph_id,identity_complete=True,declared_exposed_path_count=1,declared_max_risk_score=139).accepted:
            vulnerable_successes+=1
        try:
            run_hardened(fixture)
        except PrivilegePathRejected as exc:
            results.append({"case":name,"hardened":"blocked","reason":exc.reason.value})
        else:
            hardened_successes+=1; results.append({"case":name,"hardened":"accepted","reason":"none"})
    benign=benign_variants(); benign_pass=0; benign_summaries=[]
    for fixture in benign:
        try:
            verified=run_hardened(fixture); benign_pass+=1
            benign_summaries.append({"topology":verified.topology_path_count,"exposed":verified.exposed_path_count,"controlled":verified.controlled_path_count,"max_risk":verified.max_exposed_risk_score})
        except PrivilegePathRejected:
            benign_summaries.append({"topology":-1,"exposed":-1,"controlled":-1,"max_risk":-1})
    base=build_fixture()
    dataset_sha=hashlib.sha256(json.dumps([{"id":n.split()[0],"name":n} for n,_ in adversarial],sort_keys=True,separators=(",",":")).encode()).hexdigest()
    fixture_doc={"architecture":_architecture_digest(base["architecture"]),"identity":identity_capability_manifest_digest(base["identity"]),"p7a":base["assessment"].assessment_evidence_sha256,"posture":base["posture"].posture_evidence_sha256,"catalog":base["posture"].control_catalog_sha256,"entries":sorted(base["policy"].entry_principal_ids),"targets":sorted(base["policy"].target_capability_ids),"declared":sorted(base["request"].declared_exposed_path_ids),"risk":base["request"].declared_max_exposed_risk_score}
    fixture_sha=hashlib.sha256(json.dumps(fixture_doc,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"adversarial_cases":len(adversarial),"vulnerable_asr":f"{vulnerable_successes}/{len(adversarial)}","hardened_asr":f"{hardened_successes}/{len(adversarial)}","hardened_fpr":f"{len(benign)-benign_pass}/{len(benign)}","safe_task_rate":f"{benign_pass}/{len(benign)}","architecture_sha256":_architecture_digest(base["architecture"]),"identity_graph_sha256":identity_capability_manifest_digest(base["identity"]),"p7a_assessment_evidence_sha256":base["assessment"].assessment_evidence_sha256,"posture_evidence_sha256":base["posture"].posture_evidence_sha256,"control_catalog_sha256":base["posture"].control_catalog_sha256,"dataset_sha256":dataset_sha,"fixture_sha256":fixture_sha,"benign_summaries":benign_summaries,"results":results}

def main():
    report=run_evaluation(); print(json.dumps(report,indent=2,sort_keys=True)); total=report["adversarial_cases"]
    if report["vulnerable_asr"]!=f"{total}/{total}" or report["hardened_asr"]!=f"0/{total}" or report["hardened_fpr"]!="0/3" or report["safe_task_rate"]!="3/3": raise SystemExit(1)
if __name__=="__main__": main()
