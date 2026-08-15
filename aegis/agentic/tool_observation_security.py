from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8D_TOOL_POLICY_VERSION = "agent-tool-observation-environment-integrity-v1"
P8D_TOOL_SCHEMA_VERSION = "aegis-agent-tool-observation-manifest-v1"
P8D_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-tool-observation-assessment-v1"
P8D_ASSESSMENT_MODE = "deterministic-evidence-bound-tool-observation-v1"


class ToolEffect(StrEnum): READ_ONLY="read_only"; MUTATING="mutating"; IRREVERSIBLE="irreversible"
class ObservationTrust(StrEnum): UNTRUSTED="untrusted"; TOOL_ASSERTED="tool_asserted"; VERIFIED="verified"
class ObservationDecision(StrEnum): ALLOW="allow"; DENY="deny"
class ObservationRisk(StrEnum):
    INVOCATION_RESULT_MISMATCH="invocation_result_mismatch"; TOOL_IDENTITY_MISMATCH="tool_identity_mismatch"; ARGUMENT_DIGEST_MISMATCH="argument_digest_mismatch"
    TENANT_MISMATCH="tenant_mismatch"; TASK_MISMATCH="task_mismatch"; PRINCIPAL_MISMATCH="principal_mismatch"; GOAL_STEP_MISMATCH="goal_step_mismatch"
    STALE_RESULT="stale_result"; REPLAY_RESULT="replay_result"; RESULT_TIME_INVALID="result_time_invalid"
    SIDE_EFFECT_UNACKNOWLEDGED="side_effect_unacknowledged"; SIDE_EFFECT_ACK_MISMATCH="side_effect_ack_mismatch"
    ENVIRONMENT_STATE_SPOOF="environment_state_spoof"; ENVIRONMENT_VERSION_REGRESSION="environment_version_regression"
    OBSERVATION_LAUNDERING="observation_laundering"; OBSERVATION_TRUST_MISMATCH="observation_trust_mismatch"
    UPSTREAM_PLAN_UNSAFE="upstream_plan_unsafe"; UPSTREAM_DELEGATION_UNSAFE="upstream_delegation_unsafe"; REQUIRED_INVARIANT_UNSAFE="required_invariant_unsafe"


class ObservationRejectReason(StrEnum):
    POLICY_INVALID="policy_invalid"; REQUEST_INVALID="request_invalid"; UPSTREAM_INVALID="upstream_invalid"; MANIFEST_INVALID="manifest_invalid"
    COVERAGE_MISMATCH="coverage_mismatch"; OWNER_UNTRUSTED="owner_untrusted"; POLICY_DRIFT="policy_drift"; REFERENCE_INVALID="reference_invalid"
    DECLARED_DECISION_MISMATCH="declared_decision_mismatch"; DECLARED_RISK_MISMATCH="declared_risk_mismatch"


class ToolObservationSecurityRejected(ValueError):
    def __init__(self, reason: ObservationRejectReason, message: str, *, item_id: str | None=None):
        super().__init__(message); self.reason=reason; self.item_id=item_id


@dataclass(frozen=True)
class ToolContract:
    tool_id:str; owner_id:str; tenant_scope:str; effect:ToolEffect; authoritative_result:bool; max_result_age_seconds:int; requires_side_effect_ack:bool; required_p7i_invariant_ids:tuple[str,...]; description:str
@dataclass(frozen=True)
class EnvironmentSnapshot:
    snapshot_id:str; tenant_id:str; state_version:int; state_sha256:str; observed_at_epoch:int; owner_id:str; description:str
@dataclass(frozen=True)
class ToolInvocation:
    invocation_id:str; tool_id:str; agent_id:str; original_principal_id:str; tenant_id:str; task_id:str; goal_id:str; step_id:str; delegation_id:str|None; args_sha256:str; environment_snapshot_id:str; issued_at_epoch:int; owner_id:str; description:str
@dataclass(frozen=True)
class ToolResult:
    result_id:str; invocation_id:str; tool_id:str; args_sha256:str; payload_sha256:str; result_nonce:str; environment_snapshot_id:str; observed_environment_version:int; observed_environment_state_sha256:str; side_effect_id:str|None; side_effect_ack_sha256:str|None; attestation_sha256:str|None; produced_at_epoch:int; expires_at_epoch:int; owner_id:str; description:str
@dataclass(frozen=True)
class ToolObservation:
    observation_id:str; result_id:str; invocation_id:str; tool_id:str; original_principal_id:str; tenant_id:str; task_id:str; goal_id:str; step_id:str; environment_snapshot_id:str; environment_version:int; environment_state_sha256:str; content_sha256:str; claimed_trust:ObservationTrust; owner_id:str; description:str
@dataclass(frozen=True)
class ToolObservationManifest:
    graph_id:str; version:str; p8a_assessment_evidence_sha256:str; p8c_assessment_evidence_sha256:str; p7i_assessment_evidence_sha256:str; created_at_epoch:int; contracts:tuple[ToolContract,...]; snapshots:tuple[EnvironmentSnapshot,...]; invocations:tuple[ToolInvocation,...]; results:tuple[ToolResult,...]; observations:tuple[ToolObservation,...]; schema_version:str=P8D_TOOL_SCHEMA_VERSION
@dataclass(frozen=True)
class ToolObservationPolicy:
    expected_graph_id:str; expected_graph_version:str; expected_graph_sha256:str; expected_p8a_assessment_evidence_sha256:str; expected_p8c_assessment_evidence_sha256:str; expected_p7i_assessment_evidence_sha256:str
    required_contract_ids:frozenset[str]; required_snapshot_ids:frozenset[str]; required_invocation_ids:frozenset[str]; required_result_ids:frozenset[str]; required_observation_ids:frozenset[str]; trusted_owner_ids:frozenset[str]
    expected_contract_tenant_scope:Mapping[str,str]; expected_contract_effect:Mapping[str,ToolEffect]; expected_contract_authoritative:Mapping[str,bool]; expected_contract_max_age:Mapping[str,int]; expected_contract_requires_ack:Mapping[str,bool]; expected_contract_invariant_ids:Mapping[str,frozenset[str]]
    expected_snapshot_tenant:Mapping[str,str]; expected_snapshot_state_version:Mapping[str,int]; expected_snapshot_state_sha256:Mapping[str,str]; allowed_attestation_sha256:frozenset[str]; max_manifest_age_seconds:int=86400; max_future_skew_seconds:int=30
@dataclass(frozen=True)
class ToolObservationRequest:
    graph_id:str; graph_version:str; graph_sha256:str; p8a_assessment_evidence_sha256:str; p8c_assessment_evidence_sha256:str; p7i_assessment_evidence_sha256:str; evaluated_at_epoch:int; observation_ids:tuple[str,...]; declared_denied_observation_ids:tuple[str,...]; declared_risks_by_observation:Mapping[str,tuple[ObservationRisk,...]]
@dataclass(frozen=True)
class ToolObservationFact:
    observation_id:str; invocation_id:str; result_id:str; tool_id:str; decision:ObservationDecision; risks:tuple[ObservationRisk,...]; derived_trust:ObservationTrust; tenant_id:str; task_id:str; goal_id:str; step_id:str; environment_version:int; side_effect_acknowledged:bool; replay_detected:bool; p7i_invariant_ids:tuple[str,...]
@dataclass(frozen=True)
class VerifiedToolObservationAssessment:
    graph_id:str; graph_version:str; graph_sha256:str; p8a_assessment_evidence_sha256:str; p8c_assessment_evidence_sha256:str; p7i_assessment_evidence_sha256:str; observation_count:int; allowed_observation_count:int; denied_observation_count:int; stale_or_replay_denial_count:int; side_effect_integrity_denial_count:int; environment_integrity_denial_count:int; observation_laundering_denial_count:int; upstream_safety_denial_count:int; observations:tuple[ToolObservationFact,...]; assessment_evidence_sha256:str
    exact_tool_observation_graph_binding_verified:bool=True; exact_p8a_delegation_binding_verified:bool=True; exact_p8c_goal_plan_binding_verified:bool=True; exact_p7i_invariant_binding_verified:bool=True; invocation_result_binding_verified:bool=True; observation_origin_provenance_verified:bool=True; replay_and_staleness_checked:bool=True; side_effect_acknowledgement_verified:bool=True; environment_state_integrity_verified:bool=True; observation_trust_derived_from_evidence:bool=True; caller_declared_tool_observation_safety_trusted:bool=False; production_tool_runtime_enforcement:bool=False; production_environment_attestation:bool=False; cryptographic_tool_result_attestation:bool=False; semantic_tool_output_safety_proof:bool=False; exhaustive_environment_state_coverage:bool=False; network_operations:int=0; schema_version:str=P8D_ASSESSMENT_SCHEMA_VERSION; policy_version:str=P8D_TOOL_POLICY_VERSION; assessment_mode:str=P8D_ASSESSMENT_MODE


def _reject(reason, message, item_id=None): raise ToolObservationSecurityRejected(reason, message, item_id=item_id)
def _sha(v): return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v.casefold())
def _digest(v): return str(getattr(v,"assessment_evidence_sha256","")).casefold()
def _allowed(v): return str(getattr(getattr(v,"decision",""),"value",getattr(v,"decision",""))).casefold() in {"allow","allowed","safe"}
def _ack(s,p,v): return hashlib.sha256(f"{s}:{p.casefold()}:{v}".encode()).hexdigest()

def _norm(v):
    if is_dataclass(v): return _norm(asdict(v))
    if isinstance(v,StrEnum): return v.value
    if isinstance(v,dict): return {str(k):_norm(v[k]) for k in sorted(v)}
    if isinstance(v,(tuple,list,set,frozenset)): return [_norm(x) for x in sorted(v,key=lambda x:str(getattr(x,"value",x)))]
    if isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdefABCDEF" for c in v): return v.casefold()
    return v

def canonical_tool_observation_manifest_bytes(m): return json.dumps(_norm(m),sort_keys=True,separators=(",",":")).encode()
def tool_observation_manifest_digest(m): return hashlib.sha256(canonical_tool_observation_manifest_bytes(m)).hexdigest()

def _assessment_digest(facts,m):
    d={"graph_sha256":tool_observation_manifest_digest(m),"facts":[{"id":f.observation_id,"decision":f.decision.value,"risks":[r.value for r in f.risks],"trust":f.derived_trust.value,"version":f.environment_version,"ack":f.side_effect_acknowledged,"replay":f.replay_detected} for f in facts]}
    return hashlib.sha256(json.dumps(d,sort_keys=True,separators=(",",":")).encode()).hexdigest()


class AgentToolObservationIntegrityAnalyzer:
    def __init__(self,policy): self.policy=policy
    def _policy(self):
        p=self.policy
        if not p.expected_graph_id or not p.expected_graph_version or not _sha(p.expected_graph_sha256) or not all(_sha(x) for x in (p.expected_p8a_assessment_evidence_sha256,p.expected_p8c_assessment_evidence_sha256,p.expected_p7i_assessment_evidence_sha256)) or not p.trusted_owner_ids or p.max_manifest_age_seconds<=0 or p.max_future_skew_seconds<0: _reject(ObservationRejectReason.POLICY_INVALID,"invalid policy")
    def _upstream(self,m,p8a,p8c,p7i):
        p=self.policy
        checks=((p8a,p.expected_p8a_assessment_evidence_sha256,m.p8a_assessment_evidence_sha256,"exact_agent_delegation_graph_binding_verified","caller_declared_delegation_authorization_trusted"),(p8c,p.expected_p8c_assessment_evidence_sha256,m.p8c_assessment_evidence_sha256,"exact_goal_plan_graph_binding_verified","caller_declared_goal_plan_safety_trusted"),(p7i,p.expected_p7i_assessment_evidence_sha256,m.p7i_assessment_evidence_sha256,"exact_architecture_binding_verified","caller_declared_architecture_safety_trusted"))
        for obj,pin,md,flag,caller in checks:
            if _digest(obj)!=pin.casefold() or md.casefold()!=pin.casefold() or not bool(getattr(obj,flag,False)) or bool(getattr(obj,caller,True)): _reject(ObservationRejectReason.UPSTREAM_INVALID,"unverified upstream evidence")
    def _map(self,items,attr):
        out={}
        for x in items:
            k=str(getattr(x,attr))
            if k in out: _reject(ObservationRejectReason.COVERAGE_MISMATCH,"duplicate id",k)
            out[k]=x
        return out
    def _manifest(self,m,now):
        p=self.policy
        if m.schema_version!=P8D_TOOL_SCHEMA_VERSION or m.graph_id!=p.expected_graph_id or m.version!=p.expected_graph_version or tool_observation_manifest_digest(m)!=p.expected_graph_sha256.casefold() or now-m.created_at_epoch>p.max_manifest_age_seconds or m.created_at_epoch-now>p.max_future_skew_seconds: _reject(ObservationRejectReason.MANIFEST_INVALID,"manifest binding/freshness invalid")
        C=self._map(m.contracts,"tool_id"); S=self._map(m.snapshots,"snapshot_id"); I=self._map(m.invocations,"invocation_id"); R=self._map(m.results,"result_id"); O=self._map(m.observations,"observation_id")
        for got,need in ((C,p.required_contract_ids),(S,p.required_snapshot_ids),(I,p.required_invocation_ids),(R,p.required_result_ids),(O,p.required_observation_ids)):
            if set(got)!=set(need): _reject(ObservationRejectReason.COVERAGE_MISMATCH,"coverage mismatch")
        for k,c in C.items():
            if c.owner_id not in p.trusted_owner_ids: _reject(ObservationRejectReason.OWNER_UNTRUSTED,"contract owner",k)
            if (c.tenant_scope,c.effect,c.authoritative_result,c.max_result_age_seconds,c.requires_side_effect_ack,frozenset(c.required_p7i_invariant_ids))!=(p.expected_contract_tenant_scope.get(k),p.expected_contract_effect.get(k),p.expected_contract_authoritative.get(k),p.expected_contract_max_age.get(k),p.expected_contract_requires_ack.get(k),p.expected_contract_invariant_ids.get(k)): _reject(ObservationRejectReason.POLICY_DRIFT,"contract drift",k)
        for k,s in S.items():
            if s.owner_id not in p.trusted_owner_ids: _reject(ObservationRejectReason.OWNER_UNTRUSTED,"snapshot owner",k)
            if (s.tenant_id,s.state_version,s.state_sha256.casefold())!=(p.expected_snapshot_tenant.get(k),p.expected_snapshot_state_version.get(k),p.expected_snapshot_state_sha256.get(k,"").casefold()) or not _sha(s.state_sha256): _reject(ObservationRejectReason.POLICY_DRIFT,"snapshot drift",k)
        for k,i in I.items():
            if i.owner_id not in p.trusted_owner_ids: _reject(ObservationRejectReason.OWNER_UNTRUSTED,"invocation owner",k)
            if i.tool_id not in C or i.environment_snapshot_id not in S or not _sha(i.args_sha256): _reject(ObservationRejectReason.REFERENCE_INVALID,"invocation reference",k)
        for k,r in R.items():
            if r.owner_id not in p.trusted_owner_ids: _reject(ObservationRejectReason.OWNER_UNTRUSTED,"result owner",k)
            if r.invocation_id not in I or r.tool_id not in C or r.environment_snapshot_id not in S or not all(_sha(x) for x in (r.args_sha256,r.payload_sha256,r.observed_environment_state_sha256)) or (r.side_effect_ack_sha256 is not None and not _sha(r.side_effect_ack_sha256)) or (r.attestation_sha256 is not None and not _sha(r.attestation_sha256)): _reject(ObservationRejectReason.REFERENCE_INVALID,"result reference",k)
        for k,o in O.items():
            if o.owner_id not in p.trusted_owner_ids: _reject(ObservationRejectReason.OWNER_UNTRUSTED,"observation owner",k)
            if o.result_id not in R or o.invocation_id not in I or o.tool_id not in C or o.environment_snapshot_id not in S or not _sha(o.environment_state_sha256) or not _sha(o.content_sha256): _reject(ObservationRejectReason.REFERENCE_INVALID,"observation reference",k)
        return C,S,I,R,O
    def derive(self,m,p8a,p8c,p7i,evaluated_at_epoch):
        self._policy(); self._upstream(m,p8a,p8c,p7i); p=self.policy; C,S,I,R,O=self._manifest(m,evaluated_at_epoch)
        deleg={str(getattr(x,"delegation_id","")):x for x in getattr(p8a,"delegations",())}; steps={str(getattr(x,"step_id","")):x for x in getattr(p8c,"steps",())}; unsafe=frozenset(str(x) for x in getattr(p7i,"unsafe_invariant_ids",()))
        nonces={}; [nonces.__setitem__(r.result_nonce,nonces.get(r.result_nonce,0)+1) for r in R.values()]
        facts=[]
        for oid in sorted(O):
            o=O[oid]; r=R[o.result_id]; i=I[o.invocation_id]; c=C[o.tool_id]; b=S[i.environment_snapshot_id]; s=S[o.environment_snapshot_id]; risks=set()
            if r.invocation_id!=i.invocation_id: risks.add(ObservationRisk.INVOCATION_RESULT_MISMATCH)
            if r.tool_id!=i.tool_id or o.tool_id!=i.tool_id: risks.add(ObservationRisk.TOOL_IDENTITY_MISMATCH)
            if not hmac.compare_digest(r.args_sha256.casefold(),i.args_sha256.casefold()): risks.add(ObservationRisk.ARGUMENT_DIGEST_MISMATCH)
            if o.tenant_id!=i.tenant_id or (c.tenant_scope not in {"shared","system"} and c.tenant_scope!=i.tenant_id): risks.add(ObservationRisk.TENANT_MISMATCH)
            if o.task_id!=i.task_id: risks.add(ObservationRisk.TASK_MISMATCH)
            if o.original_principal_id!=i.original_principal_id: risks.add(ObservationRisk.PRINCIPAL_MISMATCH)
            if o.goal_id!=i.goal_id or o.step_id!=i.step_id: risks.add(ObservationRisk.GOAL_STEP_MISMATCH)
            if r.produced_at_epoch<i.issued_at_epoch or r.expires_at_epoch<r.produced_at_epoch or r.produced_at_epoch>evaluated_at_epoch+p.max_future_skew_seconds: risks.add(ObservationRisk.RESULT_TIME_INVALID)
            if evaluated_at_epoch>r.expires_at_epoch or evaluated_at_epoch-r.produced_at_epoch>c.max_result_age_seconds: risks.add(ObservationRisk.STALE_RESULT)
            if nonces.get(r.result_nonce,0)>1: risks.add(ObservationRisk.REPLAY_RESULT)
            if r.environment_snapshot_id!=i.environment_snapshot_id or o.environment_version!=r.observed_environment_version or not hmac.compare_digest(o.environment_state_sha256.casefold(),r.observed_environment_state_sha256.casefold()) or not hmac.compare_digest(o.environment_state_sha256.casefold(),s.state_sha256.casefold()): risks.add(ObservationRisk.ENVIRONMENT_STATE_SPOOF)
            if r.observed_environment_version<b.state_version or o.environment_version<b.state_version: risks.add(ObservationRisk.ENVIRONMENT_VERSION_REGRESSION)
            acked=True
            if c.requires_side_effect_ack or c.effect!=ToolEffect.READ_ONLY:
                acked=False
                if not r.side_effect_id or not r.side_effect_ack_sha256: risks.add(ObservationRisk.SIDE_EFFECT_UNACKNOWLEDGED)
                elif not hmac.compare_digest(r.side_effect_ack_sha256.casefold(),_ack(r.side_effect_id,r.payload_sha256,r.observed_environment_version)): risks.add(ObservationRisk.SIDE_EFFECT_ACK_MISMATCH)
                else: acked=True
            if i.step_id not in steps or not _allowed(steps[i.step_id]): risks.add(ObservationRisk.UPSTREAM_PLAN_UNSAFE)
            if i.delegation_id and (i.delegation_id not in deleg or not _allowed(deleg[i.delegation_id])): risks.add(ObservationRisk.UPSTREAM_DELEGATION_UNSAFE)
            if frozenset(c.required_p7i_invariant_ids)&unsafe: risks.add(ObservationRisk.REQUIRED_INVARIANT_UNSAFE)
            attested=bool(r.attestation_sha256 and r.attestation_sha256.casefold() in p.allowed_attestation_sha256); trust=ObservationTrust.VERIFIED if c.authoritative_result and attested and not risks else ObservationTrust.TOOL_ASSERTED
            if o.claimed_trust==ObservationTrust.VERIFIED and trust!=ObservationTrust.VERIFIED: risks.add(ObservationRisk.OBSERVATION_LAUNDERING)
            if o.claimed_trust!=trust: risks.add(ObservationRisk.OBSERVATION_TRUST_MISMATCH)
            facts.append(ToolObservationFact(oid,i.invocation_id,r.result_id,c.tool_id,ObservationDecision.ALLOW if not risks else ObservationDecision.DENY,tuple(sorted(risks,key=lambda x:x.value)),trust,o.tenant_id,o.task_id,o.goal_id,o.step_id,o.environment_version,acked,ObservationRisk.REPLAY_RESULT in risks,tuple(sorted(c.required_p7i_invariant_ids))))
        return tuple(facts)
    def evaluate(self,q,m,p8a,p8c,p7i):
        self._policy(); p=self.policy
        if (q.graph_id,q.graph_version,q.graph_sha256.casefold())!=(p.expected_graph_id,p.expected_graph_version,p.expected_graph_sha256.casefold()) or (q.p8a_assessment_evidence_sha256.casefold(),q.p8c_assessment_evidence_sha256.casefold(),q.p7i_assessment_evidence_sha256.casefold())!=(p.expected_p8a_assessment_evidence_sha256.casefold(),p.expected_p8c_assessment_evidence_sha256.casefold(),p.expected_p7i_assessment_evidence_sha256.casefold()) or set(q.observation_ids)!=set(p.required_observation_ids) or len(q.observation_ids)!=len(set(q.observation_ids)): _reject(ObservationRejectReason.REQUEST_INVALID,"request binding invalid")
        facts=self.derive(m,p8a,p8c,p7i,q.evaluated_at_epoch); denied=tuple(sorted(f.observation_id for f in facts if f.decision==ObservationDecision.DENY))
        if tuple(sorted(q.declared_denied_observation_ids))!=denied: _reject(ObservationRejectReason.DECLARED_DECISION_MISMATCH,"caller denial mismatch")
        if set(q.declared_risks_by_observation)!=set(p.required_observation_ids): _reject(ObservationRejectReason.DECLARED_RISK_MISMATCH,"caller risk coverage")
        fm={f.observation_id:f for f in facts}
        for oid in p.required_observation_ids:
            if tuple(sorted(q.declared_risks_by_observation[oid],key=lambda x:x.value))!=fm[oid].risks: _reject(ObservationRejectReason.DECLARED_RISK_MISMATCH,"caller risk mismatch",oid)
        def count(rs): return sum(bool(set(f.risks)&rs) for f in facts)
        return VerifiedToolObservationAssessment(m.graph_id,m.version,tool_observation_manifest_digest(m),m.p8a_assessment_evidence_sha256,m.p8c_assessment_evidence_sha256,m.p7i_assessment_evidence_sha256,len(facts),sum(f.decision==ObservationDecision.ALLOW for f in facts),sum(f.decision==ObservationDecision.DENY for f in facts),count({ObservationRisk.STALE_RESULT,ObservationRisk.REPLAY_RESULT,ObservationRisk.RESULT_TIME_INVALID}),count({ObservationRisk.SIDE_EFFECT_UNACKNOWLEDGED,ObservationRisk.SIDE_EFFECT_ACK_MISMATCH}),count({ObservationRisk.ENVIRONMENT_STATE_SPOOF,ObservationRisk.ENVIRONMENT_VERSION_REGRESSION}),count({ObservationRisk.OBSERVATION_LAUNDERING,ObservationRisk.OBSERVATION_TRUST_MISMATCH}),count({ObservationRisk.UPSTREAM_PLAN_UNSAFE,ObservationRisk.UPSTREAM_DELEGATION_UNSAFE,ObservationRisk.REQUIRED_INVARIANT_UNSAFE}),facts,_assessment_digest(facts,m))
