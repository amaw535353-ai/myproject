from __future__ import annotations

from .incident_forensics_types import (
    P8K_ASSESSMENT_MODE,
    P8K_ASSESSMENT_SCHEMA_VERSION,
    P8K_INCIDENT_POLICY_VERSION,
    P8K_INCIDENT_SCHEMA_VERSION,
    ZERO_SHA256,
    AgentIncidentForensicsManifest,
    AgentIncidentForensicsPolicy,
    AgentIncidentForensicsRejected,
    AgentIncidentForensicsRequest,
    ContainmentAction,
    ContainmentKind,
    ForensicPackage,
    IncidentCase,
    IncidentDecision,
    IncidentEvent,
    IncidentEventKind,
    IncidentForensicsFact,
    IncidentRejectReason,
    IncidentRisk,
    ReentryAuthorization,
    VerifiedAgentIncidentForensicsAssessment,
    agent_incident_forensics_manifest_digest,
    canonical_agent_incident_forensics_manifest_bytes,
    evidence_scope_digest,
    forensic_package_digest,
    incident_event_digest,
    reconstruction_digest,
)
from .incident_forensics_types import _digest_json, _reject
from .incident_forensics_validation import _IncidentValidationMixin


class AgentProvenanceIncidentForensicsAnalyzer(_IncidentValidationMixin):
    def derive(
        self,
        manifest: AgentIncidentForensicsManifest,
        p8g: object,
        p8h: object,
        p8i: object,
        p8j: object,
        now: int,
    ) -> tuple[IncidentForensicsFact, ...]:
        self._validate_upstream(p8g, p8h, p8i, p8j)
        events, actions, packages, reentries, incidents = self._validate_manifest(manifest, now)
        facts: list[IncidentForensicsFact] = []

        for incident in sorted(incidents.values(), key=lambda x: x.incident_id):
            risks: set[IncidentRisk] = set()
            triggers = tuple(incident.trigger_event_ids)
            if not triggers or any(trigger_id not in events for trigger_id in triggers):
                risks.add(IncidentRisk.INCIDENT_TRIGGER_INVALID)
                scope_ids: tuple[str, ...] = ()
            else:
                scope_ids = self._derive_scope(events, triggers)

            scope_events = tuple(events[event_id] for event_id in scope_ids)
            scope_agents = tuple(sorted({event.agent_id for event in scope_events}))
            if any(event.observed_at_epoch > incident.contained_at_epoch for event in scope_events):
                risks.add(IncidentRisk.POST_CONTAINMENT_ACTIVITY)

            action_values: list[ContainmentAction] = []
            for action_id in incident.containment_action_ids:
                action = actions.get(action_id)
                if action is None or action.incident_id != incident.incident_id:
                    risks.add(IncidentRisk.CONTAINMENT_ACTION_INVALID)
                    continue
                action_values.append(action)

            trigger_time = min((events[t].observed_at_epoch for t in triggers if t in events), default=incident.contained_at_epoch)
            for action in action_values:
                if action.issued_at_epoch < trigger_time or action.issued_at_epoch > incident.contained_at_epoch:
                    risks.add(IncidentRisk.CONTAINMENT_TIME_INVALID)

            def _has(kind: ContainmentKind, target_id: str) -> bool:
                return any(action.kind == kind and action.target_id == target_id for action in action_values)

            for agent_id in scope_agents:
                if not _has(ContainmentKind.QUARANTINE_AGENT, agent_id):
                    risks.add(IncidentRisk.AGENT_NOT_QUARANTINED)

            channel_ids = sorted({event.object_id for event in scope_events if event.kind == IncidentEventKind.MESSAGE})
            state_ids = sorted(
                {
                    event.object_id
                    for event in scope_events
                    if event.kind in {IncidentEventKind.STATE_TRANSITION, IncidentEventKind.RECOVERY}
                }
            )
            credential_ids = sorted(
                {event.object_id for event in scope_events if event.kind == IncidentEventKind.CREDENTIAL_USE}
            )
            for channel_id in channel_ids:
                if not _has(ContainmentKind.ISOLATE_CHANNEL, channel_id):
                    risks.add(IncidentRisk.CHANNEL_NOT_ISOLATED)
            for state_id in state_ids:
                if not _has(ContainmentKind.FREEZE_STATE, state_id):
                    risks.add(IncidentRisk.STATE_NOT_FROZEN)
            for credential_id in credential_ids:
                if not _has(ContainmentKind.REVOKE_CREDENTIAL, credential_id):
                    risks.add(IncidentRisk.CREDENTIAL_NOT_REVOKED)

            expected_evidence_digest = evidence_scope_digest(events, scope_ids) if scope_ids else _digest_json({})
            evidence_actions = [
                action
                for action in action_values
                if action.kind == ContainmentKind.PRESERVE_EVIDENCE and action.target_id == incident.incident_id
            ]
            if len(evidence_actions) != 1:
                risks.add(IncidentRisk.EVIDENCE_SCOPE_INCOMPLETE)
            else:
                evidence_action = evidence_actions[0]
                if tuple(evidence_action.evidence_event_ids) != scope_ids:
                    risks.add(IncidentRisk.EVIDENCE_SCOPE_INCOMPLETE)
                if evidence_action.evidence_digest_sha256.casefold() != expected_evidence_digest:
                    risks.add(IncidentRisk.EVIDENCE_DIGEST_MISMATCH)

            package = packages.get(incident.forensic_package_id)
            reconstruction_sha = _digest_json({})
            if package is None or package.incident_id != incident.incident_id:
                risks.add(IncidentRisk.FORENSIC_PACKAGE_MISSING)
            else:
                if tuple(package.scope_event_ids) != scope_ids:
                    risks.add(IncidentRisk.FORENSIC_PACKAGE_SCOPE_MISMATCH)
                expected_preserved = {event_id: events[event_id].event_sha256.casefold() for event_id in scope_ids}
                if dict(package.preserved_event_sha256_by_id) != expected_preserved:
                    risks.add(IncidentRisk.FORENSIC_PACKAGE_HASH_MISMATCH)
                expected_reconstruction = tuple(
                    event.event_id for event in sorted(scope_events, key=lambda e: (e.sequence, e.event_id))
                )
                if tuple(package.reconstruction_event_ids) != expected_reconstruction:
                    risks.add(IncidentRisk.RECONSTRUCTION_ORDER_INVALID)
                if tuple(package.root_event_ids) != tuple(sorted(triggers)):
                    risks.add(IncidentRisk.RECONSTRUCTION_ROOT_MISMATCH)
                if package.generated_at_epoch < incident.contained_at_epoch:
                    risks.add(IncidentRisk.CONTAINMENT_TIME_INVALID)
                reconstruction_sha = reconstruction_digest(expected_reconstruction)

            listed_reentries: list[ReentryAuthorization] = []
            seen_agents: set[str] = set()
            for reentry_id in incident.reentry_authorization_ids:
                reentry = reentries.get(reentry_id)
                if reentry is None or reentry.incident_id != incident.incident_id:
                    risks.add(IncidentRisk.REENTRY_UNAUTHORIZED)
                    continue
                listed_reentries.append(reentry)
                if reentry.agent_id in seen_agents:
                    risks.add(IncidentRisk.REENTRY_UNAUTHORIZED)
                seen_agents.add(reentry.agent_id)
                expected_checkpoint = self.policy.safe_checkpoint_id_by_agent.get(reentry.agent_id)
                expected_credential = self.policy.replacement_credential_sha256_by_agent.get(reentry.agent_id)
                expected_state_version = self.policy.minimum_reentry_state_version_by_agent.get(reentry.agent_id)
                if expected_checkpoint is None or reentry.agent_id not in scope_agents:
                    risks.add(IncidentRisk.REENTRY_UNAUTHORIZED)
                    continue
                if reentry.safe_checkpoint_id != expected_checkpoint:
                    risks.add(IncidentRisk.REENTRY_CHECKPOINT_MISMATCH)
                if expected_credential is None or reentry.replacement_credential_sha256.casefold() != expected_credential.casefold():
                    risks.add(IncidentRisk.REENTRY_CREDENTIAL_NOT_ROTATED)
                if expected_state_version is None or reentry.minimum_state_version < expected_state_version:
                    risks.add(IncidentRisk.REENTRY_STATE_VERSION_STALE)
                if package is None or reentry.forensic_package_sha256.casefold() != forensic_package_digest(package):
                    risks.add(IncidentRisk.REENTRY_PACKAGE_MISMATCH)
                lower_bound = incident.contained_at_epoch if package is None else max(
                    incident.contained_at_epoch, package.generated_at_epoch
                )
                if (
                    reentry.issued_at_epoch < lower_bound
                    or reentry.not_before_epoch < lower_bound
                    or reentry.not_before_epoch > reentry.expires_at_epoch
                ):
                    risks.add(IncidentRisk.REENTRY_BEFORE_CONTAINMENT)
                if reentry.expires_at_epoch < now:
                    risks.add(IncidentRisk.REENTRY_EXPIRED)

            required_reentry_agents = set(self.policy.safe_checkpoint_id_by_agent).intersection(scope_agents)
            if seen_agents != required_reentry_agents:
                risks.add(IncidentRisk.REENTRY_UNAUTHORIZED)

            decision = IncidentDecision.DENY if risks else IncidentDecision.ALLOW
            ordered_risks = tuple(sorted(risks, key=lambda r: r.value))
            facts.append(
                IncidentForensicsFact(
                    incident_id=incident.incident_id,
                    decision=decision,
                    risks=ordered_risks,
                    trigger_event_ids=triggers,
                    scope_event_ids=scope_ids,
                    scope_agent_ids=scope_agents,
                    containment_action_ids=tuple(incident.containment_action_ids),
                    forensic_package_id=incident.forensic_package_id,
                    reconstruction_sha256=reconstruction_sha,
                    reentry_authorization_ids=tuple(incident.reentry_authorization_ids),
                    risk_score=len(ordered_risks) * 10,
                )
            )
        return tuple(facts)

    def evaluate(
        self,
        request: AgentIncidentForensicsRequest,
        manifest: AgentIncidentForensicsManifest,
        p8g: object,
        p8h: object,
        p8i: object,
        p8j: object,
    ) -> VerifiedAgentIncidentForensicsAssessment:
        self._validate_request(request)
        if request.evaluated_at_epoch < manifest.created_at_epoch:
            _reject(IncidentRejectReason.REQUEST_INVALID, "evaluation predates incident manifest")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds + self.policy.max_future_skew_seconds:
            _reject(IncidentRejectReason.REQUEST_INVALID, "evaluation exceeds manifest freshness policy")

        facts = self.derive(manifest, p8g, p8h, p8i, p8j, request.evaluated_at_epoch)
        by_id = {fact.incident_id: fact for fact in facts}
        derived_complete = tuple(sorted(fact.incident_id for fact in facts if fact.decision == IncidentDecision.ALLOW))
        if tuple(sorted(request.declared_complete_incident_ids)) != derived_complete:
            _reject(IncidentRejectReason.DECLARED_DECISION_MISMATCH, "caller-declared incident completion mismatch")

        expected_scope = {incident_id: by_id[incident_id].scope_event_ids for incident_id in sorted(by_id)}
        if dict(request.declared_scope_event_ids_by_incident) != expected_scope:
            _reject(IncidentRejectReason.DECLARED_SCOPE_MISMATCH, "caller-declared incident scope mismatch")

        expected_reconstruction = {
            incident_id: by_id[incident_id].reconstruction_sha256 for incident_id in sorted(by_id)
        }
        if {k: str(v).casefold() for k, v in request.declared_reconstruction_sha256_by_incident.items()} != expected_reconstruction:
            _reject(
                IncidentRejectReason.DECLARED_RECONSTRUCTION_MISMATCH,
                "caller-declared reconstruction digest mismatch",
            )

        expected_reentries = {
            incident_id: by_id[incident_id].reentry_authorization_ids for incident_id in sorted(by_id)
        }
        if dict(request.declared_reentry_ids_by_incident) != expected_reentries:
            _reject(IncidentRejectReason.DECLARED_REENTRY_MISMATCH, "caller-declared re-entry set mismatch")

        allowed = sum(fact.decision == IncidentDecision.ALLOW for fact in facts)
        denied = len(facts) - allowed

        chain_risks = {
            IncidentRisk.EVENT_HASH_MISMATCH,
            IncidentRisk.EVENT_CHAIN_BROKEN,
            IncidentRisk.EVENT_SEQUENCE_INVALID,
            IncidentRisk.CAUSAL_PARENT_MISSING,
            IncidentRisk.CAUSAL_ORDER_INVALID,
            IncidentRisk.INCIDENT_TRIGGER_INVALID,
            IncidentRisk.INCIDENT_SCOPE_INCOMPLETE,
            IncidentRisk.INCIDENT_SCOPE_AGENT_MISMATCH,
            IncidentRisk.POST_CONTAINMENT_ACTIVITY,
        }
        containment_risks = {
            IncidentRisk.AGENT_NOT_QUARANTINED,
            IncidentRisk.CHANNEL_NOT_ISOLATED,
            IncidentRisk.STATE_NOT_FROZEN,
            IncidentRisk.CREDENTIAL_NOT_REVOKED,
            IncidentRisk.CONTAINMENT_ACTION_INVALID,
            IncidentRisk.CONTAINMENT_TIME_INVALID,
            IncidentRisk.EVIDENCE_SCOPE_INCOMPLETE,
            IncidentRisk.EVIDENCE_DIGEST_MISMATCH,
        }
        forensic_risks = {
            IncidentRisk.FORENSIC_PACKAGE_MISSING,
            IncidentRisk.FORENSIC_PACKAGE_SCOPE_MISMATCH,
            IncidentRisk.FORENSIC_PACKAGE_HASH_MISMATCH,
            IncidentRisk.RECONSTRUCTION_ORDER_INVALID,
            IncidentRisk.RECONSTRUCTION_ROOT_MISMATCH,
        }
        reentry_risks = {
            IncidentRisk.REENTRY_UNAUTHORIZED,
            IncidentRisk.REENTRY_BEFORE_CONTAINMENT,
            IncidentRisk.REENTRY_PACKAGE_MISMATCH,
            IncidentRisk.REENTRY_CHECKPOINT_MISMATCH,
            IncidentRisk.REENTRY_CREDENTIAL_NOT_ROTATED,
            IncidentRisk.REENTRY_STATE_VERSION_STALE,
            IncidentRisk.REENTRY_EXPIRED,
        }
        upstream_risks = {
            IncidentRisk.UPSTREAM_MESSAGE_UNSAFE,
            IncidentRisk.UPSTREAM_STATE_UNSAFE,
            IncidentRisk.UPSTREAM_ARTIFACT_UNSAFE,
            IncidentRisk.UPSTREAM_RECOVERY_UNSAFE,
        }

        def _count(risk_set: set[IncidentRisk]) -> int:
            return sum(bool(set(fact.risks).intersection(risk_set)) for fact in facts)

        assessment_payload = {
            "graph_id": request.graph_id,
            "graph_version": request.graph_version,
            "graph_sha256": request.graph_sha256.casefold(),
            "p8g": request.p8g_assessment_evidence_sha256.casefold(),
            "p8h": request.p8h_assessment_evidence_sha256.casefold(),
            "p8i": request.p8i_assessment_evidence_sha256.casefold(),
            "p8j": request.p8j_assessment_evidence_sha256.casefold(),
            "incidents": facts,
            "policy_version": P8K_INCIDENT_POLICY_VERSION,
            "schema_version": P8K_ASSESSMENT_SCHEMA_VERSION,
            "assessment_mode": P8K_ASSESSMENT_MODE,
        }
        assessment_sha = _digest_json(assessment_payload)

        return VerifiedAgentIncidentForensicsAssessment(
            graph_id=request.graph_id,
            graph_version=request.graph_version,
            graph_sha256=request.graph_sha256.casefold(),
            p8g_assessment_evidence_sha256=request.p8g_assessment_evidence_sha256.casefold(),
            p8h_assessment_evidence_sha256=request.p8h_assessment_evidence_sha256.casefold(),
            p8i_assessment_evidence_sha256=request.p8i_assessment_evidence_sha256.casefold(),
            p8j_assessment_evidence_sha256=request.p8j_assessment_evidence_sha256.casefold(),
            incident_count=len(facts),
            allowed_incident_count=allowed,
            denied_incident_count=denied,
            chain_integrity_denial_count=_count(chain_risks),
            containment_denial_count=_count(containment_risks),
            forensic_denial_count=_count(forensic_risks),
            reentry_denial_count=_count(reentry_risks),
            upstream_safety_denial_count=_count(upstream_risks),
            maximum_risk_score=max((fact.risk_score for fact in facts), default=0),
            incidents=facts,
            assessment_evidence_sha256=assessment_sha,
        )
