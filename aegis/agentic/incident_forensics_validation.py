from __future__ import annotations

from typing import Mapping

from .incident_forensics_types import (
    P8K_INCIDENT_SCHEMA_VERSION,
    ZERO_SHA256,
    AgentIncidentForensicsManifest,
    AgentIncidentForensicsPolicy,
    AgentIncidentForensicsRequest,
    ContainmentAction,
    ContainmentKind,
    ForensicPackage,
    IncidentCase,
    IncidentEvent,
    IncidentEventKind,
    IncidentRejectReason,
    ReentryAuthorization,
    _assert_owner,
    _coverage,
    _event_profile,
    _incident_profile,
    _reject,
    _safe,
    _sha,
    _upstream_digest,
    agent_incident_forensics_manifest_digest,
    incident_event_digest,
)

class _IncidentValidationMixin:
    def __init__(self, policy: AgentIncidentForensicsPolicy):
        self.policy = policy
        self._validate_policy()

    def _validate_policy(self) -> None:
        p = self.policy
        if not p.expected_graph_id or not p.expected_graph_version or not _sha(p.expected_graph_sha256):
            _reject(IncidentRejectReason.POLICY_INVALID, "invalid graph pin")
        for value in (
            p.expected_p8g_assessment_evidence_sha256,
            p.expected_p8h_assessment_evidence_sha256,
            p.expected_p8i_assessment_evidence_sha256,
            p.expected_p8j_assessment_evidence_sha256,
        ):
            if not _sha(value):
                _reject(IncidentRejectReason.POLICY_INVALID, "invalid upstream digest pin")
        if not p.required_event_ids or not p.required_incident_ids or not p.trusted_owner_ids:
            _reject(IncidentRejectReason.POLICY_INVALID, "required policy coverage is empty")
        if set(p.expected_event_profiles) != set(p.required_event_ids):
            _reject(IncidentRejectReason.POLICY_INVALID, "event profile coverage mismatch")
        if set(p.expected_incident_profiles) != set(p.required_incident_ids):
            _reject(IncidentRejectReason.POLICY_INVALID, "incident profile coverage mismatch")
        if set(p.safe_checkpoint_id_by_agent) != set(p.replacement_credential_sha256_by_agent):
            _reject(IncidentRejectReason.POLICY_INVALID, "re-entry agent policy mismatch")
        if set(p.safe_checkpoint_id_by_agent) != set(p.minimum_reentry_state_version_by_agent):
            _reject(IncidentRejectReason.POLICY_INVALID, "re-entry state policy mismatch")
        if any(not _sha(v) for v in p.replacement_credential_sha256_by_agent.values()):
            _reject(IncidentRejectReason.POLICY_INVALID, "invalid replacement credential digest")
        if p.max_manifest_age_seconds <= 0 or p.max_forensic_package_age_seconds <= 0 or p.max_future_skew_seconds < 0:
            _reject(IncidentRejectReason.POLICY_INVALID, "invalid freshness policy")

    def _validate_request(self, request: AgentIncidentForensicsRequest) -> None:
        p = self.policy
        exact = (
            request.graph_id == p.expected_graph_id
            and request.graph_version == p.expected_graph_version
            and request.graph_sha256.casefold() == p.expected_graph_sha256.casefold()
            and request.p8g_assessment_evidence_sha256.casefold() == p.expected_p8g_assessment_evidence_sha256.casefold()
            and request.p8h_assessment_evidence_sha256.casefold() == p.expected_p8h_assessment_evidence_sha256.casefold()
            and request.p8i_assessment_evidence_sha256.casefold() == p.expected_p8i_assessment_evidence_sha256.casefold()
            and request.p8j_assessment_evidence_sha256.casefold() == p.expected_p8j_assessment_evidence_sha256.casefold()
        )
        if not exact:
            _reject(IncidentRejectReason.REQUEST_INVALID, "request evidence binding mismatch")
        if frozenset(request.incident_ids) != p.required_incident_ids or len(request.incident_ids) != len(set(request.incident_ids)):
            _reject(IncidentRejectReason.COVERAGE_MISMATCH, "request incident coverage mismatch")

    def _validate_upstream(self, p8g: object, p8h: object, p8i: object, p8j: object) -> None:
        p = self.policy
        checks = (
            (
                p8g,
                p.expected_p8g_assessment_evidence_sha256,
                "exact_agent_message_graph_binding_verified",
                "caller_declared_message_safety_trusted",
                "messages",
            ),
            (
                p8h,
                p.expected_p8h_assessment_evidence_sha256,
                "exact_state_transition_graph_binding_verified",
                "caller_declared_state_safety_trusted",
                "transitions",
            ),
            (
                p8i,
                p.expected_p8i_assessment_evidence_sha256,
                "exact_artifact_graph_binding_verified",
                "caller_declared_artifact_safety_trusted",
                "actions",
            ),
            (
                p8j,
                p.expected_p8j_assessment_evidence_sha256,
                "exact_recovery_graph_binding_verified",
                "caller_declared_recovery_safety_trusted",
                "recoveries",
            ),
        )
        for value, expected_digest, binding_attr, caller_attr, collection_attr in checks:
            if _upstream_digest(value) != expected_digest.casefold():
                _reject(IncidentRejectReason.UPSTREAM_INVALID, "upstream evidence digest mismatch")
            if not bool(getattr(value, binding_attr, False)):
                _reject(IncidentRejectReason.UPSTREAM_INVALID, "upstream exact binding is not verified")
            if bool(getattr(value, caller_attr, True)):
                _reject(IncidentRejectReason.UPSTREAM_INVALID, "upstream trusts caller-declared safety")
            records = tuple(getattr(value, collection_attr, ()))
            if not records or any(not _safe(record) for record in records):
                _reject(IncidentRejectReason.UPSTREAM_INVALID, "upstream security assessment contains unsafe or missing facts")

    def _validate_manifest(
        self, manifest: AgentIncidentForensicsManifest, now: int
    ) -> tuple[
        dict[str, IncidentEvent],
        dict[str, ContainmentAction],
        dict[str, ForensicPackage],
        dict[str, ReentryAuthorization],
        dict[str, IncidentCase],
    ]:
        p = self.policy
        if manifest.schema_version != P8K_INCIDENT_SCHEMA_VERSION:
            _reject(IncidentRejectReason.MANIFEST_INVALID, "incident manifest schema drift")
        if manifest.graph_id != p.expected_graph_id or manifest.version != p.expected_graph_version:
            _reject(IncidentRejectReason.MANIFEST_INVALID, "incident manifest graph identity drift")
        if agent_incident_forensics_manifest_digest(manifest).casefold() != p.expected_graph_sha256.casefold():
            _reject(IncidentRejectReason.MANIFEST_INVALID, "incident manifest SHA-256 mismatch")
        if manifest.created_at_epoch > now + p.max_future_skew_seconds:
            _reject(IncidentRejectReason.MANIFEST_INVALID, "incident manifest is from the future")
        if now - manifest.created_at_epoch > p.max_manifest_age_seconds:
            _reject(IncidentRejectReason.MANIFEST_INVALID, "incident manifest is stale")
        upstream = (
            manifest.p8g_assessment_evidence_sha256,
            manifest.p8h_assessment_evidence_sha256,
            manifest.p8i_assessment_evidence_sha256,
            manifest.p8j_assessment_evidence_sha256,
        )
        expected = (
            p.expected_p8g_assessment_evidence_sha256,
            p.expected_p8h_assessment_evidence_sha256,
            p.expected_p8i_assessment_evidence_sha256,
            p.expected_p8j_assessment_evidence_sha256,
        )
        if tuple(v.casefold() for v in upstream) != tuple(v.casefold() for v in expected):
            _reject(IncidentRejectReason.MANIFEST_INVALID, "manifest upstream evidence mismatch")

        events = _coverage(manifest.events, "event_id", p.required_event_ids, "event")
        actions = _coverage(
            manifest.containment_actions,
            "action_id",
            p.required_containment_action_ids,
            "containment action",
        )
        packages = _coverage(
            manifest.forensic_packages,
            "package_id",
            p.required_forensic_package_ids,
            "forensic package",
        )
        reentries = _coverage(
            manifest.reentry_authorizations,
            "reentry_id",
            p.required_reentry_authorization_ids,
            "reentry authorization",
        )
        incidents = _coverage(manifest.incidents, "incident_id", p.required_incident_ids, "incident")

        for event_id, event in events.items():
            _assert_owner(event.owner_id, p.trusted_owner_ids, event_id)
            if not _sha(event.previous_event_sha256) or not _sha(event.payload_sha256) or not _sha(event.event_sha256):
                _reject(IncidentRejectReason.MANIFEST_INVALID, "invalid event digest", event_id)
            if event.event_sha256.casefold() != incident_event_digest(event):
                _reject(IncidentRejectReason.MANIFEST_INVALID, "event self-digest mismatch", event_id)
            if _event_profile(event) != p.expected_event_profiles[event_id]:
                _reject(IncidentRejectReason.POLICY_DRIFT, "event security profile drift", event_id)

        for action_id, action in actions.items():
            _assert_owner(action.owner_id, p.trusted_owner_ids, action_id)
            if not _sha(action.evidence_digest_sha256):
                _reject(IncidentRejectReason.MANIFEST_INVALID, "invalid containment evidence digest", action_id)
        for package_id, package in packages.items():
            _assert_owner(package.owner_id, p.trusted_owner_ids, package_id)
            if package.generated_at_epoch > now + p.max_future_skew_seconds:
                _reject(IncidentRejectReason.MANIFEST_INVALID, "forensic package is from the future", package_id)
            if now - package.generated_at_epoch > p.max_forensic_package_age_seconds:
                _reject(IncidentRejectReason.MANIFEST_INVALID, "forensic package is stale", package_id)
            if any(not _sha(v) for v in package.preserved_event_sha256_by_id.values()):
                _reject(IncidentRejectReason.MANIFEST_INVALID, "invalid preserved event digest", package_id)
        for reentry_id, reentry in reentries.items():
            _assert_owner(reentry.owner_id, p.trusted_owner_ids, reentry_id)
            if not _sha(reentry.forensic_package_sha256) or not _sha(reentry.replacement_credential_sha256):
                _reject(IncidentRejectReason.MANIFEST_INVALID, "invalid re-entry digest", reentry_id)
        for incident_id, incident in incidents.items():
            _assert_owner(incident.owner_id, p.trusted_owner_ids, incident_id)
            if _incident_profile(incident) != p.expected_incident_profiles[incident_id]:
                _reject(IncidentRejectReason.POLICY_DRIFT, "incident security profile drift", incident_id)

        self._validate_event_chain(events)
        return events, actions, packages, reentries, incidents

    def _validate_event_chain(self, events: Mapping[str, IncidentEvent]) -> None:
        sequences = [event.sequence for event in events.values()]
        if any(seq <= 0 for seq in sequences) or len(sequences) != len(set(sequences)):
            _reject(IncidentRejectReason.MANIFEST_INVALID, "event sequence numbers are invalid")
        by_agent: dict[str, list[IncidentEvent]] = {}
        for event in events.values():
            by_agent.setdefault(event.agent_id, []).append(event)
        for agent_events in by_agent.values():
            ordered = sorted(agent_events, key=lambda e: (e.sequence, e.event_id))
            previous_hash = ZERO_SHA256
            previous_sequence = 0
            for event in ordered:
                if event.sequence <= previous_sequence:
                    _reject(IncidentRejectReason.MANIFEST_INVALID, "non-monotonic agent event sequence", event.event_id)
                if event.previous_event_sha256.casefold() != previous_hash.casefold():
                    _reject(IncidentRejectReason.MANIFEST_INVALID, "agent event hash chain is broken", event.event_id)
                previous_hash = event.event_sha256
                previous_sequence = event.sequence
        for event in events.values():
            for parent_id in event.parent_event_ids:
                parent = events.get(parent_id)
                if parent is None:
                    _reject(IncidentRejectReason.REFERENCE_INVALID, "causal parent event is missing", event.event_id)
                if parent.sequence >= event.sequence or parent.observed_at_epoch > event.observed_at_epoch:
                    _reject(IncidentRejectReason.REFERENCE_INVALID, "causal parent order is invalid", event.event_id)

    @staticmethod
    def _event_parent_ids(events: Mapping[str, IncidentEvent]) -> dict[str, tuple[str, ...]]:
        by_agent: dict[str, list[IncidentEvent]] = {}
        for event in events.values():
            by_agent.setdefault(event.agent_id, []).append(event)
        previous_id: dict[str, str | None] = {}
        for agent_events in by_agent.values():
            ordered = sorted(agent_events, key=lambda e: (e.sequence, e.event_id))
            prior: str | None = None
            for event in ordered:
                previous_id[event.event_id] = prior
                prior = event.event_id
        result: dict[str, tuple[str, ...]] = {}
        for event in events.values():
            values = list(event.parent_event_ids)
            prior = previous_id.get(event.event_id)
            if prior is not None and prior not in values:
                values.append(prior)
            result[event.event_id] = tuple(values)
        return result

    @classmethod
    def _derive_scope(cls, events: Mapping[str, IncidentEvent], trigger_event_ids: tuple[str, ...]) -> tuple[str, ...]:
        parents = cls._event_parent_ids(events)
        scope = set(trigger_event_ids)
        changed = True
        while changed:
            changed = False
            for event_id, event_parents in parents.items():
                if event_id in scope:
                    continue
                if any(parent_id in scope for parent_id in event_parents):
                    scope.add(event_id)
                    changed = True
        return tuple(
            event.event_id
            for event in sorted(
                (events[event_id] for event_id in scope),
                key=lambda event: (event.sequence, event.event_id),
            )
        )
