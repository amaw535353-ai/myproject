from __future__ import annotations

from dataclasses import dataclass

from aegis.model_serving.abuse_response import IncidentAction, SignedServingTelemetryBatch


@dataclass(frozen=True)
class VulnerableIncidentDecision:
    deployment_id: str
    batch_id: str
    action: IncidentAction
    signature_verified: bool = False
    chain_verified: bool = False
    attestation_bound: bool = False


class VulnerableServingAbuseResponder:
    """Intentionally unsafe baseline that trusts caller-declared response actions."""

    def evaluate(
        self,
        *,
        signed_batch: SignedServingTelemetryBatch,
        claimed_action: IncidentAction = IncidentAction.OBSERVE,
    ) -> VulnerableIncidentDecision:
        return VulnerableIncidentDecision(
            deployment_id=signed_batch.batch.deployment_id,
            batch_id=signed_batch.batch.batch_id,
            action=claimed_action,
        )
