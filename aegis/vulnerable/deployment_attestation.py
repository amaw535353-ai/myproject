from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.model_supply_chain.deployment_attestation import SignedDeploymentAttestation


@dataclass(frozen=True)
class VulnerableDeploymentDecision:
    deployment_id: str
    model_id: str
    environment_id: str
    admitted: bool = True
    signature_verified: bool = False
    environment_verified: bool = False
    prior_gates_verified: bool = False
    real_deployment_started: bool = False


class VulnerableDeploymentLauncher:
    """Synthetic baseline that trusts deployment declarations and attestation metadata."""

    def launch(
        self,
        *,
        attestation: SignedDeploymentAttestation,
        **_: Any,
    ) -> VulnerableDeploymentDecision:
        statement = attestation.statement
        return VulnerableDeploymentDecision(
            deployment_id=statement.deployment_id,
            model_id=statement.model_id,
            environment_id=statement.environment.environment_id,
        )
