from __future__ import annotations

from dataclasses import dataclass

from aegis.model_supply_chain.model_scanning import VerifiedModelScan
from aegis.model_supply_chain.privacy_controls import PrivacyInferenceRequest, PrivacyResponseEvidence
from aegis.model_supply_chain.runtime_isolation import VerifiedRuntimePlan


@dataclass(frozen=True)
class VulnerableOracleResponse:
    output_text: str
    output_mode: str
    raw_logits_exposed: bool
    token_probabilities_exposed: bool
    embeddings_exposed: bool
    hidden_states_exposed: bool
    model_executed: bool = False


class VulnerableUnlimitedModelOracle:
    """Intentionally trusts privacy/output declarations while remaining synthetic and inert."""

    def release(
        self,
        *,
        request: PrivacyInferenceRequest,
        runtime: VerifiedRuntimePlan,
        scan: VerifiedModelScan,
        evidence: PrivacyResponseEvidence,
    ) -> VulnerableOracleResponse:
        return VulnerableOracleResponse(
            output_text=evidence.output_text,
            output_mode=request.output_mode,
            raw_logits_exposed=request.expose_logits or evidence.returned_logits,
            token_probabilities_exposed=(
                request.expose_token_probabilities or evidence.returned_token_probabilities
            ),
            embeddings_exposed=request.expose_embeddings or evidence.returned_embeddings,
            hidden_states_exposed=(request.expose_hidden_states or evidence.returned_hidden_states),
        )
