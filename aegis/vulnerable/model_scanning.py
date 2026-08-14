from __future__ import annotations

from dataclasses import dataclass

from aegis.model_supply_chain.model_scanning import ModelScanEvidenceBundle
from aegis.model_supply_chain.package_provenance import VerifiedModelPackage
from aegis.model_supply_chain.runtime_isolation import VerifiedRuntimePlan


@dataclass(frozen=True)
class VulnerableModelScanDecision:
    package_id: str
    runtime_id: str
    scanner_id: str
    evidence_artifact_count: int
    evidence_probe_count: int
    accepted: bool = True
    raw_model_bytes_scanned: bool = False
    model_executed: bool = False


class VulnerableProvenanceOnlyModelScanner:
    """Intentionally treats provenance/runtime approval as sufficient model safety evidence."""

    def evaluate(
        self,
        *,
        package: VerifiedModelPackage,
        runtime: VerifiedRuntimePlan,
        evidence: ModelScanEvidenceBundle,
    ) -> VulnerableModelScanDecision:
        return VulnerableModelScanDecision(
            package_id=package.package_id,
            runtime_id=runtime.runtime_id,
            scanner_id=evidence.scanner_id,
            evidence_artifact_count=len(evidence.artifacts),
            evidence_probe_count=len(evidence.probes),
        )
