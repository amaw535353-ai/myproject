from __future__ import annotations


class VulnerableCallerDeclaredTrainingDataTrust:
    """Intentionally weak baseline: caller assertions are treated as provenance evidence."""

    def accepts(self, *, declared_training_data_safe: bool = True, declared_provenance_complete: bool = True) -> bool:
        return bool(declared_training_data_safe and declared_provenance_complete)
