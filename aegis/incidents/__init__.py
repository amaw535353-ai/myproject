"""Deterministic incident intake from correlated detection context."""

from .intake import IncidentIntakeBoundary
from .types import IncidentIntakeRecord

__all__ = ["IncidentIntakeBoundary", "IncidentIntakeRecord"]
