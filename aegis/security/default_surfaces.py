from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


P3C_POLICY_VERSION = "explicit-non-default-external-surfaces-v1"


class ExternalSurface(StrEnum):
    OUTBOUND_NETWORK = "outbound_network"
    ARTIFACT_INGESTION = "artifact_ingestion"
    BROWSER_NAVIGATION = "browser_navigation"


class DefaultSurfacePolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class SurfaceRule:
    surface: ExternalSurface
    api_path_markers: tuple[str, ...]
    tool_name_markers: tuple[str, ...]
    default_enabled: bool = False


_DEFAULT_AGENT_TOOL_NAMES = frozenset(
    {
        "search_knowledge_base",
        "get_my_assets",
        "create_ticket",
        "request_access",
        "request_password_reset",
    }
)


DEFAULT_SURFACE_RULES: tuple[SurfaceRule, ...] = (
    SurfaceRule(
        surface=ExternalSurface.OUTBOUND_NETWORK,
        api_path_markers=("/network", "/fetch", "/http"),
        tool_name_markers=("fetch_url", "http_fetch", "outbound_network"),
    ),
    SurfaceRule(
        surface=ExternalSurface.ARTIFACT_INGESTION,
        api_path_markers=("/artifact", "/upload", "/ingest"),
        tool_name_markers=("artifact", "upload", "ingest_file"),
    ),
    SurfaceRule(
        surface=ExternalSurface.BROWSER_NAVIGATION,
        api_path_markers=("/browser", "/browse", "/navigate"),
        tool_name_markers=("browser", "browse", "navigate"),
    ),
)


class DefaultExternalSurfacePolicy:
    """Server-owned declaration of high-risk surfaces that are not default capabilities."""

    policy_version = P3C_POLICY_VERSION

    def __init__(self, rules: tuple[SurfaceRule, ...] = DEFAULT_SURFACE_RULES) -> None:
        self._rules = rules

    def is_default_enabled(self, surface: ExternalSurface) -> bool:
        rule = self._rule(surface)
        return rule.default_enabled

    def assert_tool_catalog(self, tool_names: Iterable[str]) -> None:
        observed = frozenset(str(name) for name in tool_names)
        if observed != _DEFAULT_AGENT_TOOL_NAMES:
            raise DefaultSurfacePolicyError("default_tool_catalog_changed")
        for name in observed:
            lowered = name.casefold()
            for rule in self._rules:
                if any(marker in lowered for marker in rule.tool_name_markers):
                    raise DefaultSurfacePolicyError("non_default_surface_tool_exposed")

    def assert_api_paths(self, paths: Iterable[str]) -> None:
        for raw_path in paths:
            path = str(raw_path).casefold()
            if path in {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}:
                continue
            for rule in self._rules:
                if any(marker in path for marker in rule.api_path_markers):
                    raise DefaultSurfacePolicyError("non_default_surface_route_exposed")

    def manifest(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "surface": rule.surface.value,
                "default_enabled": rule.default_enabled,
            }
            for rule in self._rules
        )

    def _rule(self, surface: ExternalSurface) -> SurfaceRule:
        for rule in self._rules:
            if rule.surface is surface:
                return rule
        raise DefaultSurfacePolicyError("unknown_external_surface")


DEFAULT_EXTERNAL_SURFACE_POLICY = DefaultExternalSurfacePolicy()
DEFAULT_AGENT_TOOL_NAMES = tuple(sorted(_DEFAULT_AGENT_TOOL_NAMES))
