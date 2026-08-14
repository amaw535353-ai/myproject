from __future__ import annotations

from dataclasses import dataclass

from aegis.model_supply_chain.package_provenance import VerifiedModelPackage
from aegis.model_supply_chain.runtime_isolation import ModelRuntimePlan


@dataclass(frozen=True)
class VulnerableRuntimePlan:
    package_id: str
    runtime_id: str
    backend: str
    parsers: tuple[str, ...]
    remote_code_requested: bool
    dynamic_code_requested: bool
    network_access_requested: bool
    subprocess_requested: bool
    host_write_requested: bool
    environment_passthrough_requested: bool
    isolation_mode: str
    model_bytes_parsed: bool = False
    model_executed: bool = False


class VulnerableHostRuntimePlanner:
    """Intentionally trusts package/runtime declarations while remaining inert."""

    def prepare(
        self,
        *,
        package: VerifiedModelPackage,
        plan: ModelRuntimePlan,
    ) -> VulnerableRuntimePlan:
        return VulnerableRuntimePlan(
            package_id=package.package_id,
            runtime_id=plan.runtime_id,
            backend=plan.backend,
            parsers=tuple(item.parser for item in plan.components),
            remote_code_requested=any(item.requires_remote_code for item in plan.components),
            dynamic_code_requested=any(
                item.dynamic_module or item.native_extensions or item.custom_ops
                for item in plan.components
            ),
            network_access_requested=plan.capabilities.network_access,
            subprocess_requested=plan.capabilities.subprocess,
            host_write_requested=plan.capabilities.host_filesystem_write,
            environment_passthrough_requested=plan.capabilities.environment_passthrough,
            isolation_mode=plan.isolation_mode,
        )
