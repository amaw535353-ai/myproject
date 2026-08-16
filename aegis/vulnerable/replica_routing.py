from __future__ import annotations

from aegis.inference.replica_routing_types import InferenceReplicaRoutingRequest


class VulnerableCallerDeclaredReplicaRoutingSafety:
    def accepts(self, request: InferenceReplicaRoutingRequest) -> bool:
        return bool(request.declared_replica_routing_safe)
