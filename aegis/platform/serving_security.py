from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass


class ServingDenied(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    data = value if isinstance(value, bytes) else canonical_bytes(value)
    return hashlib.sha256(data).hexdigest()


SENSITIVE_EVIDENCE_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    r"authorization\s*:\s*bearer(?:\s|$)",
    r"bearer\s+eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    r"eyJ[A-Za-z0-9_-]{16,}\.eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
))


def evidence_is_sensitive_material_free(payload: object, *, forbidden_values: tuple[str, ...] = ()) -> bool:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if any(pattern.search(serialized) for pattern in SENSITIVE_EVIDENCE_PATTERNS):
        return False
    return not any(value and value in serialized for value in forbidden_values)


RESERVED_HEADERS = {
    "x-internal-principal", "x-workload-identity", "x-forwarded-client-cert",
    "x-verified-tenant",
}
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


@dataclass(frozen=True)
class RequestContext:
    principal: str
    tenant: str
    request_id: str


class RequestPolicy:
    MAX_BODY = 512
    REQUEST_ID = re.compile(r"req-[a-z0-9]{8,32}\Z")

    def validate(self, *, method: str, route: str, content_type: str, body: bytes,
                 headers: dict[str, str], claimed_tenant: str, context: RequestContext) -> None:
        lowered = {k.lower(): v for k, v in headers.items()}
        if method != "POST" or route != "/v1/infer": raise ServingDenied("METHOD_OR_ROUTE_DENIED")
        if content_type.split(";", 1)[0].strip().lower() != "application/json": raise ServingDenied("CONTENT_TYPE_DENIED")
        if len(body) > self.MAX_BODY: raise ServingDenied("BODY_TOO_LARGE")
        if claimed_tenant != context.tenant: raise ServingDenied("TENANT_MISMATCH")
        if not self.REQUEST_ID.fullmatch(context.request_id): raise ServingDenied("REQUEST_ID_INVALID")
        if any(k in RESERVED_HEADERS or k.startswith("x-aegis-internal-") for k in lowered): raise ServingDenied("TRUSTED_HEADER_SPOOF")
        if any(k in HOP_HEADERS and not (k == "connection" and lowered[k].lower() == "close") for k in lowered):
            raise ServingDenied("HOP_HEADER_DENIED")


class FixedWindowLimiter:
    def __init__(self, limit: int = 3, window: float = 60.0, concurrency: int = 2) -> None:
        self.limit, self.window, self.concurrency = limit, window, concurrency
        self.hits: dict[str, list[float]] = {}; self.active: dict[str, int] = {}

    def acquire(self, principal: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        hits = [x for x in self.hits.get(principal, []) if now - x < self.window]
        if len(hits) >= self.limit: raise ServingDenied("RATE_LIMITED")
        if self.active.get(principal, 0) >= self.concurrency: raise ServingDenied("CONCURRENCY_LIMITED")
        hits.append(now); self.hits[principal] = hits
        self.active[principal] = self.active.get(principal, 0) + 1

    def release(self, principal: str) -> None:
        self.active[principal] = max(0, self.active.get(principal, 0) - 1)


class DrainState:
    def __init__(self) -> None:
        self.healthy = True; self.draining = False; self.in_flight = 0

    @property
    def ready(self) -> bool: return self.healthy and not self.draining

    def enter(self) -> None:
        if not self.ready: raise ServingDenied("NOT_READY")
        self.in_flight += 1

    def leave(self) -> None: self.in_flight = max(0, self.in_flight - 1)
    def drain(self) -> None: self.draining = True
    @property
    def safe_to_stop(self) -> bool: return self.draining and self.in_flight == 0


def runtime_security_context_valid(container: dict, pod: dict) -> bool:
    sc = container.get("securityContext", {}); psc = pod.get("securityContext", {})
    resources = container.get("resources", {})
    return all((
        psc.get("runAsNonRoot") is True,
        int(psc.get("runAsUser", 0)) > 0,
        sc.get("privileged") is not True,
        sc.get("allowPrivilegeEscalation") is False,
        sc.get("readOnlyRootFilesystem") is True,
        sc.get("capabilities", {}).get("drop") == ["ALL"],
        not sc.get("capabilities", {}).get("add"),
        psc.get("seccompProfile", {}).get("type") == "RuntimeDefault",
        bool(resources.get("requests")), bool(resources.get("limits")),
    ))
