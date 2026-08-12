from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType

from aegis.identity.models import Principal


MCP_AUDIENCE = "urn:aegisdesk:mcp"
INVENTORY_AUDIENCE = "urn:aegisdesk:synthetic-inventory"

# Synthetic lab credentials only. These are deterministic fixtures, not real secrets.
MCP_ALICE_TOKEN = "synthetic.mcp.alice.v1"
MCP_BOB_TOKEN = "synthetic.mcp.bob.v1"
INVENTORY_ALICE_ADMIN_TOKEN = "synthetic.inventory.alice.admin.v1"
INVENTORY_SERVICE_TOKEN = "synthetic.inventory.aegisdesk.service.v1"


@dataclass(frozen=True)
class SyntheticTokenClaims:
    subject: str
    audience: str
    scopes: frozenset[str]
    credential_class: str


class SyntheticTokenValidationError(RuntimeError):
    """Raised when a synthetic lab credential fails a trust-boundary check."""


_TOKEN_REGISTRY = MappingProxyType(
    {
        MCP_ALICE_TOKEN: SyntheticTokenClaims(
            subject="usr_dyn_alice",
            audience=MCP_AUDIENCE,
            scopes=frozenset({"mcp:tools"}),
            credential_class="mcp-user",
        ),
        MCP_BOB_TOKEN: SyntheticTokenClaims(
            subject="usr_dig_bob",
            audience=MCP_AUDIENCE,
            scopes=frozenset({"mcp:tools"}),
            credential_class="mcp-user",
        ),
        INVENTORY_ALICE_ADMIN_TOKEN: SyntheticTokenClaims(
            subject="usr_dyn_alice",
            audience=INVENTORY_AUDIENCE,
            scopes=frozenset({"inventory:admin"}),
            credential_class="inventory-user-admin",
        ),
        INVENTORY_SERVICE_TOKEN: SyntheticTokenClaims(
            subject="svc:aegisdesk",
            audience=INVENTORY_AUDIENCE,
            scopes=frozenset({"assets:read"}),
            credential_class="inventory-service",
        ),
    }
)


def resolve_synthetic_token(token: str) -> SyntheticTokenClaims | None:
    return _TOKEN_REGISTRY.get(token)


def token_fingerprint(token: str) -> str:
    """Return a non-reversible short fingerprint for synthetic security evidence."""

    digest = sha256(token.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def validate_mcp_inbound_token(
    token: str,
    *,
    principal: Principal,
) -> SyntheticTokenClaims:
    """Validate that an inbound credential is meant for this MCP server and user.

    This is intentionally tiny because P2-D tests architecture, not OAuth crypto.
    A real deployment must delegate validation to a standards-compliant IdP/library.
    """

    claims = resolve_synthetic_token(token)
    if claims is None:
        raise SyntheticTokenValidationError("inbound MCP credential rejected")
    if claims.audience != MCP_AUDIENCE:
        raise SyntheticTokenValidationError("inbound MCP credential rejected")
    if claims.subject != principal.user_id:
        raise SyntheticTokenValidationError("inbound MCP credential rejected")
    if "mcp:tools" not in claims.scopes:
        raise SyntheticTokenValidationError("inbound MCP credential rejected")
    return claims
