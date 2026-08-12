import pytest

from aegis.downstream.auth import (
    INVENTORY_ALICE_ADMIN_TOKEN,
    MCP_ALICE_TOKEN,
    MCP_AUDIENCE,
    SyntheticTokenValidationError,
    validate_mcp_inbound_token,
)
from aegis.identity.synthetic_auth import resolve_synthetic_principal


def test_valid_mcp_token_is_bound_to_trusted_principal() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None

    claims = validate_mcp_inbound_token(MCP_ALICE_TOKEN, principal=alice)

    assert claims.audience == MCP_AUDIENCE
    assert claims.subject == alice.user_id
    assert "mcp:tools" in claims.scopes


def test_wrong_audience_token_is_rejected_at_mcp_boundary() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None

    with pytest.raises(SyntheticTokenValidationError):
        validate_mcp_inbound_token(INVENTORY_ALICE_ADMIN_TOKEN, principal=alice)


def test_mcp_token_cannot_transfer_to_another_principal() -> None:
    bob = resolve_synthetic_principal("bob@northstar-digital.test")
    assert bob is not None

    with pytest.raises(SyntheticTokenValidationError):
        validate_mcp_inbound_token(MCP_ALICE_TOKEN, principal=bob)
