import pytest
from pydantic import ValidationError

from aegis.identity.synthetic_auth import resolve_synthetic_principal


def test_principal_is_immutable() -> None:
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    with pytest.raises(ValidationError):
        principal.tenant_id = "tenant_northstar_digital"  # type: ignore[misc]
