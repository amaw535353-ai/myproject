from pathlib import Path

import aegis.effects.signed_authorization as signed_authorization


def test_hardened_signed_authorization_does_not_import_vulnerable_baseline() -> None:
    source = Path(signed_authorization.__file__).read_text(encoding="utf-8")
    assert "aegis.vulnerable" not in source
    assert "p2o_unsigned_authorization" not in source
