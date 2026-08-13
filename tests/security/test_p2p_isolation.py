from pathlib import Path

import aegis.effects.rollback_anchor as rollback_anchor


def test_hardened_rollback_anchor_does_not_import_vulnerable_baseline() -> None:
    source = Path(rollback_anchor.__file__).read_text(encoding="utf-8")
    assert "aegis.vulnerable" not in source
    assert "p2p_rollback_blind_authorization" not in source
