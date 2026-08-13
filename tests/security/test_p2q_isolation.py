from pathlib import Path

import aegis.effects.control_plane_recovery as control_plane_recovery


def test_hardened_control_plane_recovery_does_not_import_vulnerable_baseline() -> None:
    source = Path(control_plane_recovery.__file__).read_text(encoding="utf-8")
    assert "aegis.vulnerable" not in source
    assert "p2q_partial_control_plane" not in source
