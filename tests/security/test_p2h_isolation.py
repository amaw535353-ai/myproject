import inspect

from aegis.observability import security_events


def test_hardened_telemetry_has_no_vulnerable_import() -> None:
    source = inspect.getsource(security_events)
    assert "aegis.vulnerable" not in source
    assert "VulnerableRawTelemetryRecorder" not in source
