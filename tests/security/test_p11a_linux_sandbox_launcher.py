import stat
import subprocess
import sys

import pytest

from scripts import run_p11a_linux_sandbox_lab as linux_sandbox_lab


def test_probe_is_staged_readonly(tmp_path):
    probe = linux_sandbox_lab._stage_probe(tmp_path)
    assert probe.parent == tmp_path
    assert probe.read_bytes() == linux_sandbox_lab.PROBE_SOURCE.read_bytes()
    assert stat.S_IMODE(probe.stat().st_mode) == 0o555


def test_launcher_uses_staged_absolute_probe(tmp_path, monkeypatch):
    probe = linux_sandbox_lab._stage_probe(tmp_path)
    observed = {}

    def fake_run(cmd, **kwargs):
        observed.update(cmd=cmd, kwargs=kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"uid": 20001}\n', stderr="")

    monkeypatch.setattr(linux_sandbox_lab.subprocess, "run", fake_run)
    proc = linux_sandbox_lab._probe(probe, 20001, "identity", check=True)
    prefix = linux_sandbox_lab._sandbox_prefix(20001)
    assert proc.returncode == 0
    assert observed["cmd"][: len(prefix)] == prefix
    assert observed["cmd"][-3:] == [sys.executable, str(probe), "identity"]
    assert "-m" not in observed["cmd"]
    assert observed["kwargs"] == {"cwd": probe.parent, "text": True, "capture_output": True}


def test_launcher_redacts_paths_on_failure(tmp_path, monkeypatch):
    probe = linux_sandbox_lab._stage_probe(tmp_path)

    def fake_run(cmd, **kwargs):
        stderr = f"cannot read {probe}\nsource: {linux_sandbox_lab.PROBE_SOURCE}\n"
        return subprocess.CompletedProcess(cmd, 17, stdout="", stderr=stderr)

    monkeypatch.setattr(linux_sandbox_lab.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError) as exc:
        linux_sandbox_lab._probe(probe, 20001, "identity", check=True)
    message = str(exc.value)
    assert "exit code 17" in message
    assert "<probe>" in message and "<probe-source>" in message
    assert str(probe) not in message
    assert str(linux_sandbox_lab.ROOT) not in message
