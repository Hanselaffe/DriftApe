"""WP3 shared structured PowerShell acquisition transport tests."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from driftape.acquisition import powershell


@pytest.fixture
def resolved_executable(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(powershell.os.path, "isfile", lambda _path: True)
    return r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _completed(stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> object:
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_executable_path_is_exact_and_path_not_consulted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-WP3-PS-001/002: resolution uses SystemRoot only and exact System32 path."""
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setenv("PATH", r"Z:\malicious")
    monkeypatch.setattr(powershell.os.path, "isfile", lambda _path: True)
    assert powershell.resolve_powershell_executable() == (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )


def test_missing_systemroot_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-PS-003: missing SystemRoot is a dedicated unavailable failure."""
    monkeypatch.delenv("SystemRoot", raising=False)
    with pytest.raises(powershell.PowerShellUnavailableError):
        powershell.resolve_powershell_executable()


def test_missing_executable_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-PS-004: missing built-in executable is unavailable."""
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(powershell.os.path, "isfile", lambda _path: False)
    with pytest.raises(powershell.PowerShellUnavailableError):
        powershell.resolve_powershell_executable()


def test_invocation_contract(
    monkeypatch: pytest.MonkeyPatch, resolved_executable: str
) -> None:
    """T-WP3-PS-005..010: subprocess flags, shell mode and fixed prelude are exact."""
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> object:
        captured["argv"] = argv
        captured.update(kwargs)
        return _completed(b'{"ok":true}')

    monkeypatch.setattr(powershell.subprocess, "run", fake_run)
    assert powershell.run_powershell_json("'{}'", timeout_seconds=5) == {"ok": True}

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[0] == resolved_executable
    assert captured["shell"] is False
    assert ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"] == argv[1:5]
    joined = " ".join(argv)
    assert "-ExecutionPolicy" not in joined
    assert "Bypass" not in joined
    assert "-EncodedCommand" not in joined
    assert "-NoExit" not in joined
    command = argv[5]
    assert "$ErrorActionPreference = 'Stop'" in command
    assert "[Console]::OutputEncoding" in command
    assert "$OutputEncoding" in command
    assert "UTF8Encoding($false)" in command


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (b'{"key":"value"}', {"key": "value"}),
        (b"[1,2,3]", [1, 2, 3]),
        ('{"name":"Überwachungsdienst"}'.encode(), {"name": "Überwachungsdienst"}),
        (b"  \r\n {\"ok\": true} \t ", {"ok": True}),
    ],
)
def test_valid_json_forms(
    monkeypatch: pytest.MonkeyPatch,
    resolved_executable: str,
    stdout: bytes,
    expected: object,
) -> None:
    """T-WP3-PS-011..014: object/array/Unicode/whitespace JSON parse correctly."""
    monkeypatch.setattr(
        powershell.subprocess, "run", lambda *_args, **_kwargs: _completed(stdout)
    )
    assert powershell.run_powershell_json("'static'", timeout_seconds=1) == expected


@pytest.mark.parametrize("stdout", [b"", b"  \r\n\t", b"{broken", b"{}{}"])
def test_invalid_json_output_raises(
    monkeypatch: pytest.MonkeyPatch,
    resolved_executable: str,
    stdout: bytes,
) -> None:
    """T-WP3-PS-015..017: empty, malformed or concatenated JSON is rejected."""
    monkeypatch.setattr(
        powershell.subprocess, "run", lambda *_args, **_kwargs: _completed(stdout)
    )
    with pytest.raises(powershell.PowerShellOutputError):
        powershell.run_powershell_json("'static'", timeout_seconds=1)


def test_nonzero_exit_exposes_return_code_and_bounded_stderr(
    monkeypatch: pytest.MonkeyPatch, resolved_executable: str
) -> None:
    """T-WP3-PS-018/019: command failure is distinct and exposes numeric code."""
    monkeypatch.setattr(
        powershell.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed(b"", b"synthetic failure", 7),
    )
    with pytest.raises(powershell.PowerShellCommandError) as caught:
        powershell.run_powershell_json("'static'", timeout_seconds=1)
    assert caught.value.return_code == 7
    assert caught.value.stderr_message == "synthetic failure"


def test_timeout_is_distinct(
    monkeypatch: pytest.MonkeyPatch, resolved_executable: str
) -> None:
    """T-WP3-PS-020: subprocess timeout becomes dedicated timeout exception."""
    def timeout(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=2.5)

    monkeypatch.setattr(powershell.subprocess, "run", timeout)
    with pytest.raises(powershell.PowerShellTimeoutError) as caught:
        powershell.run_powershell_json("'static'", timeout_seconds=2.5)
    assert caught.value.timeout_seconds == 2.5


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
def test_invalid_timeout_rejected(timeout: float) -> None:
    """T-WP3-PS-021: invalid/non-positive timeout raises ValueError."""
    with pytest.raises(ValueError):
        powershell.run_powershell_json("'static'", timeout_seconds=timeout)


@pytest.mark.parametrize("script", ["", "   ", None, 123])
def test_invalid_script_rejected_without_coercion(script: object) -> None:
    """T-WP3-PS-022/023: script must be a non-empty str and is never coerced."""
    with pytest.raises(ValueError):
        powershell.run_powershell_json(  # type: ignore[arg-type]
            script, timeout_seconds=1
        )


def test_runner_does_not_print_process_streams(
    monkeypatch: pytest.MonkeyPatch,
    resolved_executable: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """WP3 no-leakage contract: subprocess stdout/stderr are never printed."""
    monkeypatch.setattr(
        powershell.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed(b'{"ok":true}', b"benign stderr", 0),
    )
    assert powershell.run_powershell_json("'static'", timeout_seconds=1) == {"ok": True}
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_invalid_utf8_stdout_is_output_error(
    monkeypatch: pytest.MonkeyPatch, resolved_executable: str
) -> None:
    """WP3 UTF-8 contract: undecodable stdout is a structured-output failure."""
    monkeypatch.setattr(
        powershell.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed(b"\xff\xfe"),
    )
    with pytest.raises(powershell.PowerShellOutputError):
        powershell.run_powershell_json("'static'", timeout_seconds=1)
