"""Shared structured Windows PowerShell acquisition transport for DriftApe."""

from __future__ import annotations

import json
import math
import os
import subprocess
from pathlib import PureWindowsPath

_MAX_STDERR_CHARS = 4096
_POWERSHELL_RELATIVE_PATH = PureWindowsPath(
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
)
_POWERSHELL_PRELUDE = (
    "$ErrorActionPreference = 'Stop'; "
    "$utf8 = New-Object System.Text.UTF8Encoding($false); "
    "[Console]::OutputEncoding = $utf8; "
    "$OutputEncoding = $utf8; "
)


class PowerShellError(RuntimeError):
    """Base exception for the shared PowerShell acquisition transport."""


class PowerShellUnavailableError(PowerShellError):
    """Raised when built-in 64-bit Windows PowerShell cannot be resolved."""


class PowerShellTimeoutError(PowerShellError):
    """Raised when a trusted PowerShell acquisition exceeds its timeout."""

    def __init__(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"PowerShell command timed out after {timeout_seconds} seconds."
        )


class PowerShellCommandError(PowerShellError):
    """Raised when PowerShell exits with a non-zero return code."""

    def __init__(self, return_code: int, stderr_message: str) -> None:
        self.return_code = return_code
        self.stderr_message = stderr_message
        message = f"PowerShell command failed with exit code {return_code}."
        if stderr_message:
            message = f"{message} {stderr_message}"
        super().__init__(message)


class PowerShellOutputError(PowerShellError):
    """Raised when successful PowerShell stdout is not exactly one JSON document."""


def resolve_powershell_executable() -> str:
    """Resolve only the built-in 64-bit Windows PowerShell executable."""
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise PowerShellUnavailableError("SystemRoot is unavailable.")

    executable = str(PureWindowsPath(system_root) / _POWERSHELL_RELATIVE_PATH)
    if not os.path.isfile(executable):
        raise PowerShellUnavailableError(
            "Built-in 64-bit Windows PowerShell executable is unavailable."
        )
    return executable


def _validate_arguments(script: object, timeout_seconds: object) -> tuple[str, float]:
    if not isinstance(script, str) or script.strip() == "":
        raise ValueError("script must be a non-empty string")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or float(timeout_seconds) <= 0
    ):
        raise ValueError("timeout_seconds must be a finite number greater than zero")
    return script, float(timeout_seconds)


def _decode_stderr(stderr: bytes) -> str:
    message = stderr.decode("utf-8", errors="replace").strip()
    if len(message) > _MAX_STDERR_CHARS:
        return message[:_MAX_STDERR_CHARS] + "…"
    return message


def run_powershell_json(
    script: str,
    *,
    timeout_seconds: float,
) -> object:
    """Run a trusted static PowerShell script and return its single JSON value."""
    trusted_script, timeout = _validate_arguments(script, timeout_seconds)
    executable = resolve_powershell_executable()
    command = _POWERSHELL_PRELUDE + trusted_script
    argv = [
        executable,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        command,
    ]

    try:
        completed = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise PowerShellTimeoutError(timeout) from exc
    except OSError as exc:
        raise PowerShellUnavailableError(
            "Failed to start built-in Windows PowerShell."
        ) from exc

    if completed.returncode != 0:
        raise PowerShellCommandError(
            completed.returncode,
            _decode_stderr(completed.stderr),
        )

    try:
        stdout = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PowerShellOutputError("PowerShell stdout is not valid UTF-8.") from exc

    if stdout.strip() == "":
        raise PowerShellOutputError("PowerShell stdout is empty.")

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise PowerShellOutputError(
            "PowerShell stdout is not exactly one valid JSON document."
        ) from exc
