"""Read-only Windows platform inspection for DriftApe v0.1."""

from __future__ import annotations

import ctypes
import hashlib
import platform
import socket
import struct
import sys
from typing import cast

from driftape.models import HostInfo

_SUPPORTED_MACHINE_NAMES = frozenset({"amd64", "x86_64"})
_PRODUCT_NAME_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_MACHINE_GUID_KEY = r"SOFTWARE\Microsoft\Cryptography"


class UnsupportedPlatformError(RuntimeError):
    """Raised when the runtime is outside the DriftApe v0.1 Windows x64 target."""


class PlatformInspectionError(RuntimeError):
    """Raised when required local Windows host inspection fails."""


def _machine_architecture() -> str:
    return platform.machine()


def _is_64_bit_process() -> bool:
    return struct.calcsize("P") == 8


def is_supported_platform() -> bool:
    """Return whether the current runtime is supported by DriftApe v0.1."""
    return (
        sys.platform == "win32"
        and _is_64_bit_process()
        and _machine_architecture().casefold() in _SUPPORTED_MACHINE_NAMES
    )


def require_supported_platform() -> None:
    """Require the Windows x64 runtime supported by DriftApe v0.1."""
    if not is_supported_platform():
        raise UnsupportedPlatformError(
            "DriftApe v0.1 requires 64-bit Python on Windows x64 (AMD64)."
        )


def is_elevated() -> bool:
    """Inspect the current process administrative elevation state without changes."""
    require_supported_platform()
    try:
        windll = getattr(ctypes, "windll")
        result = windll.shell32.IsUserAnAdmin()
    except Exception as exc:
        raise PlatformInspectionError(
            "Failed to inspect Windows administrative elevation state."
        ) from exc
    return bool(result)


def _read_registry_string(subkey: str, value_name: str) -> str:
    """Read one authorized string value from the 64-bit HKLM registry view."""
    require_supported_platform()
    try:
        import winreg

        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, access) as key:
            value, _value_type = winreg.QueryValueEx(key, value_name)
    except (OSError, ImportError) as exc:
        raise PlatformInspectionError(
            f"Failed to read required Windows registry value {value_name}."
        ) from exc

    if not isinstance(value, str) or value == "":
        raise PlatformInspectionError(
            f"Windows registry value {value_name} is not a non-empty string."
        )
    return value


def _get_windows_version() -> tuple[int, int, int]:
    require_supported_platform()
    try:
        getwindowsversion = getattr(sys, "getwindowsversion")
        version = getwindowsversion()
        major = int(version.major)
        minor = int(version.minor)
        build = int(version.build)
    except Exception as exc:
        raise PlatformInspectionError("Failed to inspect Windows version.") from exc
    return major, minor, build


def _normalized_hostname() -> str:
    try:
        hostname = socket.gethostname().strip()
    except OSError as exc:
        raise PlatformInspectionError("Failed to inspect local hostname.") from exc
    if hostname == "":
        raise PlatformInspectionError("Local hostname is empty.")
    return hostname


def _machine_guid_sha256() -> str | None:
    try:
        raw_machine_guid = _read_registry_string(_MACHINE_GUID_KEY, "MachineGuid")
    except PlatformInspectionError:
        return None

    normalized = raw_machine_guid.strip().lower()
    if normalized == "":
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def collect_host_info() -> HostInfo:
    """Collect the bounded canonical DriftApe host metadata for Windows x64."""
    require_supported_platform()

    hostname = _normalized_hostname()
    major, minor, build = _get_windows_version()
    try:
        os_name = _read_registry_string(_PRODUCT_NAME_KEY, "ProductName")
    except PlatformInspectionError as exc:
        raise PlatformInspectionError(
            "Failed to inspect Windows product name."
        ) from exc

    machine_id_sha256 = _machine_guid_sha256()

    return HostInfo(
        hostname=hostname,
        machine_id_sha256=cast(str | None, machine_id_sha256),
        os_name=os_name,
        os_version=f"{major}.{minor}.{build}",
        os_build=str(build),
        architecture="AMD64",
    )
