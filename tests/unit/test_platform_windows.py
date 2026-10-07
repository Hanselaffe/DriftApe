"""WP3 Windows platform and host metadata tests."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from driftape import platform_windows
from driftape.models import HostInfo


def _supported(monkeypatch: pytest.MonkeyPatch, machine: str = "AMD64") -> None:
    monkeypatch.setattr(platform_windows.sys, "platform", "win32")
    monkeypatch.setattr(platform_windows, "_is_64_bit_process", lambda: True)
    monkeypatch.setattr(platform_windows, "_machine_architecture", lambda: machine)


def test_supported_windows_x64_is_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-PLAT-001: supported Windows x64 evaluates true."""
    _supported(monkeypatch, "x86_64")
    assert platform_windows.is_supported_platform() is True


def test_non_windows_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-PLAT-002: non-Windows evaluates false."""
    monkeypatch.setattr(platform_windows.sys, "platform", "linux")
    monkeypatch.setattr(platform_windows, "_is_64_bit_process", lambda: True)
    monkeypatch.setattr(platform_windows, "_machine_architecture", lambda: "AMD64")
    assert platform_windows.is_supported_platform() is False


def test_32_bit_windows_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-PLAT-003: 32-bit Python on Windows evaluates false."""
    monkeypatch.setattr(platform_windows.sys, "platform", "win32")
    monkeypatch.setattr(platform_windows, "_is_64_bit_process", lambda: False)
    monkeypatch.setattr(platform_windows, "_machine_architecture", lambda: "AMD64")
    assert platform_windows.is_supported_platform() is False


def test_windows_arm64_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-PLAT-004: Windows ARM64 evaluates false."""
    _supported(monkeypatch, "ARM64")
    assert platform_windows.is_supported_platform() is False


def test_require_supported_platform_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-PLAT-005: unsupported runtime raises dedicated exception."""
    monkeypatch.setattr(platform_windows.sys, "platform", "linux")
    with pytest.raises(platform_windows.UnsupportedPlatformError):
        platform_windows.require_supported_platform()


@pytest.mark.parametrize(("native_result", "expected"), [(1, True), (0, False)])
def test_elevation_api_result(
    monkeypatch: pytest.MonkeyPatch, native_result: int, expected: bool
) -> None:
    """T-WP3-PLAT-006/007: native elevation result maps directly to bool."""
    _supported(monkeypatch)
    fake_windll = SimpleNamespace(
        shell32=SimpleNamespace(IsUserAnAdmin=lambda: native_result)
    )
    monkeypatch.setattr(platform_windows.ctypes, "windll", fake_windll, raising=False)
    assert platform_windows.is_elevated() is expected


def test_elevation_api_failure_is_inspection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-WP3-PLAT-008: native API failure is not converted to false."""
    _supported(monkeypatch)

    def fail() -> int:
        raise OSError("synthetic failure")

    fake_windll = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=fail))
    monkeypatch.setattr(platform_windows.ctypes, "windll", fake_windll, raising=False)
    with pytest.raises(platform_windows.PlatformInspectionError):
        platform_windows.is_elevated()


def test_collect_host_info_valid_synthetic_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-WP3-HOST-001..006: valid bounded host inputs produce canonical HostInfo."""
    _supported(monkeypatch)
    monkeypatch.setattr(platform_windows.socket, "gethostname", lambda: "HOST01")
    monkeypatch.setattr(
        platform_windows, "_get_windows_version", lambda: (10, 0, 26100)
    )

    def read_registry(subkey: str, value_name: str) -> str:
        if value_name == "ProductName":
            assert subkey == platform_windows._PRODUCT_NAME_KEY
            return "Windows 11 Pro"
        assert subkey == platform_windows._MACHINE_GUID_KEY
        assert value_name == "MachineGuid"
        return "  ABCD-1234  "

    monkeypatch.setattr(platform_windows, "_read_registry_string", read_registry)
    host = platform_windows.collect_host_info()

    assert isinstance(host, HostInfo)
    assert host.hostname == "HOST01"
    assert host.os_name == "Windows 11 Pro"
    assert host.os_version == "10.0.26100"
    assert host.os_build == "26100"
    assert host.architecture == "AMD64"


def test_machine_guid_hash_contract_and_raw_value_not_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-WP3-HOST-007/008: MachineGuid normalization and privacy are exact."""
    _supported(monkeypatch)
    raw = "  ABCD-1234  "
    normalized = "abcd-1234"
    expected = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    monkeypatch.setattr(platform_windows.socket, "gethostname", lambda: "HOST01")
    monkeypatch.setattr(
        platform_windows, "_get_windows_version", lambda: (10, 0, 26100)
    )
    monkeypatch.setattr(
        platform_windows,
        "_read_registry_string",
        lambda _key, name: "Windows 11 Pro" if name == "ProductName" else raw,
    )

    host = platform_windows.collect_host_info()
    assert host.machine_id_sha256 == expected
    assert raw not in repr(host)
    assert normalized not in repr(host)


def test_machine_guid_failure_becomes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-WP3-HOST-009: unavailable MachineGuid yields None without fallback ID."""
    _supported(monkeypatch)
    monkeypatch.setattr(platform_windows.socket, "gethostname", lambda: "HOST01")
    monkeypatch.setattr(
        platform_windows, "_get_windows_version", lambda: (10, 0, 26100)
    )

    def read_registry(_key: str, name: str) -> str:
        if name == "ProductName":
            return "Windows 11 Pro"
        raise platform_windows.PlatformInspectionError("missing")

    monkeypatch.setattr(platform_windows, "_read_registry_string", read_registry)
    assert platform_windows.collect_host_info().machine_id_sha256 is None


def test_product_name_failure_is_inspection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-WP3-HOST-010: required ProductName failure is fatal inspection error."""
    _supported(monkeypatch)
    monkeypatch.setattr(platform_windows.socket, "gethostname", lambda: "HOST01")
    monkeypatch.setattr(
        platform_windows, "_get_windows_version", lambda: (10, 0, 26100)
    )
    monkeypatch.setattr(
        platform_windows,
        "_read_registry_string",
        lambda _key, _name: (_ for _ in ()).throw(
            platform_windows.PlatformInspectionError("missing")
        ),
    )
    with pytest.raises(platform_windows.PlatformInspectionError):
        platform_windows.collect_host_info()


def test_registry_helper_uses_read_only_64_bit_hklm_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WP3 registry discipline: authorized reads use HKLM and the 64-bit read view."""
    import sys

    _supported(monkeypatch)
    opened: dict[str, object] = {}

    class FakeKey:
        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    class FakeWinreg:
        HKEY_LOCAL_MACHINE = object()
        KEY_READ = 0x20019
        KEY_WOW64_64KEY = 0x0100

        @staticmethod
        def OpenKey(root: object, subkey: str, reserved: int, access: int) -> FakeKey:
            opened.update(
                root=root,
                subkey=subkey,
                reserved=reserved,
                access=access,
            )
            return FakeKey()

        @staticmethod
        def QueryValueEx(_key: object, value_name: str) -> tuple[str, int]:
            opened["value_name"] = value_name
            return "Windows 11 Pro", 1

    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg)
    value = platform_windows._read_registry_string(
        platform_windows._PRODUCT_NAME_KEY, "ProductName"
    )
    assert value == "Windows 11 Pro"
    assert opened["root"] is FakeWinreg.HKEY_LOCAL_MACHINE
    assert opened["subkey"] == platform_windows._PRODUCT_NAME_KEY
    assert opened["reserved"] == 0
    assert opened["access"] == FakeWinreg.KEY_READ | FakeWinreg.KEY_WOW64_64KEY
    assert opened["value_name"] == "ProductName"
