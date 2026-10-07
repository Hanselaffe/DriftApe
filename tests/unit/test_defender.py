"""WP7 Microsoft Defender collector tests."""

from __future__ import annotations

import inspect
import re
from typing import Any

import pytest

from driftape.acquisition import powershell
from driftape.collectors import defender
from driftape.models import (
    CollectorStatus,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderExclusion,
    DefenderExclusionKind,
    DefenderRuntime,
    ErrorCode,
)


def _preference_data(
    *,
    paths: object = None,
    processes: object = None,
    extensions: object = None,
    ip_addresses: object = None,
    disable_realtime_monitoring: object = False,
) -> dict[str, object]:
    return {
        "ExclusionPath": [] if paths is None else paths,
        "ExclusionProcess": [] if processes is None else processes,
        "ExclusionExtension": [] if extensions is None else extensions,
        "ExclusionIpAddress": [] if ip_addresses is None else ip_addresses,
        "DisableRealtimeMonitoring": disable_realtime_monitoring,
    }


def _success(data: object) -> dict[str, object]:
    return {"ok": True, "data": data, "error": None}


def _failure(
    *,
    category: object = "NotSpecified",
    message: object = "synthetic failure",
    native_code: object = -1,
) -> dict[str, object]:
    return {
        "ok": False,
        "data": None,
        "error": {
            "category": category,
            "message": message,
            "native_code": native_code,
            "fully_qualified_error_id": "SyntheticFailure",
        },
    }


def _document(
    *,
    preference: object | None = None,
    status: object | None = None,
) -> dict[str, object]:
    return {
        "preference": (
            _success(_preference_data()) if preference is None else preference
        ),
        "status": (
            _success({"RealTimeProtectionEnabled": True})
            if status is None
            else status
        ),
    }


@pytest.fixture(autouse=True)
def supported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        defender.platform_windows,
        "require_supported_platform",
        lambda: None,
    )


def _collect(
    monkeypatch: pytest.MonkeyPatch,
    document: object,
) -> DefenderCollectorResult:
    monkeypatch.setattr(
        defender.powershell,
        "run_powershell_json",
        lambda _script, *, timeout_seconds: document,
    )
    return defender.collect_defender()


def _assert_all_none(result: DefenderCollectorResult) -> None:
    assert result.data.exclusions is None
    assert result.data.configuration is None
    assert result.data.runtime is None


def _error_codes(result: DefenderCollectorResult) -> set[ErrorCode]:
    return {error.code for error in result.errors}


def test_t_wp7_001_valid_full_acquisition_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.status is CollectorStatus.SUCCESS
    assert result.coverage == frozenset({"exclusions", "configuration", "runtime"})
    assert result.errors == ()


def test_t_wp7_002_configuration_id_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.configuration == DefenderConfiguration(
        id="microsoft_defender", disable_realtime_monitoring=False
    )


def test_t_wp7_003_runtime_id_is_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.runtime == DefenderRuntime(
        id="microsoft_defender", real_time_protection_enabled=True
    )


def test_t_wp7_004_zero_exclusions_is_covered_empty_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.exclusions == ()
    assert "exclusions" in result.coverage


def test_t_wp7_005_configuration_false_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.configuration is not None
    assert result.data.configuration.disable_realtime_monitoring is False


def test_t_wp7_006_configuration_true_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(disable_realtime_monitoring=True))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.configuration is not None
    assert result.data.configuration.disable_realtime_monitoring is True


def test_t_wp7_007_configuration_string_boolean_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(disable_realtime_monitoring="false"))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"exclusions", "runtime"})
    assert result.data.configuration is None


@pytest.mark.parametrize("value", [0, 1])
def test_t_wp7_008_configuration_integer_boolean_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    value: int,
) -> None:
    pref = _success(_preference_data(disable_realtime_monitoring=value))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "configuration" not in result.coverage
    assert result.data.configuration is None


def test_t_wp7_009_runtime_true_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.runtime is not None
    assert result.data.runtime.real_time_protection_enabled is True


def test_t_wp7_010_runtime_false_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    status = _success({"RealTimeProtectionEnabled": False})
    result = _collect(monkeypatch, _document(status=status))
    assert result.data.runtime is not None
    assert result.data.runtime.real_time_protection_enabled is False


@pytest.mark.parametrize("value", ["true", "false", 0, 1])
def test_t_wp7_011_runtime_non_boolean_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    result = _collect(
        monkeypatch,
        _document(status=_success({"RealTimeProtectionEnabled": value})),
    )
    assert "runtime" not in result.coverage
    assert result.data.runtime is None


def test_t_wp7_012_path_outer_whitespace_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(paths=["  C:\\Temp  "]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].value == r"C:\Temp"


def test_t_wp7_013_slashes_become_backslashes(monkeypatch: pytest.MonkeyPatch) -> None:
    pref = _success(_preference_data(paths=["C:/Temp/Test"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].value == r"C:\Temp\Test"


def test_t_wp7_014_path_process_case_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(
        _preference_data(paths=["C:/TeMp"], processes=["C:/Tools/Agent.EXE"])
    )
    values = {item.kind: item.value for item in _collect(
        monkeypatch, _document(preference=pref)
    ).data.exclusions or ()}
    assert values[DefenderExclusionKind.PATH] == r"C:\TeMp"
    assert values[DefenderExclusionKind.PROCESS] == r"C:\Tools\Agent.EXE"


def test_t_wp7_015_path_process_id_is_casefolded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(processes=["C:/Tools/Agent.EXE"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions == (
        DefenderExclusion(
            id=r"process:c:\tools\agent.exe",
            kind=DefenderExclusionKind.PROCESS,
            value=r"C:\Tools\Agent.EXE",
        ),
    )


def test_t_wp7_016_environment_variable_is_not_expanded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = r"%SystemRoot%/Temp"
    pref = _success(_preference_data(paths=[value]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].value == r"%SystemRoot%\Temp"


@pytest.mark.parametrize("field", ["paths", "processes"])
def test_t_wp7_017_whitespace_path_process_rejects_exclusions(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    kwargs = {field: [" \t "]}
    pref = _success(_preference_data(**kwargs))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "exclusions" not in result.coverage
    assert result.data.exclusions is None


def test_t_wp7_018_extension_leading_dot_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(extensions=[".EXE"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions == (
        DefenderExclusion(
            id="extension:exe",
            kind=DefenderExclusionKind.EXTENSION,
            value="EXE",
        ),
    )


def test_t_wp7_019_extension_without_dot_has_same_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(extensions=["exe"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].id == "extension:exe"
    assert result.data.exclusions[0].value == "exe"


def test_t_wp7_020_single_dot_extension_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(extensions=["."]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "exclusions" not in result.coverage


def test_t_wp7_021_whitespace_extension_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(extensions=["   "]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "exclusions" not in result.coverage


def test_t_wp7_022_ipv4_uses_canonical_ipaddress_representation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(ip_addresses=[" 192.0.2.5 "]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].value == "192.0.2.5"
    assert result.data.exclusions[0].id == "ip_address:192.0.2.5"


def test_t_wp7_023_ipv6_is_compressed(monkeypatch: pytest.MonkeyPatch) -> None:
    pref = _success(
        _preference_data(ip_addresses=["2001:0DB8:0000:0000:0000:0000:0000:0001"])
    )
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].value == "2001:db8::1"
    assert result.data.exclusions[0].id == "ip_address:2001:db8::1"


def test_t_wp7_024_unparseable_ip_text_is_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(ip_addresses=["  Example-RANGE  "]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].value == "Example-RANGE"
    assert result.data.exclusions[0].id == "ip_address:example-range"


def test_t_wp7_025_ip_normalization_has_no_network_api() -> None:
    source = inspect.getsource(defender)
    for forbidden in ("socket", "getaddrinfo", "urllib", "requests", "http.client"):
        assert forbidden not in source


def test_t_wp7_026_exact_duplicate_invalidates_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(paths=[r"C:\Temp", r"C:\Temp"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is None
    assert result.coverage == frozenset({"configuration", "runtime"})


def test_t_wp7_027_case_only_path_duplicate_invalidates_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(paths=[r"C:\Temp", r"c:\TEMP"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "exclusions" not in result.coverage


def test_t_wp7_028_slash_equivalent_duplicate_invalidates_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(processes=["C:/A/x.exe", r"c:\a\X.EXE"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "exclusions" not in result.coverage


def test_t_wp7_029_extension_collision_invalidates_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(extensions=[".EXE", "exe"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "exclusions" not in result.coverage


def test_t_wp7_030_equivalent_ipv6_collision_invalidates_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(ip_addresses=["2001:db8::1", "2001:0db8:0:0:0:0:0:1"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert "exclusions" not in result.coverage


def test_t_wp7_031_final_exclusions_sort_by_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(
        _preference_data(paths=[r"Z:\x", r"A:\x"], extensions=["zip", "exe"])
    )
    result = _collect(monkeypatch, _document(preference=pref))
    ids = [item.id for item in result.data.exclusions or ()]
    assert ids == sorted(ids)


def test_t_wp7_032_source_order_does_not_change_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _success(_preference_data(paths=[r"Z:\x", r"A:\x"]))
    second = _success(_preference_data(paths=[r"A:\x", r"Z:\x"]))
    assert _collect(monkeypatch, _document(preference=first)).data.exclusions == _collect(
        monkeypatch, _document(preference=second)
    ).data.exclusions


def test_t_wp7_033_order_across_kinds_is_by_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(
        _preference_data(
            paths=[r"C:\Temp"],
            processes=[r"C:\Tool.exe"],
            extensions=["exe"],
            ip_addresses=["192.0.2.5"],
        )
    )
    ids = [item.id for item in _collect(
        monkeypatch, _document(preference=pref)
    ).data.exclusions or ()]
    assert ids == [
        "extension:exe",
        "ip_address:192.0.2.5",
        r"path:c:\temp",
        r"process:c:\tool.exe",
    ]


def test_t_wp7_034_preference_success_runtime_failure_is_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(status=_failure()))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"exclusions", "configuration"})
    assert result.data.runtime is None


def test_t_wp7_035_preference_failure_runtime_success_is_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(preference=_failure()))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"runtime"})
    assert result.data.exclusions is None
    assert result.data.configuration is None


def test_t_wp7_036_malformed_exclusions_preserve_config_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(paths="not-array"))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"configuration", "runtime"})
    assert result.data.exclusions is None


def test_t_wp7_037_malformed_config_preserves_exclusions_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(disable_realtime_monitoring=None))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"exclusions", "runtime"})
    assert result.data.configuration is None


def test_t_wp7_038_only_exclusions_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    pref = _success(_preference_data(disable_realtime_monitoring=None))
    result = _collect(monkeypatch, _document(preference=pref, status=_failure()))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"exclusions"})
    assert result.data.exclusions == ()
    assert result.data.configuration is None
    assert result.data.runtime is None


def test_t_wp7_039_no_logical_section_complete_is_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(preference=_failure(), status=_failure()),
    )
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    _assert_all_none(result)


def test_t_wp7_040_preference_permission_denied_maps_access_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(preference=_failure(category="PermissionDenied", message="localized")),
    )
    assert result.errors[0].code is ErrorCode.ACCESS_DENIED
    assert result.errors[0].scope == "collector.defender.preference"


def test_t_wp7_041_preference_other_failure_maps_command_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(preference=_failure(category="ObjectNotFound")),
    )
    assert result.errors[0].code is ErrorCode.COMMAND_FAILED


def test_t_wp7_042_runtime_permission_denied_maps_access_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(status=_failure(category="PermissionDenied")),
    )
    assert result.errors[0].code is ErrorCode.ACCESS_DENIED
    assert result.errors[0].scope == "collector.defender.runtime"


def test_t_wp7_043_runtime_other_failure_maps_command_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(status=_failure(category="ObjectNotFound")))
    assert result.errors[0].code is ErrorCode.COMMAND_FAILED


@pytest.mark.parametrize(
    ("exception", "expected_code", "native_code"),
    [
        (
            powershell.PowerShellUnavailableError("unavailable"),
            ErrorCode.COLLECTOR_UNAVAILABLE,
            None,
        ),
        (powershell.PowerShellTimeoutError(60), ErrorCode.COMMAND_TIMEOUT, None),
        (
            powershell.PowerShellCommandError(23, "details"),
            ErrorCode.COMMAND_FAILED,
            23,
        ),
        (
            powershell.PowerShellOutputError("bad output"),
            ErrorCode.UNEXPECTED_OUTPUT,
            None,
        ),
    ],
)
def test_t_wp7_044_to_047_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    exception: Exception,
    expected_code: ErrorCode,
    native_code: int | None,
) -> None:
    def fail(_script: str, *, timeout_seconds: float) -> object:
        raise exception

    monkeypatch.setattr(defender.powershell, "run_powershell_json", fail)
    result = defender.collect_defender()
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    _assert_all_none(result)
    assert result.errors[0].code is expected_code
    assert result.errors[0].native_code == native_code
    assert result.errors[0].recoverable is True


def test_t_wp7_048_unsupported_platform_skips_powershell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unsupported() -> None:
        raise defender.platform_windows.UnsupportedPlatformError("unsupported")

    called = False

    def forbidden(_script: str, *, timeout_seconds: float) -> object:
        nonlocal called
        called = True
        return _document()

    monkeypatch.setattr(defender.platform_windows, "require_supported_platform", unsupported)
    monkeypatch.setattr(defender.powershell, "run_powershell_json", forbidden)
    result = defender.collect_defender()
    assert called is False
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    _assert_all_none(result)
    assert result.errors[0].code is ErrorCode.UNSUPPORTED_OS
    assert result.errors[0].scope == "collector.defender"
    assert result.errors[0].operation == "platform check"
    assert result.errors[0].recoverable is False


def test_t_wp7_049_root_not_object_is_failed_unexpected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, [])
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    _assert_all_none(result)
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT
    assert result.errors[0].scope == "collector.defender"


def test_t_wp7_050_malformed_preference_envelope_preserves_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(preference=[]))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"runtime"})
    assert result.data.runtime is not None


def test_t_wp7_051_malformed_status_envelope_preserves_preference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(status=[]))
    assert result.status is CollectorStatus.PARTIAL
    assert result.coverage == frozenset({"exclusions", "configuration"})
    assert result.data.exclusions == ()
    assert result.data.configuration is not None


def test_t_wp7_052_exclusion_source_must_be_array(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(extensions="exe"))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is None
    assert "exclusions" not in result.coverage
    assert ErrorCode.UNEXPECTED_OUTPUT in _error_codes(result)


def test_t_wp7_053_non_string_exclusion_rejects_entire_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(paths=[r"C:\Good", 7]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is None
    assert "exclusions" not in result.coverage


def test_t_wp7_054_uses_only_shared_powershell_transport() -> None:
    source = inspect.getsource(defender)
    assert "run_powershell_json" in source
    assert "subprocess" not in source


def test_t_wp7_055_timeout_is_exactly_sixty_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def capture(script: str, *, timeout_seconds: float) -> object:
        observed["script"] = script
        observed["timeout"] = timeout_seconds
        return _document()

    monkeypatch.setattr(defender.powershell, "run_powershell_json", capture)
    result = defender.collect_defender()
    assert result.status is CollectorStatus.SUCCESS
    assert observed["timeout"] == 60


def test_t_wp7_056_script_contains_required_cmdlets() -> None:
    script = defender._DEFENDER_POWERSHELL_SCRIPT
    assert "Get-MpPreference" in script
    assert "Get-MpComputerStatus" in script


def test_t_wp7_057_preference_projects_only_authorized_facts() -> None:
    script = defender._DEFENDER_POWERSHELL_SCRIPT
    refs = set(re.findall(r"\$pref\.([A-Za-z0-9_]+)", script))
    assert refs == {
        "ExclusionPath",
        "ExclusionProcess",
        "ExclusionExtension",
        "ExclusionIpAddress",
        "DisableRealtimeMonitoring",
    }


def test_t_wp7_058_status_projects_only_authorized_fact() -> None:
    script = defender._DEFENDER_POWERSHELL_SCRIPT
    refs = set(re.findall(r"\$computerStatus\.([A-Za-z0-9_]+)", script))
    assert refs == {"RealTimeProtectionEnabled"}


def test_t_wp7_059_script_forces_exclusion_arrays() -> None:
    script = defender._DEFENDER_POWERSHELL_SCRIPT
    for field in (
        "ExclusionPath",
        "ExclusionProcess",
        "ExclusionExtension",
        "ExclusionIpAddress",
    ):
        assert re.search(rf"{field}\s*=\s*@\(", script)


def test_t_wp7_060_script_uses_structured_json() -> None:
    script = defender._DEFENDER_POWERSHELL_SCRIPT
    assert "ConvertTo-Json -Compress" in script
    assert "-Depth 6" in script


def test_t_wp7_061_command_failures_are_independently_captured() -> None:
    script = defender._DEFENDER_POWERSHELL_SCRIPT
    assert script.count("try {") == 2
    assert script.count("catch {") == 2
    assert "$preference" in script
    assert "$status" in script


def test_t_wp7_062_no_defender_mutation_scan_update_cmdlet() -> None:
    source = inspect.getsource(defender).casefold()
    for forbidden in (
        "set-mppreference",
        "add-mppreference",
        "remove-mppreference",
        "start-mpscan",
        "update-mpsignature",
        "remove-mpthreat",
    ):
        assert forbidden not in source


def test_preference_data_missing_invalidates_both_preference_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(preference={"ok": True, "error": None}))
    assert result.coverage == frozenset({"runtime"})
    assert result.errors[0].scope == "collector.defender.preference"


def test_runtime_data_missing_invalidates_only_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(status={"ok": True, "error": None}))
    assert result.coverage == frozenset({"exclusions", "configuration"})
    assert result.data.runtime is None


def test_malformed_preference_error_shape_is_unexpected_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    section = {"ok": False, "data": None, "error": "bad"}
    result = _collect(monkeypatch, _document(preference=section))
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


def test_malformed_runtime_error_shape_is_unexpected_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    section = {"ok": False, "data": None, "error": "bad"}
    result = _collect(monkeypatch, _document(status=section))
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT


def test_whitespace_only_ip_is_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    pref = _success(_preference_data(ip_addresses=["   "]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is None


def test_non_string_ip_is_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    pref = _success(_preference_data(ip_addresses=[123]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is None


def test_exactly_one_leading_extension_dot_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pref = _success(_preference_data(extensions=["..EXE"]))
    result = _collect(monkeypatch, _document(preference=pref))
    assert result.data.exclusions is not None
    assert result.data.exclusions[0].value == ".EXE"
    assert result.data.exclusions[0].id == "extension:.exe"


def test_native_error_code_boolean_is_not_persisted_as_integer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(preference=_failure(native_code=True)),
    )
    assert result.errors[0].native_code is None


def test_error_message_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    message = "x" * 2000
    result = _collect(
        monkeypatch,
        _document(preference=_failure(message=message)),
    )
    assert len(result.errors[0].message) == 1025
    assert result.errors[0].message.endswith("…")


def test_production_scope_contains_no_remote_or_security_interpretation() -> None:
    source = inspect.getsource(defender).casefold()
    for forbidden in (
        "invoke-command",
        "new-pssession",
        "shell=true",
        "severity",
        "get-mpthreat",
        "get-mpthreatdetection",
    ):
        assert forbidden not in source
