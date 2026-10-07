"""WP5 Windows services collector tests."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from driftape.acquisition import powershell
from driftape.collectors import services
from driftape.models import (
    CollectorStatus,
    ErrorCode,
    ServiceInfo,
    ServicesCollectorResult,
    ServiceStartMode,
)


def _service(
    *,
    name: object = "Spooler",
    display_name: object = "Print Spooler",
    start_mode: object = "Auto",
    path_name: object = r"C:\Windows\System32\spoolsv.exe",
    start_name: object = "LocalSystem",
) -> dict[str, object]:
    return {
        "Name": name,
        "DisplayName": display_name,
        "StartMode": start_mode,
        "PathName": path_name,
        "StartName": start_name,
    }


def _success_section(items: list[object]) -> dict[str, object]:
    return {"ok": True, "items": items, "error": None}


def _failed_section(
    *,
    category: object = "NotSpecified",
    message: object = "synthetic failure",
    native_code: object = -1,
) -> dict[str, object]:
    return {
        "ok": False,
        "items": None,
        "error": {
            "category": category,
            "message": message,
            "native_code": native_code,
            "fully_qualified_error_id": "SyntheticFailure",
        },
    }


def _document(section: object | None = None) -> dict[str, object]:
    return {
        "services": _success_section([_service()]) if section is None else section
    }


@pytest.fixture(autouse=True)
def supported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        services.platform_windows,
        "require_supported_platform",
        lambda: None,
    )


def _collect(
    monkeypatch: pytest.MonkeyPatch,
    document: object,
) -> ServicesCollectorResult:
    monkeypatch.setattr(
        services.powershell,
        "run_powershell_json",
        lambda _script, *, timeout_seconds: document,
    )
    return services.collect_services()


def _assert_failed_unexpected(result: ServicesCollectorResult) -> None:
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert result.data.services is None
    assert result.errors[0].code is ErrorCode.UNEXPECTED_OUTPUT
    assert result.errors[0].scope == "collector.services"


def test_t_wp5_001_successful_acquisition_has_full_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.status is CollectorStatus.SUCCESS
    assert result.coverage == frozenset({"services"})
    assert result.errors == ()


def test_t_wp5_002_service_maps_exactly_to_service_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document())
    assert result.data.services == (
        ServiceInfo(
            id="spooler",
            name="Spooler",
            display_name="Print Spooler",
            start_mode=ServiceStartMode.AUTO,
            path_name=r"C:\Windows\System32\spoolsv.exe",
            start_name="localsystem",
        ),
    )


def test_t_wp5_003_stable_id_is_casefold_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(name="StraßeSvc")])),
    )
    assert result.data.services is not None
    assert result.data.services[0].id == "strassesvc"


def test_t_wp5_004_original_name_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(name="SpOoLeR")])),
    )
    assert result.data.services is not None
    assert result.data.services[0].name == "SpOoLeR"


def test_t_wp5_005_empty_display_name_is_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(display_name="")])),
    )
    assert result.data.services is not None
    assert result.data.services[0].display_name == ""


def test_t_wp5_006_none_path_name_remains_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(path_name=None)])),
    )
    assert result.data.services is not None
    assert result.data.services[0].path_name is None


def test_t_wp5_007_none_start_name_remains_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(start_name=None)])),
    )
    assert result.data.services is not None
    assert result.data.services[0].start_name is None


def test_t_wp5_008_zero_service_success_is_empty_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(monkeypatch, _document(_success_section([])))
    assert result.status is CollectorStatus.SUCCESS
    assert result.coverage == frozenset({"services"})
    assert result.data.services == ()


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("Auto", ServiceStartMode.AUTO),
        ("Automatic", ServiceStartMode.AUTO),
        ("Manual", ServiceStartMode.MANUAL),
        ("Disabled", ServiceStartMode.DISABLED),
        ("Boot", ServiceStartMode.BOOT),
        ("System", ServiceStartMode.SYSTEM),
        ("FutureMode", ServiceStartMode.UNKNOWN),
        (None, ServiceStartMode.UNKNOWN),
        ("aUtOmAtIc", ServiceStartMode.AUTO),
    ],
)
def test_t_wp5_009_to_016_start_mode_normalization(
    monkeypatch: pytest.MonkeyPatch,
    source: object,
    expected: ServiceStartMode,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(start_mode=source)])),
    )
    assert result.data.services is not None
    assert result.data.services[0].start_mode is expected


def test_t_wp5_017_invalid_start_mode_type_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(start_mode=1)])),
    )
    _assert_failed_unexpected(result)


def test_t_wp5_018_path_outer_whitespace_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(path_name="  abc.exe  ")])),
    )
    assert result.data.services is not None
    assert result.data.services[0].path_name == "abc.exe"


def test_t_wp5_019_internal_executable_quoting_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = r'  "C:\Program Files\App\svc.exe" --service  '
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(path_name=value)])),
    )
    assert result.data.services is not None
    assert result.data.services[0].path_name == value.strip()


def test_t_wp5_020_path_arguments_are_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = r"C:\App\svc.exe --service --mode test"
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(path_name=value)])),
    )
    assert result.data.services is not None
    assert result.data.services[0].path_name == value


def test_t_wp5_021_environment_variables_remain_unexpanded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = r"%SystemRoot%\System32\svchost.exe -k netsvcs"
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(path_name=value)])),
    )
    assert result.data.services is not None
    assert result.data.services[0].path_name == value


def test_t_wp5_022_whitespace_only_path_becomes_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(path_name=" \t ")])),
    )
    assert result.data.services is not None
    assert result.data.services[0].path_name is None


def test_t_wp5_023_invalid_path_type_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(path_name=True)])),
    )
    _assert_failed_unexpected(result)


def test_t_wp5_024_start_name_outer_whitespace_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(start_name="  LocalSystem  ")])),
    )
    assert result.data.services is not None
    assert result.data.services[0].start_name == "localsystem"


def test_t_wp5_025_start_name_is_casefolded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            _success_section([_service(start_name=r"NT AUTHORITY\LocalService")])
        ),
    )
    assert result.data.services is not None
    assert result.data.services[0].start_name == r"nt authority\localservice"


def test_t_wp5_026_whitespace_only_start_name_becomes_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(start_name="   ")])),
    )
    assert result.data.services is not None
    assert result.data.services[0].start_name is None


def test_t_wp5_027_invalid_start_name_type_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(start_name=[])])),
    )
    _assert_failed_unexpected(result)


def test_t_wp5_028_reverse_source_order_normalizes_identically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forward = [_service(name="Alpha"), _service(name="Zulu")]
    reverse = list(reversed(forward))
    first = _collect(monkeypatch, _document(_success_section(forward)))
    second = _collect(monkeypatch, _document(_success_section(reverse)))
    assert first.data.services == second.data.services


def test_t_wp5_029_equivalent_source_orders_produce_equal_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forward = _document(
        _success_section([_service(name="Beta"), _service(name="Alpha")])
    )
    reverse = _document(
        _success_section([_service(name="Alpha"), _service(name="Beta")])
    )
    assert _collect(monkeypatch, forward) == _collect(monkeypatch, reverse)


def test_t_wp5_030_sorting_uses_canonical_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            _success_section(
                [_service(name="zService"), _service(name="AService")]
            )
        ),
    )
    assert [item.id for item in result.data.services or ()] == [
        "aservice",
        "zservice",
    ]


def test_t_wp5_031_exact_duplicate_name_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_success_section([_service(), _service()])),
    )
    _assert_failed_unexpected(result)


def test_t_wp5_032_case_variant_duplicate_name_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            _success_section([_service(name="Spooler"), _service(name="SPOOLER")])
        ),
    )
    _assert_failed_unexpected(result)


@pytest.mark.parametrize(
    "document",
    [
        [],
        {},
        {"services": {"ok": True, "items": "not-an-array", "error": None}},
        _document(_success_section(["not-an-object"])),
        _document(_success_section([_service(name=None)])),
        _document(_success_section([_service(name="")])),
        _document(_success_section([_service(name=7)])),
        _document(_success_section([_service(name=" Spooler")])),
        _document(_success_section([_service(display_name=None)])),
    ],
)
def test_t_wp5_033_to_041_malformed_output_fails_complete_section(
    monkeypatch: pytest.MonkeyPatch,
    document: object,
) -> None:
    result = _collect(monkeypatch, document)
    _assert_failed_unexpected(result)


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
            powershell.PowerShellOutputError("broken output"),
            ErrorCode.UNEXPECTED_OUTPUT,
            None,
        ),
    ],
)
def test_t_wp5_042_to_045_transport_exception_mapping(
    monkeypatch: pytest.MonkeyPatch,
    exception: Exception,
    expected_code: ErrorCode,
    native_code: int | None,
) -> None:
    def fail(_script: str, *, timeout_seconds: float) -> object:
        raise exception

    monkeypatch.setattr(services.powershell, "run_powershell_json", fail)
    result = services.collect_services()
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert result.data.services is None
    assert result.errors[0].code is expected_code
    assert result.errors[0].scope == "collector.services"
    assert result.errors[0].native_code == native_code
    assert result.errors[0].recoverable is True


def test_t_wp5_046_permission_denied_uses_structured_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(
            _failed_section(
                category="PermissionDenied",
                message="localized text is irrelevant",
                native_code=-2147024891,
            )
        ),
    )
    assert result.errors[0].code is ErrorCode.ACCESS_DENIED
    assert result.errors[0].native_code == -2147024891


def test_t_wp5_047_other_structured_failure_is_command_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _collect(
        monkeypatch,
        _document(_failed_section(category="ObjectNotFound")),
    )
    assert result.errors[0].code is ErrorCode.COMMAND_FAILED


def test_t_wp5_048_unsupported_platform_does_not_invoke_powershell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unsupported() -> None:
        raise services.platform_windows.UnsupportedPlatformError("unsupported")

    called = False

    def forbidden(_script: str, *, timeout_seconds: float) -> object:
        nonlocal called
        called = True
        return _document()

    monkeypatch.setattr(
        services.platform_windows,
        "require_supported_platform",
        unsupported,
    )
    monkeypatch.setattr(services.powershell, "run_powershell_json", forbidden)
    result = services.collect_services()
    assert called is False
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert result.data.services is None
    assert result.errors[0].code is ErrorCode.UNSUPPORTED_OS
    assert result.errors[0].scope == "collector.services"
    assert result.errors[0].operation == "platform check"
    assert result.errors[0].recoverable is False


def test_t_wp5_049_uses_only_shared_powershell_transport() -> None:
    source = inspect.getsource(services)
    assert "run_powershell_json" in source
    assert "subprocess" not in source


def test_t_wp5_050_timeout_is_exactly_sixty_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def capture(script: str, *, timeout_seconds: float) -> object:
        observed["script"] = script
        observed["timeout_seconds"] = timeout_seconds
        return _document()

    monkeypatch.setattr(services.powershell, "run_powershell_json", capture)
    result = services.collect_services()
    assert result.status is CollectorStatus.SUCCESS
    assert observed["timeout_seconds"] == 60


def test_t_wp5_051_script_uses_win32_service_cim_class() -> None:
    script = services._SERVICES_POWERSHELL_SCRIPT
    assert "Get-CimInstance -ClassName Win32_Service" in script


def test_t_wp5_052_script_projects_only_authorized_service_properties() -> None:
    script = services._SERVICES_POWERSHELL_SCRIPT
    property_argument = (
        "-Property Name,DisplayName,StartMode,PathName,StartName"
    )
    assert property_argument in script
    for forbidden in (
        "ProcessId",
        "ServiceSpecificExitCode",
        "CheckPoint",
        "WaitHint",
        "AcceptPause",
        "AcceptStop",
        "DesktopInteract",
        "$_.State",
        "$_.Status",
        "$_.Started",
        "$_.ExitCode",
    ):
        assert forbidden not in script


def test_t_wp5_053_script_uses_structured_json() -> None:
    script = services._SERVICES_POWERSHELL_SCRIPT
    assert "ConvertTo-Json -Compress" in script
    assert "-Depth 6" in script


def test_t_wp5_054_script_contains_no_service_modification() -> None:
    script = services._SERVICES_POWERSHELL_SCRIPT.casefold()
    for forbidden in (
        "new-service",
        "set-service",
        "start-service",
        "stop-service",
        "restart-service",
        "remove-service",
        "sc.exe create",
        "sc.exe config",
    ):
        assert forbidden not in script


def test_t_wp5_055_script_contains_no_remote_cim_session() -> None:
    script = services._SERVICES_POWERSHELL_SCRIPT.casefold()
    assert "new-cimsession" not in script
    assert "-cimsession" not in script


def test_services_success_and_failure_model_invariants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    success = _collect(monkeypatch, _document())
    failure = _collect(monkeypatch, _document(_success_section([_service(name=1)])))
    assert success.status is CollectorStatus.SUCCESS
    assert success.coverage == frozenset({"services"})
    assert success.data.services is not None
    assert failure.status is CollectorStatus.FAILED
    assert failure.coverage == frozenset()
    assert failure.data.services is None


def test_services_invalid_ok_and_error_shapes_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for section in (
        {"ok": "true", "items": [], "error": None},
        {"ok": False, "items": None, "error": "broken"},
    ):
        _assert_failed_unexpected(_collect(monkeypatch, _document(section)))


def test_services_section_must_be_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_failed_unexpected(_collect(monkeypatch, {"services": []}))


def test_services_section_missing_ok_flag_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_failed_unexpected(
        _collect(monkeypatch, {"services": {"items": [], "error": None}})
    )
