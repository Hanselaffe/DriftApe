"""Read-only Windows services collector for DriftApe v0.1."""

from __future__ import annotations

from driftape import platform_windows
from driftape.acquisition import powershell
from driftape.models import (
    CollectorStatus,
    DriftApeError,
    ErrorCode,
    ServiceInfo,
    ServicesCollectorResult,
    ServicesData,
    ServiceStartMode,
)

_SERVICES_SCOPE = "collector.services"
_SERVICES_COVERAGE = "services"
_ACQUISITION_TIMEOUT_SECONDS = 60
_MAX_ERROR_MESSAGE_CHARS = 1024
_MAX_NATIVE_CODE_CHARS = 128

_SERVICES_POWERSHELL_SCRIPT = r"""
$services = $null

try {
    $items = @(
        Get-CimInstance -ClassName Win32_Service `
            -Property Name,DisplayName,StartMode,PathName,StartName |
            ForEach-Object {
                [PSCustomObject]@{
                    Name = if ($null -eq $_.Name) { $null } else { [string]$_.Name }
                    DisplayName = if ($null -eq $_.DisplayName) {
                        $null
                    } else {
                        [string]$_.DisplayName
                    }
                    StartMode = if ($null -eq $_.StartMode) {
                        $null
                    } else {
                        [string]$_.StartMode
                    }
                    PathName = if ($null -eq $_.PathName) {
                        $null
                    } else {
                        [string]$_.PathName
                    }
                    StartName = if ($null -eq $_.StartName) {
                        $null
                    } else {
                        [string]$_.StartName
                    }
                }
            }
    )
    $services = [ordered]@{
        ok = $true
        items = $items
        error = $null
    }
}
catch {
    $services = [ordered]@{
        ok = $false
        items = $null
        error = [ordered]@{
            category = [string]$_.CategoryInfo.Category
            message = [string]$_.Exception.Message
            native_code = if ($null -eq $_.Exception) {
                $null
            } else {
                [int]$_.Exception.HResult
            }
            fully_qualified_error_id = [string]$_.FullyQualifiedErrorId
        }
    }
}

[ordered]@{
    services = $services
} | ConvertTo-Json -Compress -Depth 6
""".strip()


class _ServicesOutputError(ValueError):
    """Raised when the logical services section has malformed output."""


def _bounded_message(value: object, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    message = value.strip()
    if not message:
        return fallback
    if len(message) > _MAX_ERROR_MESSAGE_CHARS:
        return message[:_MAX_ERROR_MESSAGE_CHARS] + "…"
    return message


def _native_code(value: object) -> int | str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        code = value.strip()
        if code and len(code) <= _MAX_NATIVE_CODE_CHARS:
            return code
    return None


def _error(
    *,
    code: ErrorCode,
    operation: str,
    message: str,
    native_code: int | str | None = None,
    recoverable: bool,
) -> DriftApeError:
    return DriftApeError(
        code=code,
        scope=_SERVICES_SCOPE,
        operation=operation,
        message=message,
        native_code=native_code,
        recoverable=recoverable,
    )


def _failed_result(error: DriftApeError) -> ServicesCollectorResult:
    return ServicesCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=ServicesData(services=None),
        errors=(error,),
    )


def _normalize_name(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not value:
        raise _ServicesOutputError("Name must be a non-empty string.")
    if value != value.strip():
        raise _ServicesOutputError(
            "Name must not contain leading or trailing whitespace."
        )
    return value.casefold(), value


def _normalize_display_name(value: object) -> str:
    if not isinstance(value, str):
        raise _ServicesOutputError("DisplayName must be a string.")
    return value


def _normalize_start_mode(value: object) -> ServiceStartMode:
    if value is None:
        return ServiceStartMode.UNKNOWN
    if not isinstance(value, str):
        raise _ServicesOutputError("StartMode must be a string or null.")

    mapping = {
        "auto": ServiceStartMode.AUTO,
        "automatic": ServiceStartMode.AUTO,
        "manual": ServiceStartMode.MANUAL,
        "disabled": ServiceStartMode.DISABLED,
        "boot": ServiceStartMode.BOOT,
        "system": ServiceStartMode.SYSTEM,
    }
    return mapping.get(value.casefold(), ServiceStartMode.UNKNOWN)


def _normalize_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _ServicesOutputError(f"{field_name} must be a string or null.")
    normalized = value.strip()
    return normalized or None


def _normalize_service(value: object) -> ServiceInfo:
    if not isinstance(value, dict):
        raise _ServicesOutputError("Service item must be an object.")

    service_id, name = _normalize_name(value.get("Name"))
    display_name = _normalize_display_name(value.get("DisplayName"))
    start_mode = _normalize_start_mode(value.get("StartMode"))
    path_name = _normalize_optional_text(value.get("PathName"), "PathName")
    start_name = _normalize_optional_text(value.get("StartName"), "StartName")
    if start_name is not None:
        start_name = start_name.casefold()

    return ServiceInfo(
        id=service_id,
        name=name,
        display_name=display_name,
        start_mode=start_mode,
        path_name=path_name,
        start_name=start_name,
    )


def _normalize_services_section(section: object) -> tuple[ServiceInfo, ...]:
    if not isinstance(section, dict):
        raise _ServicesOutputError("Services section must be an object.")

    ok = section.get("ok")
    if not isinstance(ok, bool):
        raise _ServicesOutputError("Services section ok flag must be a boolean.")
    if not ok:
        raise _ServicesOutputError("Services section reports acquisition failure.")

    items = section.get("items")
    if not isinstance(items, list):
        raise _ServicesOutputError("Services section items must be an array.")

    normalized = tuple(_normalize_service(item) for item in items)
    ids = [item.id for item in normalized]
    if len(ids) != len(set(ids)):
        raise _ServicesOutputError(
            "Services section contains a duplicate normalized service id."
        )
    return tuple(sorted(normalized, key=lambda item: item.id))


def _structured_acquisition_error(section: object) -> DriftApeError:
    operation = "Get-CimInstance Win32_Service"
    if not isinstance(section, dict) or section.get("ok") is not False:
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            operation=operation,
            message="PowerShell services section status is malformed.",
            recoverable=True,
        )

    error_data = section.get("error")
    if not isinstance(error_data, dict):
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            operation=operation,
            message="PowerShell services section error is malformed.",
            recoverable=True,
        )

    category = error_data.get("category")
    code = (
        ErrorCode.ACCESS_DENIED
        if isinstance(category, str) and category.casefold() == "permissiondenied"
        else ErrorCode.COMMAND_FAILED
    )
    return _error(
        code=code,
        operation=operation,
        message=_bounded_message(
            error_data.get("message"),
            "Get-CimInstance Win32_Service failed during local collection.",
        ),
        native_code=_native_code(error_data.get("native_code")),
        recoverable=True,
    )


def _process_document(raw: object) -> ServicesCollectorResult:
    acquisition_operation = "PowerShell services acquisition"
    if not isinstance(raw, dict):
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation=acquisition_operation,
                message="PowerShell services acquisition result must be an object.",
                recoverable=True,
            )
        )

    if _SERVICES_COVERAGE not in raw:
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation=acquisition_operation,
                message="PowerShell output is missing the services section.",
                recoverable=True,
            )
        )

    section = raw[_SERVICES_COVERAGE]
    if isinstance(section, dict) and section.get("ok") is False:
        return _failed_result(_structured_acquisition_error(section))

    try:
        normalized = _normalize_services_section(section)
    except _ServicesOutputError as exc:
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation="Get-CimInstance Win32_Service",
                message=str(exc),
                recoverable=True,
            )
        )

    return ServicesCollectorResult(
        status=CollectorStatus.SUCCESS,
        coverage=frozenset({_SERVICES_COVERAGE}),
        data=ServicesData(services=normalized),
        errors=(),
    )


def collect_services() -> ServicesCollectorResult:
    """Collect normalized local Windows service configuration facts."""
    try:
        platform_windows.require_supported_platform()
    except platform_windows.UnsupportedPlatformError:
        return _failed_result(
            _error(
                code=ErrorCode.UNSUPPORTED_OS,
                operation="platform check",
                message="DriftApe services collection requires Windows x64.",
                recoverable=False,
            )
        )

    try:
        raw = powershell.run_powershell_json(
            _SERVICES_POWERSHELL_SCRIPT,
            timeout_seconds=_ACQUISITION_TIMEOUT_SECONDS,
        )
    except powershell.PowerShellUnavailableError:
        return _failed_result(
            _error(
                code=ErrorCode.COLLECTOR_UNAVAILABLE,
                operation="PowerShell services acquisition",
                message="Built-in Windows PowerShell is unavailable.",
                recoverable=True,
            )
        )
    except powershell.PowerShellTimeoutError:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_TIMEOUT,
                operation="PowerShell services acquisition",
                message="PowerShell services acquisition exceeded 60 seconds.",
                recoverable=True,
            )
        )
    except powershell.PowerShellCommandError as exc:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_FAILED,
                operation="PowerShell services acquisition",
                message="PowerShell services acquisition failed.",
                native_code=exc.return_code,
                recoverable=True,
            )
        )
    except powershell.PowerShellOutputError:
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation="PowerShell services acquisition",
                message="PowerShell services acquisition returned invalid JSON output.",
                recoverable=True,
            )
        )

    return _process_document(raw)
