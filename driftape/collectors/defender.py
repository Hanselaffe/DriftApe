"""Read-only Microsoft Defender configuration/state collector for DriftApe."""

from __future__ import annotations

import ipaddress

from driftape import platform_windows
from driftape.acquisition import powershell
from driftape.models import (
    CollectorStatus,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderData,
    DefenderExclusion,
    DefenderExclusionKind,
    DefenderRuntime,
    DriftApeError,
    ErrorCode,
)

_DEFENDER_SCOPE = "collector.defender"
_EXCLUSIONS_SCOPE = "collector.defender.exclusions"
_CONFIGURATION_SCOPE = "collector.defender.configuration"
_PREFERENCE_SCOPE = "collector.defender.preference"
_RUNTIME_SCOPE = "collector.defender.runtime"
_EXCLUSIONS_COVERAGE = "exclusions"
_CONFIGURATION_COVERAGE = "configuration"
_RUNTIME_COVERAGE = "runtime"
_FULL_COVERAGE = frozenset(
    {_EXCLUSIONS_COVERAGE, _CONFIGURATION_COVERAGE, _RUNTIME_COVERAGE}
)
_ACQUISITION_TIMEOUT_SECONDS = 60
_MAX_ERROR_MESSAGE_CHARS = 1024
_MAX_NATIVE_CODE_CHARS = 128
_DEFENDER_ID = "microsoft_defender"

_DEFENDER_POWERSHELL_SCRIPT = r"""
$preference = $null
$status = $null

try {
    $pref = Get-MpPreference
    $preference = [ordered]@{
        ok = $true
        data = [ordered]@{
            ExclusionPath = @(
                $pref.ExclusionPath | ForEach-Object {
                    if ($null -eq $_) { $null } else { [string]$_ }
                }
            )
            ExclusionProcess = @(
                $pref.ExclusionProcess | ForEach-Object {
                    if ($null -eq $_) { $null } else { [string]$_ }
                }
            )
            ExclusionExtension = @(
                $pref.ExclusionExtension | ForEach-Object {
                    if ($null -eq $_) { $null } else { [string]$_ }
                }
            )
            ExclusionIpAddress = @(
                $pref.ExclusionIpAddress | ForEach-Object {
                    if ($null -eq $_) { $null } else { [string]$_ }
                }
            )
            DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
        }
        error = $null
    }
}
catch {
    $preference = [ordered]@{
        ok = $false
        data = $null
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

try {
    $computerStatus = Get-MpComputerStatus
    $status = [ordered]@{
        ok = $true
        data = [ordered]@{
            RealTimeProtectionEnabled = $computerStatus.RealTimeProtectionEnabled
        }
        error = $null
    }
}
catch {
    $status = [ordered]@{
        ok = $false
        data = $null
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
    preference = $preference
    status = $status
} | ConvertTo-Json -Compress -Depth 6
""".strip()


class _DefenderOutputError(ValueError):
    """Raised when a Defender logical subsection is malformed."""


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
    scope: str,
    operation: str,
    message: str,
    native_code: int | str | None = None,
    recoverable: bool,
) -> DriftApeError:
    return DriftApeError(
        code=code,
        scope=scope,
        operation=operation,
        message=message,
        native_code=native_code,
        recoverable=recoverable,
    )


def _failed_result(error: DriftApeError) -> DefenderCollectorResult:
    return DefenderCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=DefenderData(exclusions=None, configuration=None, runtime=None),
        errors=(error,),
    )


def _structured_command_error(
    section: dict[object, object],
    *,
    operation: str,
    scope: str,
    fallback: str,
) -> DriftApeError:
    error_data = section.get("error")
    if not isinstance(error_data, dict):
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            scope=scope,
            operation=operation,
            message=f"{operation} structured error is malformed.",
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
        scope=scope,
        operation=operation,
        message=_bounded_message(error_data.get("message"), fallback),
        native_code=_native_code(error_data.get("native_code")),
        recoverable=True,
    )


def _normalize_path_like(
    value: object,
    kind: DefenderExclusionKind,
) -> DefenderExclusion:
    if not isinstance(value, str):
        raise _DefenderOutputError(f"{kind.value} exclusion must be a string.")
    normalized = value.strip().replace("/", "\\")
    if not normalized:
        raise _DefenderOutputError(f"{kind.value} exclusion must not be empty.")
    identity = normalized.casefold()
    return DefenderExclusion(
        id=f"{kind.value}:{identity}",
        kind=kind,
        value=normalized,
    )


def _normalize_extension(value: object) -> DefenderExclusion:
    if not isinstance(value, str):
        raise _DefenderOutputError("extension exclusion must be a string.")
    normalized = value.strip()
    if normalized.startswith("."):
        normalized = normalized[1:]
    if not normalized:
        raise _DefenderOutputError("extension exclusion must not be empty.")
    identity = normalized.casefold()
    return DefenderExclusion(
        id=f"{DefenderExclusionKind.EXTENSION.value}:{identity}",
        kind=DefenderExclusionKind.EXTENSION,
        value=normalized,
    )


def _normalize_ip_address(value: object) -> DefenderExclusion:
    if not isinstance(value, str):
        raise _DefenderOutputError("ip_address exclusion must be a string.")
    normalized = value.strip()
    if not normalized:
        raise _DefenderOutputError("ip_address exclusion must not be empty.")
    try:
        normalized = str(ipaddress.ip_address(normalized))
    except ValueError:
        pass
    identity = normalized.casefold()
    return DefenderExclusion(
        id=f"{DefenderExclusionKind.IP_ADDRESS.value}:{identity}",
        kind=DefenderExclusionKind.IP_ADDRESS,
        value=normalized,
    )


def _normalize_exclusions(data: dict[object, object]) -> tuple[DefenderExclusion, ...]:
    fields = (
        ("ExclusionPath", DefenderExclusionKind.PATH),
        ("ExclusionProcess", DefenderExclusionKind.PROCESS),
        ("ExclusionExtension", DefenderExclusionKind.EXTENSION),
        ("ExclusionIpAddress", DefenderExclusionKind.IP_ADDRESS),
    )
    normalized: list[DefenderExclusion] = []

    for field_name, kind in fields:
        source = data.get(field_name)
        if not isinstance(source, list):
            raise _DefenderOutputError(f"{field_name} must be an array.")
        for value in source:
            if kind in (DefenderExclusionKind.PATH, DefenderExclusionKind.PROCESS):
                exclusion = _normalize_path_like(value, kind)
            elif kind is DefenderExclusionKind.EXTENSION:
                exclusion = _normalize_extension(value)
            else:
                exclusion = _normalize_ip_address(value)
            normalized.append(exclusion)

    ids = [item.id for item in normalized]
    if len(ids) != len(set(ids)):
        raise _DefenderOutputError(
            "Defender exclusions contain a duplicate canonical exclusion id."
        )
    return tuple(sorted(normalized, key=lambda item: item.id))


def _normalize_configuration(data: dict[object, object]) -> DefenderConfiguration:
    value = data.get("DisableRealtimeMonitoring")
    if not isinstance(value, bool):
        raise _DefenderOutputError("DisableRealtimeMonitoring must be a boolean.")
    return DefenderConfiguration(
        id=_DEFENDER_ID,
        disable_realtime_monitoring=value,
    )


def _normalize_runtime(data: dict[object, object]) -> DefenderRuntime:
    value = data.get("RealTimeProtectionEnabled")
    if not isinstance(value, bool):
        raise _DefenderOutputError("RealTimeProtectionEnabled must be a boolean.")
    return DefenderRuntime(
        id=_DEFENDER_ID,
        real_time_protection_enabled=value,
    )


def _process_preference(
    section: object,
) -> tuple[
    tuple[DefenderExclusion, ...] | None,
    DefenderConfiguration | None,
    frozenset[str],
    tuple[DriftApeError, ...],
]:
    if not isinstance(section, dict):
        return (
            None,
            None,
            frozenset(),
            (
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    scope=_PREFERENCE_SCOPE,
                    operation="Get-MpPreference",
                    message="PowerShell preference section must be an object.",
                    recoverable=True,
                ),
            ),
        )

    ok = section.get("ok")
    if not isinstance(ok, bool):
        return (
            None,
            None,
            frozenset(),
            (
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    scope=_PREFERENCE_SCOPE,
                    operation="Get-MpPreference",
                    message="PowerShell preference status must be a boolean.",
                    recoverable=True,
                ),
            ),
        )
    if not ok:
        return (
            None,
            None,
            frozenset(),
            (
                _structured_command_error(
                    section,
                    operation="Get-MpPreference",
                    scope=_PREFERENCE_SCOPE,
                    fallback="Get-MpPreference failed during local collection.",
                ),
            ),
        )

    data = section.get("data")
    if not isinstance(data, dict):
        return (
            None,
            None,
            frozenset(),
            (
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    scope=_PREFERENCE_SCOPE,
                    operation="Get-MpPreference",
                    message="PowerShell preference data must be an object.",
                    recoverable=True,
                ),
            ),
        )

    coverage: set[str] = set()
    errors: list[DriftApeError] = []
    exclusions: tuple[DefenderExclusion, ...] | None = None
    configuration: DefenderConfiguration | None = None

    try:
        exclusions = _normalize_exclusions(data)
        coverage.add(_EXCLUSIONS_COVERAGE)
    except _DefenderOutputError as exc:
        errors.append(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                scope=_EXCLUSIONS_SCOPE,
                operation="Defender exclusions normalization",
                message=str(exc),
                recoverable=True,
            )
        )

    try:
        configuration = _normalize_configuration(data)
        coverage.add(_CONFIGURATION_COVERAGE)
    except _DefenderOutputError as exc:
        errors.append(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                scope=_CONFIGURATION_SCOPE,
                operation="Defender configuration normalization",
                message=str(exc),
                recoverable=True,
            )
        )

    return exclusions, configuration, frozenset(coverage), tuple(errors)


def _process_runtime(
    section: object,
) -> tuple[DefenderRuntime | None, frozenset[str], tuple[DriftApeError, ...]]:
    if not isinstance(section, dict):
        return (
            None,
            frozenset(),
            (
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    scope=_RUNTIME_SCOPE,
                    operation="Get-MpComputerStatus",
                    message="PowerShell runtime section must be an object.",
                    recoverable=True,
                ),
            ),
        )

    ok = section.get("ok")
    if not isinstance(ok, bool):
        return (
            None,
            frozenset(),
            (
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    scope=_RUNTIME_SCOPE,
                    operation="Get-MpComputerStatus",
                    message="PowerShell runtime status must be a boolean.",
                    recoverable=True,
                ),
            ),
        )
    if not ok:
        return (
            None,
            frozenset(),
            (
                _structured_command_error(
                    section,
                    operation="Get-MpComputerStatus",
                    scope=_RUNTIME_SCOPE,
                    fallback="Get-MpComputerStatus failed during local collection.",
                ),
            ),
        )

    data = section.get("data")
    if not isinstance(data, dict):
        return (
            None,
            frozenset(),
            (
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    scope=_RUNTIME_SCOPE,
                    operation="Get-MpComputerStatus",
                    message="PowerShell runtime data must be an object.",
                    recoverable=True,
                ),
            ),
        )

    try:
        runtime = _normalize_runtime(data)
    except _DefenderOutputError as exc:
        return (
            None,
            frozenset(),
            (
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    scope=_RUNTIME_SCOPE,
                    operation="Defender runtime normalization",
                    message=str(exc),
                    recoverable=True,
                ),
            ),
        )
    return runtime, frozenset({_RUNTIME_COVERAGE}), ()


def _process_document(raw: object) -> DefenderCollectorResult:
    if not isinstance(raw, dict):
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                scope=_DEFENDER_SCOPE,
                operation="PowerShell Defender acquisition",
                message="PowerShell Defender acquisition result must be an object.",
                recoverable=True,
            )
        )

    exclusions, configuration, preference_coverage, preference_errors = (
        _process_preference(raw.get("preference"))
    )
    runtime, runtime_coverage, runtime_errors = _process_runtime(raw.get("status"))
    coverage = preference_coverage | runtime_coverage
    errors = preference_errors + runtime_errors

    if coverage == _FULL_COVERAGE:
        status = CollectorStatus.SUCCESS
    elif coverage:
        status = CollectorStatus.PARTIAL
    else:
        status = CollectorStatus.FAILED

    return DefenderCollectorResult(
        status=status,
        coverage=coverage,
        data=DefenderData(
            exclusions=exclusions if _EXCLUSIONS_COVERAGE in coverage else None,
            configuration=(
                configuration if _CONFIGURATION_COVERAGE in coverage else None
            ),
            runtime=runtime if _RUNTIME_COVERAGE in coverage else None,
        ),
        errors=errors,
    )


def collect_defender() -> DefenderCollectorResult:
    """Collect normalized local Microsoft Defender configuration/state facts."""
    try:
        platform_windows.require_supported_platform()
    except platform_windows.UnsupportedPlatformError:
        return _failed_result(
            _error(
                code=ErrorCode.UNSUPPORTED_OS,
                scope=_DEFENDER_SCOPE,
                operation="platform check",
                message="DriftApe Defender collection requires Windows x64.",
                recoverable=False,
            )
        )

    try:
        raw = powershell.run_powershell_json(
            _DEFENDER_POWERSHELL_SCRIPT,
            timeout_seconds=_ACQUISITION_TIMEOUT_SECONDS,
        )
    except powershell.PowerShellUnavailableError:
        return _failed_result(
            _error(
                code=ErrorCode.COLLECTOR_UNAVAILABLE,
                scope=_DEFENDER_SCOPE,
                operation="PowerShell Defender acquisition",
                message="Built-in Windows PowerShell is unavailable.",
                recoverable=True,
            )
        )
    except powershell.PowerShellTimeoutError:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_TIMEOUT,
                scope=_DEFENDER_SCOPE,
                operation="PowerShell Defender acquisition",
                message="PowerShell Defender acquisition exceeded 60 seconds.",
                recoverable=True,
            )
        )
    except powershell.PowerShellCommandError as exc:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_FAILED,
                scope=_DEFENDER_SCOPE,
                operation="PowerShell Defender acquisition",
                message="PowerShell Defender acquisition failed.",
                native_code=exc.return_code,
                recoverable=True,
            )
        )
    except powershell.PowerShellOutputError:
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                scope=_DEFENDER_SCOPE,
                operation="PowerShell Defender acquisition",
                message="PowerShell Defender acquisition returned invalid JSON output.",
                recoverable=True,
            )
        )

    return _process_document(raw)
