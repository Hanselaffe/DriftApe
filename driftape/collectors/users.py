"""Read-only local users and Administrators membership collector for DriftApe."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeVar

from driftape import platform_windows
from driftape.acquisition import powershell
from driftape.models import (
    AdministratorMember,
    CollectorStatus,
    DriftApeError,
    ErrorCode,
    LocalUser,
    PrincipalSource,
    UsersCollectorResult,
    UsersData,
)

_USERS_SCOPE = "collector.users"
_LOCAL_USERS_SCOPE = "collector.users.local_users"
_ADMINISTRATORS_SCOPE = "collector.users.administrators"
_LOCAL_USERS_COVERAGE = "local_users"
_ADMINISTRATORS_COVERAGE = "administrators"
_ACQUISITION_TIMEOUT_SECONDS = 60
_MAX_ERROR_MESSAGE_CHARS = 1024
_MAX_NATIVE_CODE_CHARS = 128

_USERS_POWERSHELL_SCRIPT = r"""
$localUsers = $null
$administrators = $null

try {
    $items = @(
        Get-LocalUser | ForEach-Object {
            [PSCustomObject]@{
                SID = if ($null -eq $_.SID) { $null } else { [string]$_.SID.Value }
                Name = $_.Name
                Enabled = $_.Enabled
                PrincipalSource = if ($null -eq $_.PrincipalSource) {
                    $null
                } else {
                    [string]$_.PrincipalSource
                }
            }
        }
    )
    $localUsers = [ordered]@{
        ok = $true
        items = $items
        error = $null
    }
}
catch {
    $localUsers = [ordered]@{
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

try {
    $items = @(
        Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
            [PSCustomObject]@{
                SID = if ($null -eq $_.SID) { $null } else { [string]$_.SID.Value }
                Name = $_.Name
                ObjectClass = if ($null -eq $_.ObjectClass) {
                    $null
                } else {
                    [string]$_.ObjectClass
                }
                PrincipalSource = if ($null -eq $_.PrincipalSource) {
                    $null
                } else {
                    [string]$_.PrincipalSource
                }
            }
        }
    )
    $administrators = [ordered]@{
        ok = $true
        items = $items
        error = $null
    }
}
catch {
    $administrators = [ordered]@{
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
    local_users = $localUsers
    administrators = $administrators
} | ConvertTo-Json -Compress -Depth 6
""".strip()


class _Identified(Protocol):
    id: str


_T = TypeVar("_T", bound=_Identified)


class _SectionOutputError(ValueError):
    """Raised when a logical collector subsection has malformed output."""


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


def _failed_result(error: DriftApeError) -> UsersCollectorResult:
    return UsersCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=UsersData(local_users=None, administrators=None),
        errors=(error,),
    )


def _require_non_empty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _SectionOutputError(f"{field_name} must be a non-empty string.")
    return value


def _normalize_principal_source(value: object) -> PrincipalSource:
    if not isinstance(value, str):
        return PrincipalSource.UNKNOWN
    mapping = {
        "local": PrincipalSource.LOCAL,
        "activedirectory": PrincipalSource.ACTIVE_DIRECTORY,
        "microsoftaccount": PrincipalSource.MICROSOFT_ACCOUNT,
        "azuread": PrincipalSource.MICROSOFT_ENTRA,
        "microsoftentra": PrincipalSource.MICROSOFT_ENTRA,
    }
    return mapping.get(value.casefold(), PrincipalSource.UNKNOWN)


def _normalize_local_user(value: object) -> LocalUser:
    if not isinstance(value, dict):
        raise _SectionOutputError("Local user item must be an object.")

    sid = _require_non_empty_string(value.get("SID"), "SID")
    name = _require_non_empty_string(value.get("Name"), "Name")
    enabled = value.get("Enabled")
    if not isinstance(enabled, bool):
        raise _SectionOutputError("Enabled must be a boolean.")

    return LocalUser(
        id=sid,
        name=name,
        enabled=enabled,
        principal_source=_normalize_principal_source(value.get("PrincipalSource")),
    )


def _normalize_administrator(value: object) -> AdministratorMember:
    if not isinstance(value, dict):
        raise _SectionOutputError("Administrator item must be an object.")

    sid = _require_non_empty_string(value.get("SID"), "SID")
    name = _require_non_empty_string(value.get("Name"), "Name")
    object_class = _require_non_empty_string(value.get("ObjectClass"), "ObjectClass")

    return AdministratorMember(
        id=sid,
        name=name,
        object_class=object_class,
        principal_source=_normalize_principal_source(value.get("PrincipalSource")),
    )


def _normalize_items(
    section: object,
    *,
    item_normalizer: Callable[[object], _T],
) -> tuple[_T, ...]:
    if not isinstance(section, dict):
        raise _SectionOutputError("Collector subsection must be an object.")

    ok = section.get("ok")
    if not isinstance(ok, bool):
        raise _SectionOutputError("Collector subsection ok flag must be a boolean.")
    if not ok:
        raise _SectionOutputError("Collector subsection reports acquisition failure.")

    items = section.get("items")
    if not isinstance(items, list):
        raise _SectionOutputError("Collector subsection items must be an array.")

    normalized = tuple(item_normalizer(item) for item in items)
    ids = [item.id for item in normalized]
    if len(ids) != len(set(ids)):
        raise _SectionOutputError("Collector subsection contains a duplicate SID.")

    return tuple(sorted(normalized, key=lambda item: item.id))


def _subsection_error(
    section: object,
    *,
    scope: str,
    operation: str,
) -> DriftApeError:
    if not isinstance(section, dict):
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            scope=scope,
            operation=operation,
            message="PowerShell subsection output is malformed.",
            recoverable=True,
        )

    ok = section.get("ok")
    if ok is not False:
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            scope=scope,
            operation=operation,
            message="PowerShell subsection status is malformed.",
            recoverable=True,
        )

    error_data = section.get("error")
    if not isinstance(error_data, dict):
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            scope=scope,
            operation=operation,
            message="PowerShell subsection error is malformed.",
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
        message=_bounded_message(
            error_data.get("message"),
            f"{operation} failed during local collection.",
        ),
        native_code=_native_code(error_data.get("native_code")),
        recoverable=True,
    )


def _process_section(
    root: dict[str, object],
    *,
    key: str,
    scope: str,
    operation: str,
    item_normalizer: Callable[[object], _T],
) -> tuple[tuple[_T, ...] | None, DriftApeError | None]:
    if key not in root:
        return None, _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            scope=scope,
            operation=operation,
            message=f"PowerShell output is missing the {key} subsection.",
            recoverable=True,
        )

    section = root[key]
    if isinstance(section, dict) and section.get("ok") is False:
        return None, _subsection_error(section, scope=scope, operation=operation)

    try:
        return _normalize_items(section, item_normalizer=item_normalizer), None
    except _SectionOutputError as exc:
        return None, _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            scope=scope,
            operation=operation,
            message=str(exc),
            recoverable=True,
        )


def collect_users() -> UsersCollectorResult:
    """Collect normalized local users and local Administrators membership facts."""
    try:
        platform_windows.require_supported_platform()
    except platform_windows.UnsupportedPlatformError:
        return _failed_result(
            _error(
                code=ErrorCode.UNSUPPORTED_OS,
                scope=_USERS_SCOPE,
                operation="platform check",
                message="DriftApe users collection requires Windows x64.",
                recoverable=False,
            )
        )

    try:
        raw = powershell.run_powershell_json(
            _USERS_POWERSHELL_SCRIPT,
            timeout_seconds=_ACQUISITION_TIMEOUT_SECONDS,
        )
    except powershell.PowerShellUnavailableError:
        return _failed_result(
            _error(
                code=ErrorCode.COLLECTOR_UNAVAILABLE,
                scope=_USERS_SCOPE,
                operation="PowerShell users acquisition",
                message="Built-in Windows PowerShell is unavailable.",
                recoverable=True,
            )
        )
    except powershell.PowerShellTimeoutError:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_TIMEOUT,
                scope=_USERS_SCOPE,
                operation="PowerShell users acquisition",
                message="PowerShell users acquisition exceeded 60 seconds.",
                recoverable=True,
            )
        )
    except powershell.PowerShellCommandError as exc:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_FAILED,
                scope=_USERS_SCOPE,
                operation="PowerShell users acquisition",
                message="PowerShell users acquisition failed.",
                native_code=exc.return_code,
                recoverable=True,
            )
        )
    except powershell.PowerShellOutputError:
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                scope=_USERS_SCOPE,
                operation="PowerShell users acquisition",
                message="PowerShell users acquisition returned invalid JSON output.",
                recoverable=True,
            )
        )

    if not isinstance(raw, dict):
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                scope=_USERS_SCOPE,
                operation="PowerShell users acquisition",
                message="PowerShell users acquisition result must be an object.",
                recoverable=True,
            )
        )

    local_users, local_error = _process_section(
        raw,
        key=_LOCAL_USERS_COVERAGE,
        scope=_LOCAL_USERS_SCOPE,
        operation="Get-LocalUser",
        item_normalizer=_normalize_local_user,
    )
    administrators, administrators_error = _process_section(
        raw,
        key=_ADMINISTRATORS_COVERAGE,
        scope=_ADMINISTRATORS_SCOPE,
        operation="Get-LocalGroupMember",
        item_normalizer=_normalize_administrator,
    )

    coverage: set[str] = set()
    if local_users is not None:
        coverage.add(_LOCAL_USERS_COVERAGE)
    if administrators is not None:
        coverage.add(_ADMINISTRATORS_COVERAGE)

    if len(coverage) == 2:
        status = CollectorStatus.SUCCESS
    elif coverage:
        status = CollectorStatus.PARTIAL
    else:
        status = CollectorStatus.FAILED

    errors = tuple(
        error
        for error in (local_error, administrators_error)
        if error is not None
    )

    return UsersCollectorResult(
        status=status,
        coverage=frozenset(coverage),
        data=UsersData(
            local_users=local_users,
            administrators=administrators,
        ),
        errors=errors,
    )
