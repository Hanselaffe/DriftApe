"""Read-only Windows Scheduled Tasks collector for DriftApe v0.1."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from driftape import platform_windows
from driftape.acquisition import powershell
from driftape.models import (
    CollectorStatus,
    DriftApeError,
    ErrorCode,
    ScheduledTaskInfo,
    TaskAction,
    TaskPrincipal,
    TasksCollectorResult,
    TasksData,
    TaskTrigger,
)

_TASKS_SCOPE = "collector.tasks"
_TASK_SCOPE = "collector.tasks.task"
_TASKS_COVERAGE = "tasks"
_ACQUISITION_TIMEOUT_SECONDS = 120
_MAX_ERROR_MESSAGE_CHARS = 1024
_MAX_NATIVE_CODE_CHARS = 128
_MAX_TASK_CONTEXT_CHARS = 256
_SEPARATOR_RUN = re.compile(r"\\+")

_TASKS_POWERSHELL_SCRIPT = r"""
$enumeration = $null

try {
    $items = @(
        Get-ScheduledTask | ForEach-Object {
            $taskName = if ($null -eq $_.TaskName) {
                $null
            } else {
                [string]$_.TaskName
            }
            $taskPath = if ($null -eq $_.TaskPath) {
                $null
            } else {
                [string]$_.TaskPath
            }

            try {
                $xml = Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath
                [PSCustomObject][ordered]@{
                    TaskName = $taskName
                    TaskPath = $taskPath
                    export_ok = $true
                    Xml = if ($null -eq $xml) { $null } else { [string]$xml }
                    error = $null
                }
            }
            catch {
                [PSCustomObject][ordered]@{
                    TaskName = $taskName
                    TaskPath = $taskPath
                    export_ok = $false
                    Xml = $null
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
        }
    )

    $enumeration = [ordered]@{
        ok = $true
        items = $items
        error = $null
    }
}
catch {
    $enumeration = [ordered]@{
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
    enumeration = $enumeration
} | ConvertTo-Json -Compress -Depth 10
""".strip()


class _TaskOutputError(ValueError):
    """Raised when one scheduled-task observation cannot be normalized."""


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
    recoverable: bool,
    native_code: int | str | None = None,
    scope: str = _TASKS_SCOPE,
) -> DriftApeError:
    return DriftApeError(
        code=code,
        scope=scope,
        operation=operation,
        message=_bounded_message(message, "Scheduled Tasks collection failed."),
        native_code=native_code,
        recoverable=recoverable,
    )


def _failed_result(error: DriftApeError) -> TasksCollectorResult:
    return TasksCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=TasksData(tasks=None),
        errors=(error,),
    )


def _local_name(tag: object) -> str:
    if not isinstance(tag, str) or not tag:
        raise _TaskOutputError("XML element tag must be a non-empty string.")
    if tag.startswith("{"):
        closing = tag.find("}")
        if closing < 0 or closing == len(tag) - 1:
            raise _TaskOutputError("XML element has an invalid expanded name.")
        return tag[closing + 1 :]
    if ":" in tag:
        local = tag.rsplit(":", 1)[1]
        if not local:
            raise _TaskOutputError("XML element has an invalid qualified name.")
        return local
    return tag


def _direct_child(parent: ET.Element, name: str) -> ET.Element | None:
    for child in parent:
        if _local_name(child.tag) == name:
            return child
    return None


def _direct_child_text(parent: ET.Element, name: str) -> str | None:
    child = _direct_child(parent, name)
    if child is None:
        return None
    return child.text


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized.casefold() if normalized else None


def _normalize_task_path(value: object) -> str:
    if not isinstance(value, str):
        raise _TaskOutputError("TaskPath must be a string.")
    normalized = value.replace("/", "\\")
    normalized = _SEPARATOR_RUN.sub(r"\\", normalized)
    if normalized in ("", "\\"):
        return "\\"
    normalized = normalized.strip("\\")
    if not normalized:
        return "\\"
    return f"\\{normalized}\\"


def _normalize_task_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise _TaskOutputError("TaskName must be a non-empty string.")
    if value != value.strip():
        raise _TaskOutputError(
            "TaskName must not contain leading or trailing whitespace."
        )
    return value


def _normalize_identity(item: object) -> tuple[str, str, str]:
    if not isinstance(item, dict):
        raise _TaskOutputError("Scheduled-task item must be an object.")
    task_path = _normalize_task_path(item.get("TaskPath"))
    task_name = _normalize_task_name(item.get("TaskName"))
    return (task_path + task_name).casefold(), task_path, task_name


def _task_context(task_path: str | None, task_name: str | None) -> str:
    if task_path is None and task_name is None:
        return "scheduled task"
    raw = f"{task_path or ''}{task_name or ''}"
    normalized = raw.replace("\r", " ").replace("\n", " ")
    if len(normalized) > _MAX_TASK_CONTEXT_CHARS:
        normalized = normalized[:_MAX_TASK_CONTEXT_CHARS] + "…"
    return f"scheduled task {normalized!r}"


def _canonicalize_subtree(element: ET.Element) -> str:
    try:
        serialized = ET.tostring(element, encoding="unicode")
        canonical = ET.canonicalize(
            serialized,
            with_comments=False,
            strip_text=True,
            rewrite_prefixes=True,
        )
    except (ET.ParseError, ValueError, TypeError) as exc:
        raise _TaskOutputError("Task XML canonicalization failed.") from exc
    if not isinstance(canonical, str) or not canonical:
        raise _TaskOutputError("Task XML canonicalization produced empty output.")
    return canonical


def _normalize_principals(root: ET.Element) -> tuple[TaskPrincipal, ...]:
    container = _direct_child(root, "Principals")
    if container is None:
        return ()

    principals: list[TaskPrincipal] = []
    for element in container:
        if _local_name(element.tag) != "Principal":
            continue
        raw_id = element.attrib.get("id")
        if not isinstance(raw_id, str):
            raise _TaskOutputError("Principal id attribute is required.")
        principal_id = raw_id.strip().casefold()
        if not principal_id:
            raise _TaskOutputError("Principal id attribute must be non-empty.")
        principals.append(
            TaskPrincipal(
                id=principal_id,
                user_id=_normalize_optional_text(
                    _direct_child_text(element, "UserId")
                ),
                group_id=_normalize_optional_text(
                    _direct_child_text(element, "GroupId")
                ),
                logon_type=_normalize_optional_text(
                    _direct_child_text(element, "LogonType")
                ),
                run_level=_normalize_optional_text(
                    _direct_child_text(element, "RunLevel")
                ),
            )
        )

    principals.sort(key=lambda principal: principal.id)
    ids = [principal.id for principal in principals]
    if len(ids) != len(set(ids)):
        raise _TaskOutputError("Task XML contains a duplicate normalized principal id.")
    return tuple(principals)


def _normalize_actions(root: ET.Element) -> tuple[TaskAction, ...]:
    container = _direct_child(root, "Actions")
    if container is None:
        return ()

    actions: list[TaskAction] = []
    for element in container:
        action_type = _local_name(element.tag)
        if not action_type:
            raise _TaskOutputError("Task action type must be non-empty.")
        actions.append(
            TaskAction(
                type=action_type,
                xml_c14n=_canonicalize_subtree(element),
            )
        )
    return tuple(actions)


def _normalize_triggers(root: ET.Element) -> tuple[TaskTrigger, ...]:
    container = _direct_child(root, "Triggers")
    if container is None:
        return ()

    triggers: list[TaskTrigger] = []
    for element in container:
        trigger_type = _local_name(element.tag)
        if not trigger_type:
            raise _TaskOutputError("Task trigger type must be non-empty.")
        triggers.append(
            TaskTrigger(
                type=trigger_type,
                xml_c14n=_canonicalize_subtree(element),
            )
        )
    return tuple(sorted(triggers, key=lambda trigger: (trigger.type, trigger.xml_c14n)))


def _normalize_xml(
    xml_value: object,
    *,
    task_id: str,
    task_path: str,
    task_name: str,
) -> ScheduledTaskInfo:
    if not isinstance(xml_value, str) or not xml_value.strip():
        raise _TaskOutputError("Exported task XML must be a non-empty string.")
    try:
        root = ET.fromstring(xml_value)
    except ET.ParseError as exc:
        raise _TaskOutputError("Exported task XML is malformed.") from exc
    if _local_name(root.tag) != "Task":
        raise _TaskOutputError("Exported task XML root must be Task.")

    return ScheduledTaskInfo(
        id=task_id,
        task_path=task_path,
        task_name=task_name,
        principals=_normalize_principals(root),
        actions=_normalize_actions(root),
        triggers=_normalize_triggers(root),
    )


def _structured_command_error(
    section: object,
    *,
    operation: str,
    fallback: str,
    scope: str,
) -> DriftApeError:
    if not isinstance(section, dict):
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            operation=operation,
            message="PowerShell structured error is malformed.",
            recoverable=True,
            scope=scope,
        )
    error_data = section.get("error")
    if not isinstance(error_data, dict):
        return _error(
            code=ErrorCode.UNEXPECTED_OUTPUT,
            operation=operation,
            message="PowerShell structured error is malformed.",
            recoverable=True,
            scope=scope,
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
        message=_bounded_message(error_data.get("message"), fallback),
        native_code=_native_code(error_data.get("native_code")),
        recoverable=True,
        scope=scope,
    )


def _process_document(raw: object) -> TasksCollectorResult:
    if not isinstance(raw, dict):
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation="PowerShell tasks acquisition",
                message="PowerShell tasks acquisition result must be an object.",
                recoverable=True,
            )
        )

    enumeration = raw.get("enumeration")
    if not isinstance(enumeration, dict):
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation="Get-ScheduledTask",
                message="PowerShell output has a malformed enumeration section.",
                recoverable=True,
            )
        )

    ok = enumeration.get("ok")
    if not isinstance(ok, bool):
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation="Get-ScheduledTask",
                message="PowerShell enumeration status is malformed.",
                recoverable=True,
            )
        )
    if not ok:
        return _failed_result(
            _structured_command_error(
                enumeration,
                operation="Get-ScheduledTask",
                fallback="Get-ScheduledTask failed during local collection.",
                scope=_TASKS_SCOPE,
            )
        )

    items = enumeration.get("items")
    if not isinstance(items, list):
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation="Get-ScheduledTask",
                message="PowerShell enumeration items must be an array.",
                recoverable=True,
            )
        )

    identities: list[tuple[str, str, str] | None] = []
    errors: list[DriftApeError] = []
    seen_ids: set[str] = set()

    for item in items:
        try:
            identity = _normalize_identity(item)
        except _TaskOutputError as exc:
            identities.append(None)
            errors.append(
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    operation="Scheduled Task normalization",
                    message=str(exc),
                    recoverable=True,
                    scope=_TASK_SCOPE,
                )
            )
            continue

        task_id, _task_path, _task_name = identity
        if task_id in seen_ids:
            return _failed_result(
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    operation="Scheduled Task normalization",
                    message="Enumeration contains a duplicate canonical task id.",
                    recoverable=True,
                )
            )
        seen_ids.add(task_id)
        identities.append(identity)

    normalized_tasks: list[ScheduledTaskInfo] = []
    for item, identity in zip(items, identities, strict=True):
        if identity is None:
            continue
        task_id, task_path, task_name = identity
        assert isinstance(item, dict)
        export_ok = item.get("export_ok")
        context = _task_context(task_path, task_name)
        if not isinstance(export_ok, bool):
            errors.append(
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    operation="Export-ScheduledTask",
                    message=f"{context} has a malformed export status.",
                    recoverable=True,
                    scope=_TASK_SCOPE,
                )
            )
            continue
        if not export_ok:
            export_error = _structured_command_error(
                item,
                operation="Export-ScheduledTask",
                fallback=f"Export-ScheduledTask failed for {context}.",
                scope=_TASK_SCOPE,
            )
            errors.append(export_error)
            continue

        try:
            normalized_tasks.append(
                _normalize_xml(
                    item.get("Xml"),
                    task_id=task_id,
                    task_path=task_path,
                    task_name=task_name,
                )
            )
        except _TaskOutputError as exc:
            errors.append(
                _error(
                    code=ErrorCode.UNEXPECTED_OUTPUT,
                    operation="Scheduled Task XML parsing",
                    message=f"{context}: {exc}",
                    recoverable=True,
                    scope=_TASK_SCOPE,
                )
            )

    normalized_tasks.sort(key=lambda task: task.id)
    task_tuple = tuple(normalized_tasks)
    if errors:
        return TasksCollectorResult(
            status=CollectorStatus.PARTIAL,
            coverage=frozenset(),
            data=TasksData(tasks=task_tuple),
            errors=tuple(errors),
        )

    return TasksCollectorResult(
        status=CollectorStatus.SUCCESS,
        coverage=frozenset({_TASKS_COVERAGE}),
        data=TasksData(tasks=task_tuple),
        errors=(),
    )


def collect_tasks() -> TasksCollectorResult:
    """Collect canonical local Windows Scheduled Task definition facts."""
    try:
        platform_windows.require_supported_platform()
    except platform_windows.UnsupportedPlatformError:
        return _failed_result(
            _error(
                code=ErrorCode.UNSUPPORTED_OS,
                operation="platform check",
                message="DriftApe Scheduled Tasks collection requires Windows x64.",
                recoverable=False,
            )
        )

    try:
        raw = powershell.run_powershell_json(
            _TASKS_POWERSHELL_SCRIPT,
            timeout_seconds=_ACQUISITION_TIMEOUT_SECONDS,
        )
    except powershell.PowerShellUnavailableError:
        return _failed_result(
            _error(
                code=ErrorCode.COLLECTOR_UNAVAILABLE,
                operation="PowerShell tasks acquisition",
                message="Built-in Windows PowerShell is unavailable.",
                recoverable=True,
            )
        )
    except powershell.PowerShellTimeoutError:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_TIMEOUT,
                operation="PowerShell tasks acquisition",
                message="PowerShell tasks acquisition exceeded 120 seconds.",
                recoverable=True,
            )
        )
    except powershell.PowerShellCommandError as exc:
        return _failed_result(
            _error(
                code=ErrorCode.COMMAND_FAILED,
                operation="PowerShell tasks acquisition",
                message="PowerShell tasks acquisition failed.",
                native_code=exc.return_code,
                recoverable=True,
            )
        )
    except powershell.PowerShellOutputError:
        return _failed_result(
            _error(
                code=ErrorCode.UNEXPECTED_OUTPUT,
                operation="PowerShell tasks acquisition",
                message="PowerShell tasks acquisition returned invalid JSON output.",
                recoverable=True,
            )
        )

    return _process_document(raw)
