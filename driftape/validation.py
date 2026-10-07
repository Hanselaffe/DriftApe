"""Strict validation for untrusted DriftApe v0.1 snapshot mappings."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol, TypeVar, cast

from driftape.constants import SNAPSHOT_SCHEMA_VERSION
from driftape.models import (
    AdministratorMember,
    CollectionInfo,
    CollectorSet,
    CollectorStatus,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderData,
    DefenderExclusion,
    DefenderExclusionKind,
    DefenderRuntime,
    DriftApeError,
    ErrorCode,
    HostInfo,
    LocalUser,
    PrincipalSource,
    ScheduledTaskInfo,
    ServiceInfo,
    ServicesCollectorResult,
    ServicesData,
    ServiceStartMode,
    Snapshot,
    SnapshotKind,
    TaskAction,
    TaskPrincipal,
    TasksCollectorResult,
    TasksData,
    TaskTrigger,
    UsersCollectorResult,
    UsersData,
)

_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEFENDER_ID = "microsoft_defender"

_USERS_COVERAGE = frozenset({"local_users", "administrators"})
_SERVICES_COVERAGE = frozenset({"services"})
_TASKS_COVERAGE = frozenset({"tasks"})
_DEFENDER_COVERAGE = frozenset({"exclusions", "configuration", "runtime"})

_EnumT = TypeVar("_EnumT", bound=StrEnum)


class _HasId(Protocol):
    id: str


class SnapshotValidationError(ValueError):
    """Raised when canonical snapshot input violates the v0.1 contract."""

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SnapshotValidationError(path, "expected object")
    for key in value:
        if not isinstance(key, str):
            raise SnapshotValidationError(path, "object keys must be strings")
    return cast(Mapping[str, object], value)


def _array(value: object, path: str) -> list[object]:
    if not isinstance(value, list):
        raise SnapshotValidationError(path, "expected array")
    return cast(list[object], value)


def _keys(
    value: Mapping[str, object],
    path: str,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    for key in required:
        if key not in value:
            raise SnapshotValidationError(
                f"{path}.{key}" if path else key,
                "missing required field",
            )
    allowed = required | optional
    for key in value:
        if key not in allowed:
            raise SnapshotValidationError(
                f"{path}.{key}" if path else key,
                "unknown field",
            )


def _string(value: object, path: str, *, non_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SnapshotValidationError(path, "expected string")
    if non_empty and value == "":
        raise SnapshotValidationError(path, "must be non-empty")
    return value


def _non_empty_no_edge_whitespace(value: object, path: str) -> str:
    result = _string(value, path, non_empty=True)
    if result != result.strip():
        raise SnapshotValidationError(
            path, "leading/trailing whitespace is not allowed"
        )
    return result


def _nullable_string(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _string(value, path)


def _boolean(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise SnapshotValidationError(path, "expected boolean")
    return cast(bool, value)


def _enum(value: object, path: str, enum_type: type[_EnumT]) -> _EnumT:
    raw = _string(value, path)
    try:
        return enum_type(raw)
    except ValueError as exc:
        raise SnapshotValidationError(path, f"invalid value {raw!r}") from exc


def _native_code(value: object, path: str) -> str | int | None:
    if value is None or isinstance(value, str) or type(value) is int:
        return cast(str | int | None, value)
    raise SnapshotValidationError(path, "expected string, integer, or null")


def _errors(value: object, path: str) -> tuple[DriftApeError, ...]:
    items = _array(value, path)
    return tuple(
        validate_error(item, f"{path}[{index}]")
        for index, item in enumerate(items)
    )


def _coverage(value: object, path: str, allowed: frozenset[str]) -> frozenset[str]:
    items = _array(value, path)
    seen: set[str] = set()
    for index, item in enumerate(items):
        coverage_id = _string(item, f"{path}[{index}]", non_empty=True)
        if coverage_id not in allowed:
            raise SnapshotValidationError(
                f"{path}[{index}]", f"unknown coverage identifier {coverage_id!r}"
            )
        if coverage_id in seen:
            raise SnapshotValidationError(
                f"{path}[{index}]", f"duplicate coverage identifier {coverage_id!r}"
            )
        seen.add(coverage_id)
    return frozenset(seen)


def _validate_status_coverage(
    status: CollectorStatus,
    coverage: frozenset[str],
    full_coverage: frozenset[str],
    path: str,
) -> None:
    if status is CollectorStatus.SUCCESS and coverage != full_coverage:
        raise SnapshotValidationError(path, "success requires full collector coverage")
    if status is CollectorStatus.FAILED and coverage:
        raise SnapshotValidationError(path, "failed requires empty coverage")
    if status is CollectorStatus.PARTIAL and coverage == full_coverage:
        raise SnapshotValidationError(path, "partial requires a strict coverage subset")


def _unique_ids(items: tuple[_HasId, ...], path: str) -> None:
    seen: set[str] = set()
    for index, item in enumerate(items):
        resource_id = item.id
        if resource_id in seen:
            raise SnapshotValidationError(
                f"{path}[{index}].id", f"duplicate resource id {resource_id!r}"
            )
        seen.add(resource_id)


def validate_error(raw: object, path: str = "error") -> DriftApeError:
    """Validate and construct a persisted operational error."""
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset(
            {"code", "scope", "operation", "message", "native_code", "recoverable"}
        ),
    )
    return DriftApeError(
        code=_enum(value["code"], f"{path}.code", ErrorCode),
        scope=_string(value["scope"], f"{path}.scope", non_empty=True),
        operation=_string(value["operation"], f"{path}.operation", non_empty=True),
        message=_string(value["message"], f"{path}.message", non_empty=True),
        native_code=_native_code(value["native_code"], f"{path}.native_code"),
        recoverable=_boolean(value["recoverable"], f"{path}.recoverable"),
    )


def _validate_host(raw: object, path: str) -> HostInfo:
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset(
            {
                "hostname",
                "machine_id_sha256",
                "os_name",
                "os_version",
                "os_build",
                "architecture",
            }
        ),
    )
    machine_id = value["machine_id_sha256"]
    if machine_id is not None:
        machine_id = _string(machine_id, f"{path}.machine_id_sha256")
        if _SHA256_RE.fullmatch(machine_id) is None:
            raise SnapshotValidationError(
                f"{path}.machine_id_sha256",
                "must be exactly 64 lowercase hexadecimal characters or null",
            )
    return HostInfo(
        hostname=_non_empty_no_edge_whitespace(value["hostname"], f"{path}.hostname"),
        machine_id_sha256=cast(str | None, machine_id),
        os_name=_string(value["os_name"], f"{path}.os_name", non_empty=True),
        os_version=_string(value["os_version"], f"{path}.os_version", non_empty=True),
        os_build=_string(value["os_build"], f"{path}.os_build", non_empty=True),
        architecture=_string(
            value["architecture"], f"{path}.architecture", non_empty=True
        ),
    )


def _validate_collection(raw: object, path: str) -> CollectionInfo:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"is_elevated", "complete"}))
    return CollectionInfo(
        is_elevated=_boolean(value["is_elevated"], f"{path}.is_elevated"),
        complete=_boolean(value["complete"], f"{path}.complete"),
    )


def _validate_local_user(raw: object, path: str) -> LocalUser:
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset({"id", "name", "enabled", "principal_source"}),
    )
    return LocalUser(
        id=_string(value["id"], f"{path}.id", non_empty=True),
        name=_string(value["name"], f"{path}.name", non_empty=True),
        enabled=_boolean(value["enabled"], f"{path}.enabled"),
        principal_source=_enum(
            value["principal_source"], f"{path}.principal_source", PrincipalSource
        ),
    )


def _validate_administrator(raw: object, path: str) -> AdministratorMember:
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset({"id", "name", "object_class", "principal_source"}),
    )
    return AdministratorMember(
        id=_string(value["id"], f"{path}.id", non_empty=True),
        name=_string(value["name"], f"{path}.name", non_empty=True),
        object_class=_string(
            value["object_class"], f"{path}.object_class", non_empty=True
        ),
        principal_source=_enum(
            value["principal_source"], f"{path}.principal_source", PrincipalSource
        ),
    )


def _validate_service(raw: object, path: str) -> ServiceInfo:
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset(
            {"id", "name", "display_name", "start_mode", "path_name", "start_name"}
        ),
    )
    return ServiceInfo(
        id=_string(value["id"], f"{path}.id", non_empty=True),
        name=_string(value["name"], f"{path}.name", non_empty=True),
        display_name=_string(value["display_name"], f"{path}.display_name"),
        start_mode=_enum(value["start_mode"], f"{path}.start_mode", ServiceStartMode),
        path_name=_nullable_string(value["path_name"], f"{path}.path_name"),
        start_name=_nullable_string(value["start_name"], f"{path}.start_name"),
    )


def _validate_task_principal(raw: object, path: str) -> TaskPrincipal:
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset({"id", "user_id", "group_id", "logon_type", "run_level"}),
    )
    return TaskPrincipal(
        id=_string(value["id"], f"{path}.id", non_empty=True),
        user_id=_nullable_string(value["user_id"], f"{path}.user_id"),
        group_id=_nullable_string(value["group_id"], f"{path}.group_id"),
        logon_type=_nullable_string(value["logon_type"], f"{path}.logon_type"),
        run_level=_nullable_string(value["run_level"], f"{path}.run_level"),
    )


def _validate_task_action(raw: object, path: str) -> TaskAction:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"type", "xml_c14n"}))
    return TaskAction(
        type=_string(value["type"], f"{path}.type", non_empty=True),
        xml_c14n=_string(value["xml_c14n"], f"{path}.xml_c14n", non_empty=True),
    )


def _validate_task_trigger(raw: object, path: str) -> TaskTrigger:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"type", "xml_c14n"}))
    return TaskTrigger(
        type=_string(value["type"], f"{path}.type", non_empty=True),
        xml_c14n=_string(value["xml_c14n"], f"{path}.xml_c14n", non_empty=True),
    )


def _validate_task(raw: object, path: str) -> ScheduledTaskInfo:
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset(
            {"id", "task_path", "task_name", "principals", "actions", "triggers"}
        ),
    )
    principal_items = _array(value["principals"], f"{path}.principals")
    principals = tuple(
        _validate_task_principal(item, f"{path}.principals[{index}]")
        for index, item in enumerate(principal_items)
    )
    _unique_ids(principals, f"{path}.principals")
    action_items = _array(value["actions"], f"{path}.actions")
    actions = tuple(
        _validate_task_action(item, f"{path}.actions[{index}]")
        for index, item in enumerate(action_items)
    )
    trigger_items = _array(value["triggers"], f"{path}.triggers")
    triggers = tuple(
        _validate_task_trigger(item, f"{path}.triggers[{index}]")
        for index, item in enumerate(trigger_items)
    )
    return ScheduledTaskInfo(
        id=_string(value["id"], f"{path}.id", non_empty=True),
        task_path=_string(value["task_path"], f"{path}.task_path", non_empty=True),
        task_name=_string(value["task_name"], f"{path}.task_name", non_empty=True),
        principals=principals,
        actions=actions,
        triggers=triggers,
    )


def _validate_defender_exclusion(raw: object, path: str) -> DefenderExclusion:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"id", "kind", "value"}))
    return DefenderExclusion(
        id=_string(value["id"], f"{path}.id", non_empty=True),
        kind=_enum(value["kind"], f"{path}.kind", DefenderExclusionKind),
        value=_string(value["value"], f"{path}.value", non_empty=True),
    )


def _validate_defender_configuration(raw: object, path: str) -> DefenderConfiguration:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"id", "disable_realtime_monitoring"}))
    config_id = _string(value["id"], f"{path}.id", non_empty=True)
    if config_id != _DEFENDER_ID:
        raise SnapshotValidationError(f"{path}.id", f"must equal {_DEFENDER_ID!r}")
    return DefenderConfiguration(
        id=config_id,
        disable_realtime_monitoring=_boolean(
            value["disable_realtime_monitoring"], f"{path}.disable_realtime_monitoring"
        ),
    )


def _validate_defender_runtime(raw: object, path: str) -> DefenderRuntime:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"id", "real_time_protection_enabled"}))
    runtime_id = _string(value["id"], f"{path}.id", non_empty=True)
    if runtime_id != _DEFENDER_ID:
        raise SnapshotValidationError(f"{path}.id", f"must equal {_DEFENDER_ID!r}")
    return DefenderRuntime(
        id=runtime_id,
        real_time_protection_enabled=_boolean(
            value["real_time_protection_enabled"],
            f"{path}.real_time_protection_enabled",
        ),
    )


def _validate_users_data(raw: object, path: str) -> UsersData:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"local_users", "administrators"}))

    local_users: tuple[LocalUser, ...] | None
    if value["local_users"] is None:
        local_users = None
    else:
        items = _array(value["local_users"], f"{path}.local_users")
        local_users = tuple(
            _validate_local_user(item, f"{path}.local_users[{index}]")
            for index, item in enumerate(items)
        )
        _unique_ids(local_users, f"{path}.local_users")

    administrators: tuple[AdministratorMember, ...] | None
    if value["administrators"] is None:
        administrators = None
    else:
        items = _array(value["administrators"], f"{path}.administrators")
        administrators = tuple(
            _validate_administrator(item, f"{path}.administrators[{index}]")
            for index, item in enumerate(items)
        )
        _unique_ids(administrators, f"{path}.administrators")

    return UsersData(local_users=local_users, administrators=administrators)


def _validate_services_data(raw: object, path: str) -> ServicesData:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"services"}))
    services: tuple[ServiceInfo, ...] | None
    if value["services"] is None:
        services = None
    else:
        items = _array(value["services"], f"{path}.services")
        services = tuple(
            _validate_service(item, f"{path}.services[{index}]")
            for index, item in enumerate(items)
        )
        _unique_ids(services, f"{path}.services")
    return ServicesData(services=services)


def _validate_tasks_data(raw: object, path: str) -> TasksData:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"tasks"}))
    tasks: tuple[ScheduledTaskInfo, ...] | None
    if value["tasks"] is None:
        tasks = None
    else:
        items = _array(value["tasks"], f"{path}.tasks")
        tasks = tuple(
            _validate_task(item, f"{path}.tasks[{index}]")
            for index, item in enumerate(items)
        )
        _unique_ids(tasks, f"{path}.tasks")
    return TasksData(tasks=tasks)


def _validate_defender_data(raw: object, path: str) -> DefenderData:
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"exclusions", "configuration", "runtime"}))

    exclusions: tuple[DefenderExclusion, ...] | None
    if value["exclusions"] is None:
        exclusions = None
    else:
        items = _array(value["exclusions"], f"{path}.exclusions")
        exclusions = tuple(
            _validate_defender_exclusion(item, f"{path}.exclusions[{index}]")
            for index, item in enumerate(items)
        )
        _unique_ids(exclusions, f"{path}.exclusions")

    configuration = (
        None
        if value["configuration"] is None
        else _validate_defender_configuration(
            value["configuration"], f"{path}.configuration"
        )
    )
    runtime = (
        None
        if value["runtime"] is None
        else _validate_defender_runtime(value["runtime"], f"{path}.runtime")
    )
    return DefenderData(
        exclusions=exclusions,
        configuration=configuration,
        runtime=runtime,
    )


def validate_users_collector(
    raw: object, path: str = "collectors.users"
) -> UsersCollectorResult:
    """Validate and construct the users collector result."""
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"status", "coverage", "data", "errors"}))
    status = _enum(value["status"], f"{path}.status", CollectorStatus)
    coverage = _coverage(value["coverage"], f"{path}.coverage", _USERS_COVERAGE)
    _validate_status_coverage(status, coverage, _USERS_COVERAGE, f"{path}.coverage")
    data = _validate_users_data(value["data"], f"{path}.data")
    if "local_users" in coverage and data.local_users is None:
        raise SnapshotValidationError(
            f"{path}.data.local_users", "covered section must not be null"
        )
    if "administrators" in coverage and data.administrators is None:
        raise SnapshotValidationError(
            f"{path}.data.administrators", "covered section must not be null"
        )
    return UsersCollectorResult(
        status=status,
        coverage=coverage,
        data=data,
        errors=_errors(value["errors"], f"{path}.errors"),
    )


def validate_services_collector(
    raw: object, path: str = "collectors.services"
) -> ServicesCollectorResult:
    """Validate and construct the services collector result."""
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"status", "coverage", "data", "errors"}))
    status = _enum(value["status"], f"{path}.status", CollectorStatus)
    coverage = _coverage(value["coverage"], f"{path}.coverage", _SERVICES_COVERAGE)
    _validate_status_coverage(status, coverage, _SERVICES_COVERAGE, f"{path}.coverage")
    data = _validate_services_data(value["data"], f"{path}.data")
    if "services" in coverage and data.services is None:
        raise SnapshotValidationError(
            f"{path}.data.services", "covered section must not be null"
        )
    return ServicesCollectorResult(
        status=status,
        coverage=coverage,
        data=data,
        errors=_errors(value["errors"], f"{path}.errors"),
    )


def validate_tasks_collector(
    raw: object, path: str = "collectors.tasks"
) -> TasksCollectorResult:
    """Validate and construct the scheduled-tasks collector result."""
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"status", "coverage", "data", "errors"}))
    status = _enum(value["status"], f"{path}.status", CollectorStatus)
    coverage = _coverage(value["coverage"], f"{path}.coverage", _TASKS_COVERAGE)
    _validate_status_coverage(status, coverage, _TASKS_COVERAGE, f"{path}.coverage")
    data = _validate_tasks_data(value["data"], f"{path}.data")
    if "tasks" in coverage and data.tasks is None:
        raise SnapshotValidationError(
            f"{path}.data.tasks", "covered section must not be null"
        )
    return TasksCollectorResult(
        status=status,
        coverage=coverage,
        data=data,
        errors=_errors(value["errors"], f"{path}.errors"),
    )


def validate_defender_collector(
    raw: object, path: str = "collectors.defender"
) -> DefenderCollectorResult:
    """Validate and construct the Microsoft Defender collector result."""
    value = _mapping(raw, path)
    _keys(value, path, required=frozenset({"status", "coverage", "data", "errors"}))
    status = _enum(value["status"], f"{path}.status", CollectorStatus)
    coverage = _coverage(value["coverage"], f"{path}.coverage", _DEFENDER_COVERAGE)
    _validate_status_coverage(status, coverage, _DEFENDER_COVERAGE, f"{path}.coverage")
    data = _validate_defender_data(value["data"], f"{path}.data")
    if "exclusions" in coverage and data.exclusions is None:
        raise SnapshotValidationError(
            f"{path}.data.exclusions", "covered section must not be null"
        )
    if "configuration" in coverage and data.configuration is None:
        raise SnapshotValidationError(
            f"{path}.data.configuration", "covered section must not be null"
        )
    if "runtime" in coverage and data.runtime is None:
        raise SnapshotValidationError(
            f"{path}.data.runtime", "covered section must not be null"
        )
    return DefenderCollectorResult(
        status=status,
        coverage=coverage,
        data=data,
        errors=_errors(value["errors"], f"{path}.errors"),
    )


def _validate_collectors(raw: object, path: str) -> CollectorSet:
    value = _mapping(raw, path)
    _keys(
        value,
        path,
        required=frozenset({"users", "services", "tasks", "defender"}),
    )
    return CollectorSet(
        users=validate_users_collector(value["users"], f"{path}.users"),
        services=validate_services_collector(value["services"], f"{path}.services"),
        tasks=validate_tasks_collector(value["tasks"], f"{path}.tasks"),
        defender=validate_defender_collector(value["defender"], f"{path}.defender"),
    )


def _timestamp(value: object, path: str) -> datetime:
    raw = _string(value, path)
    if _TIMESTAMP_RE.fullmatch(raw) is None:
        raise SnapshotValidationError(
            path, "expected UTC timestamp in YYYY-MM-DDTHH:MM:SSZ format"
        )
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SnapshotValidationError(path, "invalid calendar timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def validate_snapshot(raw: Mapping[str, object]) -> Snapshot:
    """Validate a complete raw mapping and return a typed canonical snapshot."""
    value = _mapping(raw, "snapshot")
    _keys(
        value,
        "",
        required=frozenset(
            {
                "schema_version",
                "tool_version",
                "snapshot_kind",
                "collected_at_utc",
                "host",
                "collection",
                "collectors",
                "errors",
            }
        ),
    )

    schema_version = _string(value["schema_version"], "schema_version")
    if schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotValidationError(
            "schema_version", f"must equal {SNAPSHOT_SCHEMA_VERSION!r}"
        )

    collection = _validate_collection(value["collection"], "collection")
    collectors = _validate_collectors(value["collectors"], "collectors")
    if collection.complete and any(
        status is not CollectorStatus.SUCCESS
        for status in (
            collectors.users.status,
            collectors.services.status,
            collectors.tasks.status,
            collectors.defender.status,
        )
    ):
        raise SnapshotValidationError(
            "collection.complete",
            "true requires all collector statuses to be success",
        )

    return Snapshot(
        schema_version=schema_version,
        tool_version=_string(value["tool_version"], "tool_version", non_empty=True),
        snapshot_kind=_enum(value["snapshot_kind"], "snapshot_kind", SnapshotKind),
        collected_at_utc=_timestamp(value["collected_at_utc"], "collected_at_utc"),
        host=_validate_host(value["host"], "host"),
        collection=collection,
        collectors=collectors,
        errors=_errors(value["errors"], "errors"),
    )
