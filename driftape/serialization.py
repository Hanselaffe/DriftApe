"""Explicit canonical serialization for DriftApe v0.1 snapshots."""

from __future__ import annotations

import json
from datetime import timedelta

from driftape.models import (
    AdministratorMember,
    CollectionInfo,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderData,
    DefenderExclusion,
    DefenderRuntime,
    DriftApeError,
    HostInfo,
    LocalUser,
    ScheduledTaskInfo,
    ServiceInfo,
    ServicesCollectorResult,
    ServicesData,
    Snapshot,
    TaskAction,
    TaskPrincipal,
    TasksCollectorResult,
    TasksData,
    TaskTrigger,
    UsersCollectorResult,
    UsersData,
)


class SnapshotSerializationError(ValueError):
    """Raised when a typed snapshot violates canonical serialization invariants."""


def _timestamp_to_string(snapshot: Snapshot) -> str:
    value = snapshot.collected_at_utc
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SnapshotSerializationError("collected_at_utc must be timezone-aware UTC")
    if value.microsecond != 0:
        raise SnapshotSerializationError(
            "collected_at_utc must not contain fractional seconds"
        )
    return (
        f"{value.year:04d}-"
        f"{value.month:02d}-"
        f"{value.day:02d}T"
        f"{value.hour:02d}:"
        f"{value.minute:02d}:"
        f"{value.second:02d}Z"
    )


def _error_to_mapping(error: DriftApeError) -> dict[str, object]:
    return {
        "code": error.code.value,
        "scope": error.scope,
        "operation": error.operation,
        "message": error.message,
        "native_code": error.native_code,
        "recoverable": error.recoverable,
    }


def _host_to_mapping(host: HostInfo) -> dict[str, object]:
    return {
        "hostname": host.hostname,
        "machine_id_sha256": host.machine_id_sha256,
        "os_name": host.os_name,
        "os_version": host.os_version,
        "os_build": host.os_build,
        "architecture": host.architecture,
    }


def _collection_to_mapping(collection: CollectionInfo) -> dict[str, object]:
    return {
        "is_elevated": collection.is_elevated,
        "complete": collection.complete,
    }


def _local_user_to_mapping(user: LocalUser) -> dict[str, object]:
    return {
        "id": user.id,
        "name": user.name,
        "enabled": user.enabled,
        "principal_source": user.principal_source.value,
    }


def _administrator_to_mapping(member: AdministratorMember) -> dict[str, object]:
    return {
        "id": member.id,
        "name": member.name,
        "object_class": member.object_class,
        "principal_source": member.principal_source.value,
    }


def _users_data_to_mapping(data: UsersData) -> dict[str, object]:
    local_users: object = None
    if data.local_users is not None:
        local_users = [_local_user_to_mapping(user) for user in data.local_users]

    administrators: object = None
    if data.administrators is not None:
        administrators = [
            _administrator_to_mapping(member) for member in data.administrators
        ]

    return {
        "local_users": local_users,
        "administrators": administrators,
    }


def _service_to_mapping(service: ServiceInfo) -> dict[str, object]:
    return {
        "id": service.id,
        "name": service.name,
        "display_name": service.display_name,
        "start_mode": service.start_mode.value,
        "path_name": service.path_name,
        "start_name": service.start_name,
    }


def _services_data_to_mapping(data: ServicesData) -> dict[str, object]:
    services: object = None
    if data.services is not None:
        services = [_service_to_mapping(service) for service in data.services]
    return {"services": services}


def _task_principal_to_mapping(principal: TaskPrincipal) -> dict[str, object]:
    return {
        "id": principal.id,
        "user_id": principal.user_id,
        "group_id": principal.group_id,
        "logon_type": principal.logon_type,
        "run_level": principal.run_level,
    }


def _task_action_to_mapping(action: TaskAction) -> dict[str, object]:
    return {
        "type": action.type,
        "xml_c14n": action.xml_c14n,
    }


def _task_trigger_to_mapping(trigger: TaskTrigger) -> dict[str, object]:
    return {
        "type": trigger.type,
        "xml_c14n": trigger.xml_c14n,
    }


def _task_to_mapping(task: ScheduledTaskInfo) -> dict[str, object]:
    return {
        "id": task.id,
        "task_path": task.task_path,
        "task_name": task.task_name,
        "principals": [
            _task_principal_to_mapping(principal) for principal in task.principals
        ],
        "actions": [_task_action_to_mapping(action) for action in task.actions],
        "triggers": [_task_trigger_to_mapping(trigger) for trigger in task.triggers],
    }


def _tasks_data_to_mapping(data: TasksData) -> dict[str, object]:
    tasks: object = None
    if data.tasks is not None:
        tasks = [_task_to_mapping(task) for task in data.tasks]
    return {"tasks": tasks}


def _defender_exclusion_to_mapping(
    exclusion: DefenderExclusion,
) -> dict[str, object]:
    return {
        "id": exclusion.id,
        "kind": exclusion.kind.value,
        "value": exclusion.value,
    }


def _defender_configuration_to_mapping(
    configuration: DefenderConfiguration,
) -> dict[str, object]:
    return {
        "id": configuration.id,
        "disable_realtime_monitoring": configuration.disable_realtime_monitoring,
    }


def _defender_runtime_to_mapping(runtime: DefenderRuntime) -> dict[str, object]:
    return {
        "id": runtime.id,
        "real_time_protection_enabled": runtime.real_time_protection_enabled,
    }


def _defender_data_to_mapping(data: DefenderData) -> dict[str, object]:
    exclusions: object = None
    if data.exclusions is not None:
        exclusions = [
            _defender_exclusion_to_mapping(exclusion) for exclusion in data.exclusions
        ]

    configuration: object = None
    if data.configuration is not None:
        configuration = _defender_configuration_to_mapping(data.configuration)

    runtime: object = None
    if data.runtime is not None:
        runtime = _defender_runtime_to_mapping(data.runtime)

    return {
        "exclusions": exclusions,
        "configuration": configuration,
        "runtime": runtime,
    }


def _users_collector_to_mapping(
    collector: UsersCollectorResult,
) -> dict[str, object]:
    return {
        "status": collector.status.value,
        "coverage": sorted(collector.coverage),
        "data": _users_data_to_mapping(collector.data),
        "errors": [_error_to_mapping(error) for error in collector.errors],
    }


def _services_collector_to_mapping(
    collector: ServicesCollectorResult,
) -> dict[str, object]:
    return {
        "status": collector.status.value,
        "coverage": sorted(collector.coverage),
        "data": _services_data_to_mapping(collector.data),
        "errors": [_error_to_mapping(error) for error in collector.errors],
    }


def _tasks_collector_to_mapping(
    collector: TasksCollectorResult,
) -> dict[str, object]:
    return {
        "status": collector.status.value,
        "coverage": sorted(collector.coverage),
        "data": _tasks_data_to_mapping(collector.data),
        "errors": [_error_to_mapping(error) for error in collector.errors],
    }


def _defender_collector_to_mapping(
    collector: DefenderCollectorResult,
) -> dict[str, object]:
    return {
        "status": collector.status.value,
        "coverage": sorted(collector.coverage),
        "data": _defender_data_to_mapping(collector.data),
        "errors": [_error_to_mapping(error) for error in collector.errors],
    }


def snapshot_to_mapping(snapshot: Snapshot) -> dict[str, object]:
    """Convert a typed Snapshot to the exact persisted primitive mapping."""
    return {
        "schema_version": snapshot.schema_version,
        "tool_version": snapshot.tool_version,
        "snapshot_kind": snapshot.snapshot_kind.value,
        "collected_at_utc": _timestamp_to_string(snapshot),
        "host": _host_to_mapping(snapshot.host),
        "collection": _collection_to_mapping(snapshot.collection),
        "collectors": {
            "users": _users_collector_to_mapping(snapshot.collectors.users),
            "services": _services_collector_to_mapping(snapshot.collectors.services),
            "tasks": _tasks_collector_to_mapping(snapshot.collectors.tasks),
            "defender": _defender_collector_to_mapping(snapshot.collectors.defender),
        },
        "errors": [_error_to_mapping(error) for error in snapshot.errors],
    }


def serialize_snapshot(snapshot: Snapshot) -> bytes:
    """Return deterministic canonical UTF-8 JSON bytes for a typed Snapshot."""
    mapping = snapshot_to_mapping(snapshot)
    text = json.dumps(
        mapping,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"{text}\n".encode("utf-8")
