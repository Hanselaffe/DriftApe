"""Typed snapshot orchestration for DriftApe v0.1."""

from __future__ import annotations

from datetime import datetime, timezone

from driftape import platform_windows
from driftape.collectors.defender import collect_defender
from driftape.collectors.services import collect_services
from driftape.collectors.tasks import collect_tasks
from driftape.collectors.users import collect_users
from driftape.constants import SNAPSHOT_SCHEMA_VERSION, TOOL_VERSION
from driftape.models import (
    CollectionInfo,
    CollectorSet,
    CollectorStatus,
    DefenderCollectorResult,
    DefenderData,
    DriftApeError,
    ErrorCode,
    ServicesCollectorResult,
    ServicesData,
    Snapshot,
    SnapshotKind,
    TasksCollectorResult,
    TasksData,
    UsersCollectorResult,
    UsersData,
)


class SnapshotCollectionError(RuntimeError):
    """Raised when a truthful Snapshot cannot be constructed."""


def _utc_now() -> datetime:
    """Return the collection-start time as UTC with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def _internal_error(scope: str, operation: str, domain: str) -> DriftApeError:
    return DriftApeError(
        code=ErrorCode.INTERNAL_ERROR,
        scope=scope,
        operation=operation,
        message=f"{domain} collector raised an unexpected internal exception.",
        native_code=None,
        recoverable=False,
    )


def _failed_users_result() -> UsersCollectorResult:
    return UsersCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=UsersData(local_users=None, administrators=None),
        errors=(
            _internal_error(
                "collector.users",
                "users collector",
                "Users",
            ),
        ),
    )


def _failed_services_result() -> ServicesCollectorResult:
    return ServicesCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=ServicesData(services=None),
        errors=(
            _internal_error(
                "collector.services",
                "services collector",
                "Services",
            ),
        ),
    )


def _failed_tasks_result() -> TasksCollectorResult:
    return TasksCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=TasksData(tasks=None),
        errors=(
            _internal_error(
                "collector.tasks",
                "tasks collector",
                "Tasks",
            ),
        ),
    )


def _failed_defender_result() -> DefenderCollectorResult:
    return DefenderCollectorResult(
        status=CollectorStatus.FAILED,
        coverage=frozenset(),
        data=DefenderData(exclusions=None, configuration=None, runtime=None),
        errors=(
            _internal_error(
                "collector.defender",
                "defender collector",
                "Defender",
            ),
        ),
    )


def _collect_users_isolated() -> UsersCollectorResult:
    try:
        result = collect_users()
    except Exception:
        return _failed_users_result()
    if not isinstance(result, UsersCollectorResult):
        return _failed_users_result()
    return result


def _collect_services_isolated() -> ServicesCollectorResult:
    try:
        result = collect_services()
    except Exception:
        return _failed_services_result()
    if not isinstance(result, ServicesCollectorResult):
        return _failed_services_result()
    return result


def _collect_tasks_isolated() -> TasksCollectorResult:
    try:
        result = collect_tasks()
    except Exception:
        return _failed_tasks_result()
    if not isinstance(result, TasksCollectorResult):
        return _failed_tasks_result()
    return result


def _collect_defender_isolated() -> DefenderCollectorResult:
    try:
        result = collect_defender()
    except Exception:
        return _failed_defender_result()
    if not isinstance(result, DefenderCollectorResult):
        return _failed_defender_result()
    return result


def collect_snapshot(snapshot_kind: SnapshotKind) -> Snapshot:
    """Collect one complete typed DriftApe snapshot from accepted collectors."""
    if not isinstance(snapshot_kind, SnapshotKind):
        raise TypeError("snapshot_kind must be a SnapshotKind")

    platform_windows.require_supported_platform()
    collection_start_utc = _utc_now()

    try:
        host = platform_windows.collect_host_info()
    except platform_windows.PlatformInspectionError as exc:
        raise SnapshotCollectionError("Host metadata inspection failed.") from exc

    try:
        is_elevated = platform_windows.is_elevated()
    except platform_windows.PlatformInspectionError as exc:
        raise SnapshotCollectionError("Elevation-state inspection failed.") from exc

    users = _collect_users_isolated()
    services = _collect_services_isolated()
    tasks = _collect_tasks_isolated()
    defender = _collect_defender_isolated()

    collectors = CollectorSet(
        users=users,
        services=services,
        tasks=tasks,
        defender=defender,
    )
    complete = (
        users.status is CollectorStatus.SUCCESS
        and services.status is CollectorStatus.SUCCESS
        and tasks.status is CollectorStatus.SUCCESS
        and defender.status is CollectorStatus.SUCCESS
    )
    collection = CollectionInfo(is_elevated=is_elevated, complete=complete)

    return Snapshot(
        schema_version=SNAPSHOT_SCHEMA_VERSION,
        tool_version=TOOL_VERSION,
        snapshot_kind=snapshot_kind,
        collected_at_utc=collection_start_utc,
        host=host,
        collection=collection,
        collectors=collectors,
        errors=(),
    )
