"""WP8 snapshot orchestration tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import pytest

import driftape.snapshot as snapshot_module
from driftape import platform_windows
from driftape.constants import SNAPSHOT_SCHEMA_VERSION, TOOL_VERSION
from driftape.models import (
    CollectionInfo,
    CollectorStatus,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderData,
    DefenderRuntime,
    DriftApeError,
    ErrorCode,
    HostInfo,
    ServicesCollectorResult,
    ServicesData,
    SnapshotKind,
    TasksCollectorResult,
    TasksData,
    UsersCollectorResult,
    UsersData,
)
from driftape.serialization import serialize_snapshot, snapshot_to_mapping
from driftape.snapshot import SnapshotCollectionError, collect_snapshot
from driftape.validation import validate_snapshot

_FIXED_TIME = datetime(2026, 8, 25, 15, 30, 45, tzinfo=timezone.utc)
_HOST = HostInfo(
    hostname="HOST01",
    machine_id_sha256="a" * 64,
    os_name="Windows 11 Pro",
    os_version="10.0.26200",
    os_build="26200",
    architecture="AMD64",
)


def _error(scope: str = "collector.users") -> DriftApeError:
    return DriftApeError(
        code=ErrorCode.COMMAND_FAILED,
        scope=scope,
        operation="synthetic operation",
        message="Synthetic bounded collector error.",
        native_code=None,
        recoverable=True,
    )


def _users(status: CollectorStatus = CollectorStatus.SUCCESS) -> UsersCollectorResult:
    if status is CollectorStatus.SUCCESS:
        return UsersCollectorResult(
            status=status,
            coverage=frozenset({"local_users", "administrators"}),
            data=UsersData(local_users=(), administrators=()),
            errors=(),
        )
    if status is CollectorStatus.PARTIAL:
        return UsersCollectorResult(
            status=status,
            coverage=frozenset({"local_users"}),
            data=UsersData(local_users=(), administrators=None),
            errors=(_error(),),
        )
    return UsersCollectorResult(
        status=status,
        coverage=frozenset(),
        data=UsersData(local_users=None, administrators=None),
        errors=(_error(),),
    )


def _services(
    status: CollectorStatus = CollectorStatus.SUCCESS,
) -> ServicesCollectorResult:
    if status is CollectorStatus.SUCCESS:
        return ServicesCollectorResult(
            status=status,
            coverage=frozenset({"services"}),
            data=ServicesData(services=()),
            errors=(),
        )
    return ServicesCollectorResult(
        status=status,
        coverage=frozenset(),
        data=ServicesData(services=None),
        errors=(_error("collector.services"),),
    )


def _tasks(status: CollectorStatus = CollectorStatus.SUCCESS) -> TasksCollectorResult:
    if status is CollectorStatus.SUCCESS:
        return TasksCollectorResult(
            status=status,
            coverage=frozenset({"tasks"}),
            data=TasksData(tasks=()),
            errors=(),
        )
    if status is CollectorStatus.PARTIAL:
        return TasksCollectorResult(
            status=status,
            coverage=frozenset(),
            data=TasksData(tasks=()),
            errors=(_error("collector.tasks"),),
        )
    return TasksCollectorResult(
        status=status,
        coverage=frozenset(),
        data=TasksData(tasks=None),
        errors=(_error("collector.tasks"),),
    )


def _defender(
    status: CollectorStatus = CollectorStatus.SUCCESS,
) -> DefenderCollectorResult:
    if status is CollectorStatus.SUCCESS:
        return DefenderCollectorResult(
            status=status,
            coverage=frozenset({"exclusions", "configuration", "runtime"}),
            data=DefenderData(
                exclusions=(),
                configuration=DefenderConfiguration(
                    id="microsoft_defender", disable_realtime_monitoring=False
                ),
                runtime=DefenderRuntime(
                    id="microsoft_defender", real_time_protection_enabled=True
                ),
            ),
            errors=(),
        )
    return DefenderCollectorResult(
        status=status,
        coverage=frozenset(),
        data=DefenderData(exclusions=None, configuration=None, runtime=None),
        errors=(_error("collector.defender"),),
    )


def _patch_success_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    elevated: bool = True,
    users: UsersCollectorResult | None = None,
    services: ServicesCollectorResult | None = None,
    tasks: TasksCollectorResult | None = None,
    defender: DefenderCollectorResult | None = None,
) -> tuple[
    UsersCollectorResult,
    ServicesCollectorResult,
    TasksCollectorResult,
    DefenderCollectorResult,
]:
    user_result = users if users is not None else _users()
    service_result = services if services is not None else _services()
    task_result = tasks if tasks is not None else _tasks()
    defender_result = defender if defender is not None else _defender()
    monkeypatch.setattr(snapshot_module.platform_windows, "require_supported_platform", lambda: None)
    monkeypatch.setattr(snapshot_module, "_utc_now", lambda: _FIXED_TIME)
    monkeypatch.setattr(snapshot_module.platform_windows, "collect_host_info", lambda: _HOST)
    monkeypatch.setattr(snapshot_module.platform_windows, "is_elevated", lambda: elevated)
    monkeypatch.setattr(snapshot_module, "collect_users", lambda: user_result)
    monkeypatch.setattr(snapshot_module, "collect_services", lambda: service_result)
    monkeypatch.setattr(snapshot_module, "collect_tasks", lambda: task_result)
    monkeypatch.setattr(snapshot_module, "collect_defender", lambda: defender_result)
    return user_result, service_result, task_result, defender_result


def test_all_success_produces_valid_typed_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_success_dependencies(monkeypatch)
    result = collect_snapshot(SnapshotKind.BASELINE)
    assert result.collection == CollectionInfo(is_elevated=True, complete=True)
    assert validate_snapshot(snapshot_to_mapping(result)) == result


def test_snapshot_uses_accepted_schema_version(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_success_dependencies(monkeypatch)
    assert collect_snapshot(SnapshotKind.BASELINE).schema_version == SNAPSHOT_SCHEMA_VERSION


def test_snapshot_uses_accepted_tool_version(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_success_dependencies(monkeypatch)
    assert collect_snapshot(SnapshotKind.BASELINE).tool_version == TOOL_VERSION


@pytest.mark.parametrize("kind", [SnapshotKind.BASELINE, SnapshotKind.CURRENT])
def test_snapshot_kind_is_preserved(
    monkeypatch: pytest.MonkeyPatch, kind: SnapshotKind
) -> None:
    _patch_success_dependencies(monkeypatch)
    assert collect_snapshot(kind).snapshot_kind is kind


def test_non_snapshot_kind_raises_before_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def platform_check() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(snapshot_module.platform_windows, "require_supported_platform", platform_check)
    with pytest.raises(TypeError):
        collect_snapshot("baseline")  # type: ignore[arg-type]
    assert called is False


def test_timestamp_is_utc_second_precision_and_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    clock_calls = 0

    def clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        return _FIXED_TIME

    _patch_success_dependencies(monkeypatch)
    monkeypatch.setattr(snapshot_module, "_utc_now", clock)
    result = collect_snapshot(SnapshotKind.BASELINE)
    assert result.collected_at_utc == _FIXED_TIME
    assert result.collected_at_utc.tzinfo is timezone.utc
    assert result.collected_at_utc.microsecond == 0
    assert clock_calls == 1


def test_utc_now_normalizes_microseconds(monkeypatch: pytest.MonkeyPatch) -> None:
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz: timezone | None = None) -> FixedDateTime:
            assert tz is timezone.utc
            return cls(2026, 8, 25, 15, 30, 45, 987654, tzinfo=timezone.utc)

    monkeypatch.setattr(snapshot_module, "datetime", FixedDateTime)
    assert snapshot_module._utc_now() == _FIXED_TIME


def test_no_collector_generates_a_wp8_clock_call(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _patch_success_dependencies(monkeypatch)
    monkeypatch.setattr(snapshot_module, "_utc_now", lambda: events.append("clock") or _FIXED_TIME)
    monkeypatch.setattr(snapshot_module, "collect_users", lambda: events.append("users") or _users())
    monkeypatch.setattr(snapshot_module, "collect_services", lambda: events.append("services") or _services())
    monkeypatch.setattr(snapshot_module, "collect_tasks", lambda: events.append("tasks") or _tasks())
    monkeypatch.setattr(snapshot_module, "collect_defender", lambda: events.append("defender") or _defender())
    collect_snapshot(SnapshotKind.BASELINE)
    assert events == ["clock", "users", "services", "tasks", "defender"]


def test_supported_platform_check_precedes_host_and_collectors(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _patch_success_dependencies(monkeypatch)
    monkeypatch.setattr(snapshot_module.platform_windows, "require_supported_platform", lambda: events.append("platform"))
    monkeypatch.setattr(snapshot_module.platform_windows, "collect_host_info", lambda: events.append("host") or _HOST)
    monkeypatch.setattr(snapshot_module, "collect_users", lambda: events.append("users") or _users())
    collect_snapshot(SnapshotKind.BASELINE)
    assert events[0:3] == ["platform", "host", "users"]


def test_unsupported_platform_propagates_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    def unsupported() -> None:
        events.append("platform")
        raise platform_windows.UnsupportedPlatformError("unsupported")

    monkeypatch.setattr(snapshot_module.platform_windows, "require_supported_platform", unsupported)
    monkeypatch.setattr(snapshot_module.platform_windows, "collect_host_info", lambda: events.append("host") or _HOST)
    monkeypatch.setattr(snapshot_module.platform_windows, "is_elevated", lambda: events.append("elevation") or True)
    monkeypatch.setattr(snapshot_module, "collect_users", lambda: events.append("users") or _users())
    with pytest.raises(platform_windows.UnsupportedPlatformError, match="unsupported"):
        collect_snapshot(SnapshotKind.BASELINE)
    assert events == ["platform"]


def test_host_and_elevation_are_called_once_and_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    host_calls = 0
    elevation_calls = 0
    _patch_success_dependencies(monkeypatch, elevated=False)

    def host() -> HostInfo:
        nonlocal host_calls
        host_calls += 1
        return _HOST

    def elevation() -> bool:
        nonlocal elevation_calls
        elevation_calls += 1
        return False

    monkeypatch.setattr(snapshot_module.platform_windows, "collect_host_info", host)
    monkeypatch.setattr(snapshot_module.platform_windows, "is_elevated", elevation)
    result = collect_snapshot(SnapshotKind.CURRENT)
    assert host_calls == 1
    assert elevation_calls == 1
    assert result.host is _HOST
    assert result.collection.is_elevated is False


@pytest.mark.parametrize("elevated", [True, False])
def test_elevation_value_is_preserved(monkeypatch: pytest.MonkeyPatch, elevated: bool) -> None:
    _patch_success_dependencies(monkeypatch, elevated=elevated)
    assert collect_snapshot(SnapshotKind.BASELINE).collection.is_elevated is elevated


def test_host_inspection_failure_is_fatal_and_collectors_do_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _patch_success_dependencies(monkeypatch)

    def bad_host() -> HostInfo:
        raise platform_windows.PlatformInspectionError("secret detail")

    monkeypatch.setattr(snapshot_module.platform_windows, "collect_host_info", bad_host)
    monkeypatch.setattr(snapshot_module, "collect_users", lambda: events.append("users") or _users())
    with pytest.raises(SnapshotCollectionError, match="Host metadata inspection failed"):
        collect_snapshot(SnapshotKind.BASELINE)
    assert events == []


def test_elevation_inspection_failure_is_fatal_and_collectors_do_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _patch_success_dependencies(monkeypatch)

    def bad_elevation() -> bool:
        raise platform_windows.PlatformInspectionError("secret detail")

    monkeypatch.setattr(snapshot_module.platform_windows, "is_elevated", bad_elevation)
    monkeypatch.setattr(snapshot_module, "collect_users", lambda: events.append("users") or _users())
    with pytest.raises(SnapshotCollectionError, match="Elevation-state inspection failed"):
        collect_snapshot(SnapshotKind.BASELINE)
    assert events == []


def test_collectors_run_in_fixed_order_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _patch_success_dependencies(monkeypatch)
    monkeypatch.setattr(snapshot_module, "collect_users", lambda: events.append("users") or _users())
    monkeypatch.setattr(snapshot_module, "collect_services", lambda: events.append("services") or _services())
    monkeypatch.setattr(snapshot_module, "collect_tasks", lambda: events.append("tasks") or _tasks())
    monkeypatch.setattr(snapshot_module, "collect_defender", lambda: events.append("defender") or _defender())
    collect_snapshot(SnapshotKind.BASELINE)
    assert events == ["users", "services", "tasks", "defender"]


@pytest.mark.parametrize(
    ("users", "services", "tasks", "defender", "expected"),
    [
        (_users(), _services(), _tasks(), _defender(), True),
        (_users(CollectorStatus.PARTIAL), _services(), _tasks(), _defender(), False),
        (_users(), _services(CollectorStatus.FAILED), _tasks(), _defender(), False),
        (_users(), _services(), _tasks(CollectorStatus.PARTIAL), _defender(), False),
        (_users(), _services(), _tasks(), _defender(CollectorStatus.FAILED), False),
        (
            _users(CollectorStatus.PARTIAL),
            _services(CollectorStatus.FAILED),
            _tasks(CollectorStatus.PARTIAL),
            _defender(CollectorStatus.FAILED),
            False,
        ),
    ],
)
def test_completeness_is_based_only_on_all_success_statuses(
    monkeypatch: pytest.MonkeyPatch,
    users: UsersCollectorResult,
    services: ServicesCollectorResult,
    tasks: TasksCollectorResult,
    defender: DefenderCollectorResult,
    expected: bool,
) -> None:
    _patch_success_dependencies(
        monkeypatch,
        users=users,
        services=services,
        tasks=tasks,
        defender=defender,
    )
    assert collect_snapshot(SnapshotKind.BASELINE).collection.complete is expected


def test_valid_collector_results_are_preserved_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    users = _users(CollectorStatus.PARTIAL)
    services = _services()
    tasks = _tasks(CollectorStatus.PARTIAL)
    defender = _defender()
    _patch_success_dependencies(
        monkeypatch,
        users=users,
        services=services,
        tasks=tasks,
        defender=defender,
    )
    result = collect_snapshot(SnapshotKind.BASELINE)
    assert result.collectors.users is users
    assert result.collectors.services is services
    assert result.collectors.tasks is tasks
    assert result.collectors.defender is defender
    assert result.collectors.users.errors == users.errors
    assert result.collectors.tasks.data == tasks.data
    assert result.errors == ()


_COLLECTOR_CASES = [
    ("users", UsersCollectorResult, "collector.users", "users collector", "Users"),
    ("services", ServicesCollectorResult, "collector.services", "services collector", "Services"),
    ("tasks", TasksCollectorResult, "collector.tasks", "tasks collector", "Tasks"),
    ("defender", DefenderCollectorResult, "collector.defender", "defender collector", "Defender"),
]


def _assert_internal_failure_shape(
    result: UsersCollectorResult | ServicesCollectorResult | TasksCollectorResult | DefenderCollectorResult,
    *,
    scope: str,
    operation: str,
    domain: str,
) -> None:
    assert result.status is CollectorStatus.FAILED
    assert result.coverage == frozenset()
    assert len(result.errors) == 1
    error = result.errors[0]
    assert error.code is ErrorCode.INTERNAL_ERROR
    assert error.scope == scope
    assert error.operation == operation
    assert error.message == f"{domain} collector raised an unexpected internal exception."
    assert error.native_code is None
    assert error.recoverable is False
    assert "INJECTED_SECRET" not in error.message
    if isinstance(result, UsersCollectorResult):
        assert result.data.local_users is None
        assert result.data.administrators is None
    elif isinstance(result, ServicesCollectorResult):
        assert result.data.services is None
    elif isinstance(result, TasksCollectorResult):
        assert result.data.tasks is None
    else:
        assert result.data.exclusions is None
        assert result.data.configuration is None
        assert result.data.runtime is None


@pytest.mark.parametrize(("name", "expected_type", "scope", "operation", "domain"), _COLLECTOR_CASES)
def test_unexpected_collector_exception_is_isolated_and_later_collectors_run(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    expected_type: type[object],
    scope: str,
    operation: str,
    domain: str,
) -> None:
    events: list[str] = []
    _patch_success_dependencies(monkeypatch)

    def raising() -> object:
        events.append(name)
        raise RuntimeError("INJECTED_SECRET")

    monkeypatch.setattr(snapshot_module, f"collect_{name}", raising)
    for later_name, factory in (
        ("users", _users),
        ("services", _services),
        ("tasks", _tasks),
        ("defender", _defender),
    ):
        if later_name != name:
            monkeypatch.setattr(
                snapshot_module,
                f"collect_{later_name}",
                lambda n=later_name, f=factory: events.append(n) or f(),
            )

    result = collect_snapshot(SnapshotKind.BASELINE)
    collector_result = getattr(result.collectors, name)
    assert isinstance(collector_result, expected_type)
    _assert_internal_failure_shape(
        collector_result,
        scope=scope,
        operation=operation,
        domain=domain,
    )
    assert result.collection.complete is False
    assert result.errors == ()
    expected_order = ["users", "services", "tasks", "defender"]
    assert events == expected_order


@pytest.mark.parametrize(("name", "expected_type", "scope", "operation", "domain"), _COLLECTOR_CASES)
def test_wrong_collector_return_type_is_isolated(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    expected_type: type[object],
    scope: str,
    operation: str,
    domain: str,
) -> None:
    events: list[str] = []
    _patch_success_dependencies(monkeypatch)
    monkeypatch.setattr(
        snapshot_module,
        f"collect_{name}",
        lambda: events.append(name) or {"wrong": "type"},
    )
    for other_name, factory in (
        ("users", _users),
        ("services", _services),
        ("tasks", _tasks),
        ("defender", _defender),
    ):
        if other_name != name:
            monkeypatch.setattr(
                snapshot_module,
                f"collect_{other_name}",
                lambda n=other_name, f=factory: events.append(n) or f(),
            )

    result = collect_snapshot(SnapshotKind.CURRENT)
    collector_result = getattr(result.collectors, name)
    assert isinstance(collector_result, expected_type)
    _assert_internal_failure_shape(
        collector_result,
        scope=scope,
        operation=operation,
        domain=domain,
    )
    assert events == ["users", "services", "tasks", "defender"]
    assert result.collection.complete is False


def test_baseexception_is_not_caught_at_collector_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_success_dependencies(monkeypatch)

    def interrupt() -> UsersCollectorResult:
        raise KeyboardInterrupt

    monkeypatch.setattr(snapshot_module, "collect_users", interrupt)
    with pytest.raises(KeyboardInterrupt):
        collect_snapshot(SnapshotKind.BASELINE)


def test_schema_round_trip_and_canonical_serialization_compatibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_success_dependencies(monkeypatch)
    first = collect_snapshot(SnapshotKind.BASELINE)
    second = collect_snapshot(SnapshotKind.BASELINE)
    mapping = snapshot_to_mapping(first)
    assert validate_snapshot(mapping) == first
    assert first == second
    assert serialize_snapshot(first) == serialize_snapshot(second)


def test_root_errors_remain_empty_when_collector_has_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    users = _users(CollectorStatus.PARTIAL)
    _patch_success_dependencies(monkeypatch, users=users)
    result = collect_snapshot(SnapshotKind.BASELINE)
    assert result.errors == ()
    assert result.collectors.users.errors == users.errors


def test_baseline_and_current_use_same_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_success_dependencies(monkeypatch)
    baseline = collect_snapshot(SnapshotKind.BASELINE)
    current = collect_snapshot(SnapshotKind.CURRENT)
    assert replace(baseline, snapshot_kind=SnapshotKind.CURRENT) == current
