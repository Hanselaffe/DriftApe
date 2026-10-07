from __future__ import annotations

import hashlib
import json
from dataclasses import is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum

import pytest

import driftape.diff as diff_module
from driftape.constants import SNAPSHOT_SCHEMA_VERSION
from driftape.diff import (
    Change,
    ChangeType,
    ComparisonStatus,
    DiffSchemaMismatchError,
    HostMismatchError,
    InvalidDiffInputError,
    compare_snapshots,
)
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

ALL_DOMAINS = (
    "users.local_users",
    "users.administrators",
    "services.services",
    "tasks.tasks",
    "defender.exclusions",
    "defender.configuration",
    "defender.runtime",
)


def _user(
    resource_id: str = "S-1-5-21-1000",
    *,
    name: str = "alice",
    enabled: bool = True,
    principal_source: PrincipalSource = PrincipalSource.LOCAL,
) -> LocalUser:
    return LocalUser(resource_id, name, enabled, principal_source)


def _admin(
    resource_id: str = "S-1-5-32-544",
    *,
    name: str = "Administrator",
    object_class: str = "User",
    principal_source: PrincipalSource = PrincipalSource.LOCAL,
) -> AdministratorMember:
    return AdministratorMember(
        resource_id, name, object_class, principal_source
    )


def _service(
    resource_id: str = "spooler",
    *,
    name: str = "Spooler",
    display_name: str = "Print Spooler",
    start_mode: ServiceStartMode = ServiceStartMode.AUTO,
    path_name: str | None = r"C:\Windows\System32\spoolsv.exe",
    start_name: str | None = "LocalSystem",
) -> ServiceInfo:
    return ServiceInfo(
        resource_id,
        name,
        display_name,
        start_mode,
        path_name,
        start_name,
    )


def _task(
    resource_id: str = r"\maintenance\cleanup",
    *,
    task_path: str = "\\Maintenance\\",
    task_name: str = "Cleanup",
    principals: tuple[TaskPrincipal, ...] | None = None,
    actions: tuple[TaskAction, ...] | None = None,
    triggers: tuple[TaskTrigger, ...] | None = None,
) -> ScheduledTaskInfo:
    if principals is None:
        principals = (
            TaskPrincipal(
                id="principal-1",
                user_id="SYSTEM",
                group_id=None,
                logon_type="ServiceAccount",
                run_level="HighestAvailable",
            ),
        )
    if actions is None:
        actions = (TaskAction(type="Exec", xml_c14n="<Exec>A</Exec>"),)
    if triggers is None:
        triggers = (TaskTrigger(type="BootTrigger", xml_c14n="<BootTrigger/>"),)
    return ScheduledTaskInfo(
        resource_id,
        task_path,
        task_name,
        principals,
        actions,
        triggers,
    )


def _exclusion(
    resource_id: str = "path:c:/temp",
    *,
    kind: DefenderExclusionKind = DefenderExclusionKind.PATH,
    value: str = "C:/Temp",
) -> DefenderExclusion:
    return DefenderExclusion(resource_id, kind, value)


def _snapshot(
    kind: SnapshotKind,
    *,
    schema_version: str = SNAPSHOT_SCHEMA_VERSION,
    tool_version: str = "0.1.0",
    timestamp: datetime | None = None,
    hostname: str = "HOST-A",
    machine_id: str | None = "a" * 64,
    os_name: str = "Windows",
    os_version: str = "11",
    os_build: str = "26100",
    architecture: str = "AMD64",
    users_status: CollectorStatus = CollectorStatus.SUCCESS,
    users_coverage: frozenset[str] = frozenset({"local_users", "administrators"}),
    local_users: tuple[LocalUser, ...] | None = (),
    administrators: tuple[AdministratorMember, ...] | None = (),
    services_status: CollectorStatus = CollectorStatus.SUCCESS,
    services_coverage: frozenset[str] = frozenset({"services"}),
    services: tuple[ServiceInfo, ...] | None = (),
    tasks_status: CollectorStatus = CollectorStatus.SUCCESS,
    tasks_coverage: frozenset[str] = frozenset({"tasks"}),
    tasks: tuple[ScheduledTaskInfo, ...] | None = (),
    defender_status: CollectorStatus = CollectorStatus.SUCCESS,
    defender_coverage: frozenset[str] = frozenset(
        {"exclusions", "configuration", "runtime"}
    ),
    exclusions: tuple[DefenderExclusion, ...] | None = (),
    configuration: DefenderConfiguration | None = None,
    runtime: DefenderRuntime | None = None,
) -> Snapshot:
    if timestamp is None:
        timestamp = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
    if configuration is None and "configuration" in defender_coverage:
        configuration = DefenderConfiguration("microsoft_defender", False)
    if runtime is None and "runtime" in defender_coverage:
        runtime = DefenderRuntime("microsoft_defender", True)
    return Snapshot(
        schema_version=schema_version,
        tool_version=tool_version,
        snapshot_kind=kind,
        collected_at_utc=timestamp,
        host=HostInfo(
            hostname=hostname,
            machine_id_sha256=machine_id,
            os_name=os_name,
            os_version=os_version,
            os_build=os_build,
            architecture=architecture,
        ),
        collection=CollectionInfo(is_elevated=False, complete=False),
        collectors=CollectorSet(
            users=UsersCollectorResult(
                status=users_status,
                coverage=users_coverage,
                data=UsersData(local_users, administrators),
                errors=(),
            ),
            services=ServicesCollectorResult(
                status=services_status,
                coverage=services_coverage,
                data=ServicesData(services),
                errors=(),
            ),
            tasks=TasksCollectorResult(
                status=tasks_status,
                coverage=tasks_coverage,
                data=TasksData(tasks),
                errors=(),
            ),
            defender=DefenderCollectorResult(
                status=defender_status,
                coverage=defender_coverage,
                data=DefenderData(exclusions, configuration, runtime),
                errors=(),
            ),
        ),
        errors=(),
    )


def _pair(**kwargs: object) -> tuple[Snapshot, Snapshot]:
    return _snapshot(SnapshotKind.BASELINE, **kwargs), _snapshot(
        SnapshotKind.CURRENT, **kwargs
    )


def _independent_digest(change: Change) -> str:
    payload = {
        "domain": change.domain,
        "object_id": change.object_id,
        "change_type": change.change_type.value,
        "property": change.property,
        "old_value": change.old_value,
        "new_value": change.new_value,
    }
    text = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(f"{text}\n".encode()).hexdigest()


def _assert_primitives(value: object) -> None:
    assert not isinstance(value, Enum)
    assert not is_dataclass(value)
    if value is None or type(value) is bool or isinstance(value, str):
        return
    if isinstance(value, list):
        for item in value:
            _assert_primitives(item)
        return
    if isinstance(value, dict):
        assert all(isinstance(key, str) for key in value)
        for item in value.values():
            _assert_primitives(item)
        return
    raise AssertionError(f"non-canonical value: {type(value)!r}")


def test_t_wp10_001_non_snapshot_baseline_raises_type_error() -> None:
    current = _snapshot(SnapshotKind.CURRENT)
    with pytest.raises(TypeError):
        compare_snapshots({}, current)  # type: ignore[arg-type]


def test_t_wp10_002_non_snapshot_current_raises_type_error() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE)
    with pytest.raises(TypeError):
        compare_snapshots(baseline, {})  # type: ignore[arg-type]


def test_t_wp10_003_wrong_baseline_role_raises() -> None:
    with pytest.raises(InvalidDiffInputError):
        compare_snapshots(
            _snapshot(SnapshotKind.CURRENT), _snapshot(SnapshotKind.CURRENT)
        )


def test_t_wp10_004_wrong_current_role_raises() -> None:
    with pytest.raises(InvalidDiffInputError):
        compare_snapshots(
            _snapshot(SnapshotKind.BASELINE), _snapshot(SnapshotKind.BASELINE)
        )


def test_t_wp10_005_unsupported_baseline_schema_raises() -> None:
    with pytest.raises(DiffSchemaMismatchError):
        compare_snapshots(
            _snapshot(SnapshotKind.BASELINE, schema_version="other"),
            _snapshot(SnapshotKind.CURRENT),
        )


def test_t_wp10_006_unsupported_current_schema_raises() -> None:
    with pytest.raises(DiffSchemaMismatchError):
        compare_snapshots(
            _snapshot(SnapshotKind.BASELINE),
            _snapshot(SnapshotKind.CURRENT, schema_version="other"),
        )


def test_t_wp10_007_tool_version_difference_is_ignored() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, tool_version="0.1.0")
    current = _snapshot(SnapshotKind.CURRENT, tool_version="9.9.9")
    assert compare_snapshots(baseline, current).changes == ()


def test_t_wp10_008_matching_fingerprints_allow_hostname_case_difference() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, hostname="Host-A")
    current = _snapshot(SnapshotKind.CURRENT, hostname="HOST-A")
    assert compare_snapshots(baseline, current).status is ComparisonStatus.COMPLETE


def test_t_wp10_009_different_non_null_fingerprints_raise() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, machine_id="a" * 64)
    current = _snapshot(SnapshotKind.CURRENT, machine_id="b" * 64)
    with pytest.raises(HostMismatchError):
        compare_snapshots(baseline, current)


def test_t_wp10_010_both_missing_fingerprints_fall_back_casefolded_hostname() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, machine_id=None, hostname="Straße")
    current = _snapshot(SnapshotKind.CURRENT, machine_id=None, hostname="STRASSE")
    assert compare_snapshots(baseline, current).status is ComparisonStatus.COMPLETE


def test_t_wp10_011_one_missing_fingerprint_falls_back_to_hostname() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, machine_id="a" * 64, hostname="Host")
    current = _snapshot(SnapshotKind.CURRENT, machine_id=None, hostname="HOST")
    assert compare_snapshots(baseline, current).status is ComparisonStatus.COMPLETE


def test_t_wp10_012_fallback_hostname_mismatch_raises() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, machine_id=None, hostname="A")
    current = _snapshot(SnapshotKind.CURRENT, machine_id="a" * 64, hostname="B")
    with pytest.raises(HostMismatchError):
        compare_snapshots(baseline, current)


def test_t_wp10_013_os_metadata_differences_are_ignored() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE)
    current = _snapshot(
        SnapshotKind.CURRENT,
        os_name="Other",
        os_version="99",
        os_build="99999",
        architecture="ARM64",
    )
    assert compare_snapshots(baseline, current).changes == ()


def test_t_wp10_014_all_seven_covered_is_complete() -> None:
    baseline, current = _pair()
    result = compare_snapshots(baseline, current)
    assert result.status is ComparisonStatus.COMPLETE
    assert result.compared_domains == ALL_DOMAINS
    assert result.skipped_domains == ()


def test_t_wp10_015_missing_current_coverage_skips_exact_domain() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE)
    current = _snapshot(
        SnapshotKind.CURRENT,
        users_coverage=frozenset({"administrators"}),
    )
    result = compare_snapshots(baseline, current)
    assert result.status is ComparisonStatus.PARTIAL
    assert result.skipped_domains == ("users.local_users",)


def test_t_wp10_016_missing_baseline_coverage_skips_exact_domain() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        defender_coverage=frozenset({"configuration", "runtime"}),
    )
    current = _snapshot(SnapshotKind.CURRENT)
    result = compare_snapshots(baseline, current)
    assert result.skipped_domains == ("defender.exclusions",)


def test_t_wp10_017_diagnostic_data_without_coverage_is_ignored() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        tasks_coverage=frozenset(),
        tasks=tuple(_task(f"task-{index}") for index in range(200)),
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        tasks_coverage=frozenset(),
        tasks=tuple(_task(f"task-{index}") for index in range(5)),
    )
    result = compare_snapshots(baseline, current)
    assert "tasks.tasks" in result.skipped_domains
    assert [change for change in result.changes if change.domain == "tasks.tasks"] == []


def test_t_wp10_018_partial_collector_can_compare_covered_subsection() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        users_status=CollectorStatus.PARTIAL,
        users_coverage=frozenset({"local_users"}),
        local_users=(_user(),),
        administrators=None,
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        users_status=CollectorStatus.PARTIAL,
        users_coverage=frozenset({"local_users"}),
        local_users=(_user(enabled=False),),
        administrators=None,
    )
    result = compare_snapshots(baseline, current)
    assert "users.local_users" in result.compared_domains
    assert result.changes[0].property == "enabled"


def test_t_wp10_019_covered_empty_sequences_are_valid() -> None:
    baseline, current = _pair()
    result = compare_snapshots(baseline, current)
    assert result.status is ComparisonStatus.COMPLETE


def test_t_wp10_020_empty_baseline_to_populated_current_is_added() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, local_users=())
    current = _snapshot(SnapshotKind.CURRENT, local_users=(_user(),))
    changes = compare_snapshots(baseline, current).changes
    assert len(changes) == 1
    assert changes[0].change_type is ChangeType.ADDED


def test_t_wp10_021_populated_baseline_to_empty_current_is_removed() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, services=(_service(),))
    current = _snapshot(SnapshotKind.CURRENT, services=())
    changes = compare_snapshots(baseline, current).changes
    assert len(changes) == 1
    assert changes[0].change_type is ChangeType.REMOVED


def test_t_wp10_022_local_user_added() -> None:
    result = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE),
        _snapshot(SnapshotKind.CURRENT, local_users=(_user(),)),
    )
    change = result.changes[0]
    assert (change.domain, change.object_type, change.object_id) == (
        "users.local_users",
        "local_user",
        "S-1-5-21-1000",
    )


def test_t_wp10_023_local_user_removed() -> None:
    result = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE, local_users=(_user(),)),
        _snapshot(SnapshotKind.CURRENT),
    )
    assert result.changes[0].change_type is ChangeType.REMOVED


def test_t_wp10_024_local_user_enabled_modified() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, local_users=(_user(enabled=True),))
    current = _snapshot(SnapshotKind.CURRENT, local_users=(_user(enabled=False),))
    change = compare_snapshots(baseline, current).changes[0]
    assert (change.property, change.old_value, change.new_value) == (
        "enabled",
        True,
        False,
    )


def test_t_wp10_025_user_name_and_source_are_separate_changes() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, local_users=(_user(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        local_users=(
            _user(name="Alice Renamed", principal_source=PrincipalSource.UNKNOWN),
        ),
    )
    changes = compare_snapshots(baseline, current).changes
    assert [change.property for change in changes] == ["name", "principal_source"]


def test_t_wp10_026_administrator_sid_identity_drives_added_removed() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        administrators=(_admin("S-1-A", name="same"),),
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        administrators=(_admin("S-1-B", name="same"),),
    )
    changes = compare_snapshots(baseline, current).changes
    assert {change.object_id for change in changes} == {"S-1-A", "S-1-B"}
    assert {change.change_type for change in changes} == {
        ChangeType.ADDED,
        ChangeType.REMOVED,
    }


def test_t_wp10_027_administrator_properties_modify_separately() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, administrators=(_admin(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        administrators=(
            _admin(
                name="Admin2",
                object_class="Group",
                principal_source=PrincipalSource.UNKNOWN,
            ),
        ),
    )
    changes = compare_snapshots(baseline, current).changes
    assert [change.property for change in changes] == [
        "name",
        "object_class",
        "principal_source",
    ]


def test_t_wp10_028_service_normalized_id_drives_added_removed() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        services=(_service("svc-a", name="Same"),),
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        services=(_service("svc-b", name="Same"),),
    )
    changes = compare_snapshots(baseline, current).changes
    assert {change.object_id for change in changes} == {"svc-a", "svc-b"}


def test_t_wp10_029_service_path_and_account_are_two_changes() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, services=(_service(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        services=(_service(path_name="D:/svc.exe", start_name="User"),),
    )
    changes = compare_snapshots(baseline, current).changes
    assert [change.property for change in changes] == ["path_name", "start_name"]


def test_t_wp10_030_service_display_start_mode_and_name_case_are_changes() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, services=(_service(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        services=(
            _service(
                name="SPOOLER",
                display_name="Other",
                start_mode=ServiceStartMode.DISABLED,
            ),
        ),
    )
    changes = compare_snapshots(baseline, current).changes
    assert [change.property for change in changes] == [
        "display_name",
        "name",
        "start_mode",
    ]


def test_t_wp10_031_task_normalized_id_drives_added_removed() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, tasks=(_task("task-a"),))
    current = _snapshot(SnapshotKind.CURRENT, tasks=(_task("task-b"),))
    changes = compare_snapshots(baseline, current).changes
    assert {change.object_id for change in changes} == {"task-a", "task-b"}


def test_t_wp10_032_task_actions_change_is_one_property_change() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, tasks=(_task(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        tasks=(_task(actions=(TaskAction("Exec", "<Exec>B</Exec>"),)),),
    )
    changes = compare_snapshots(baseline, current).changes
    assert len(changes) == 1
    assert changes[0].property == "actions"


def test_t_wp10_033_task_principals_change_is_one_property_change() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, tasks=(_task(),))
    principal = TaskPrincipal("principal-1", "User", None, "Password", "LeastPrivilege")
    current = _snapshot(SnapshotKind.CURRENT, tasks=(_task(principals=(principal,)),))
    changes = compare_snapshots(baseline, current).changes
    assert len(changes) == 1
    assert changes[0].property == "principals"


def test_t_wp10_034_task_triggers_change_is_one_property_change() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, tasks=(_task(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        tasks=(_task(triggers=(TaskTrigger("Logon", "<Logon/>"),)),),
    )
    changes = compare_snapshots(baseline, current).changes
    assert len(changes) == 1
    assert changes[0].property == "triggers"


def test_t_wp10_035_task_structured_values_are_primitive_lists_and_mappings() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, tasks=(_task(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        tasks=(_task(actions=(TaskAction("Exec", "<Exec>B</Exec>"),)),),
    )
    change = compare_snapshots(baseline, current).changes[0]
    _assert_primitives(change.old_value)
    _assert_primitives(change.new_value)
    assert isinstance(change.old_value, list)


def test_t_wp10_036_defender_exclusion_id_drives_added_removed() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        exclusions=(_exclusion("path:a", value="A"),),
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        exclusions=(_exclusion("path:b", value="A"),),
    )
    changes = compare_snapshots(baseline, current).changes
    assert {change.object_id for change in changes} == {"path:a", "path:b"}


def test_t_wp10_037_defender_configuration_boolean_modified() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        configuration=DefenderConfiguration("microsoft_defender", False),
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        configuration=DefenderConfiguration("microsoft_defender", True),
    )
    change = compare_snapshots(baseline, current).changes[0]
    assert change.property == "disable_realtime_monitoring"
    assert change.object_name == "Microsoft Defender configuration"


def test_t_wp10_038_defender_runtime_boolean_modified() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        runtime=DefenderRuntime("microsoft_defender", True),
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        runtime=DefenderRuntime("microsoft_defender", False),
    )
    change = compare_snapshots(baseline, current).changes[0]
    assert change.property == "real_time_protection_enabled"
    assert change.object_name == "Microsoft Defender runtime"


def test_t_wp10_039_added_contract_contains_complete_new_mapping() -> None:
    current_user = _user()
    change = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE),
        _snapshot(SnapshotKind.CURRENT, local_users=(current_user,)),
    ).changes[0]
    assert change.property is None
    assert change.old_value is None
    assert change.new_value == {
        "id": current_user.id,
        "name": current_user.name,
        "enabled": current_user.enabled,
        "principal_source": "local",
    }


def test_t_wp10_040_removed_contract_contains_complete_old_mapping() -> None:
    baseline_service = _service()
    change = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE, services=(baseline_service,)),
        _snapshot(SnapshotKind.CURRENT),
    ).changes[0]
    assert change.property is None
    assert change.old_value == {
        "id": "spooler",
        "name": "Spooler",
        "display_name": "Print Spooler",
        "start_mode": "auto",
        "path_name": r"C:\Windows\System32\spoolsv.exe",
        "start_name": "LocalSystem",
    }
    assert change.new_value is None


def test_t_wp10_041_modified_scalar_contract_is_one_property() -> None:
    change = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE, local_users=(_user(enabled=True),)),
        _snapshot(SnapshotKind.CURRENT, local_users=(_user(enabled=False),)),
    ).changes[0]
    assert change.property == "enabled"
    assert type(change.old_value) is bool
    assert type(change.new_value) is bool


def test_t_wp10_042_id_is_never_modified_property() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, services=(_service("a"),))
    current = _snapshot(SnapshotKind.CURRENT, services=(_service("b"),))
    changes = compare_snapshots(baseline, current).changes
    assert all(change.property != "id" for change in changes)


def test_t_wp10_043_enums_become_canonical_string_values() -> None:
    change = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE),
        _snapshot(SnapshotKind.CURRENT, exclusions=(_exclusion(),)),
    ).changes[0]
    assert isinstance(change.new_value, dict)
    assert change.new_value["kind"] == "path"
    assert not isinstance(change.new_value["kind"], Enum)


def test_t_wp10_044_dataclass_resources_never_appear_in_values() -> None:
    change = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE),
        _snapshot(SnapshotKind.CURRENT, tasks=(_task(),)),
    ).changes[0]
    _assert_primitives(change.new_value)


def test_t_wp10_045_scalar_change_id_matches_independent_digest() -> None:
    change = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE, local_users=(_user(enabled=True),)),
        _snapshot(SnapshotKind.CURRENT, local_users=(_user(enabled=False),)),
    ).changes[0]
    assert change.change_id == _independent_digest(change)
    assert len(change.change_id) == 64
    assert change.change_id == change.change_id.lower()


def test_t_wp10_046_structured_change_id_matches_independent_digest() -> None:
    change = compare_snapshots(
        _snapshot(SnapshotKind.BASELINE, tasks=(_task(),)),
        _snapshot(
            SnapshotKind.CURRENT,
            tasks=(_task(actions=(TaskAction("Exec", "<Exec>B</Exec>"),)),),
        ),
    ).changes[0]
    assert change.change_id == _independent_digest(change)


def test_t_wp10_047_timestamps_do_not_affect_change_id() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, local_users=(_user(enabled=True),))
    current_a = _snapshot(
        SnapshotKind.CURRENT,
        local_users=(_user(enabled=False),),
        timestamp=datetime(2026, 8, 26, 13, 0, tzinfo=timezone.utc),
    )
    current_b = replace(
        current_a,
        collected_at_utc=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert compare_snapshots(baseline, current_a).changes[0].change_id == (
        compare_snapshots(baseline, current_b).changes[0].change_id
    )


def test_t_wp10_048_tool_versions_do_not_affect_change_id() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, services=(_service(),))
    current_a = _snapshot(
        SnapshotKind.CURRENT,
        services=(_service(start_name="User"),),
        tool_version="1",
    )
    current_b = replace(current_a, tool_version="2")
    assert compare_snapshots(baseline, current_a).changes[0].change_id == (
        compare_snapshots(baseline, current_b).changes[0].change_id
    )


def test_t_wp10_049_object_name_is_not_part_of_change_id() -> None:
    kwargs = {
        "domain": "users.local_users",
        "object_type": "local_user",
        "object_id": "S-1",
        "change_type": ChangeType.MODIFIED,
        "property_name": "enabled",
        "old_value": True,
        "new_value": False,
    }
    first = diff_module._make_change(  # type: ignore[arg-type]
        object_name="A", **kwargs
    )
    second = diff_module._make_change(  # type: ignore[arg-type]
        object_name="B", **kwargs
    )
    assert first.change_id == second.change_id


def test_t_wp10_050_mapping_insertion_order_does_not_affect_digest() -> None:
    first = diff_module._change_id(
        domain="d",
        object_id="o",
        change_type=ChangeType.MODIFIED,
        property_name="p",
        old_value={"a": "1", "b": "2"},
        new_value={"x": "3", "y": "4"},
    )
    second = diff_module._change_id(
        domain="d",
        object_id="o",
        change_type=ChangeType.MODIFIED,
        property_name="p",
        old_value={"b": "2", "a": "1"},
        new_value={"y": "4", "x": "3"},
    )
    assert first == second


def test_t_wp10_051_changes_sorted_by_frozen_sort_key() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        local_users=(_user("z", enabled=True),),
        services=(_service("b", start_name="A"),),
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        local_users=(_user("z", enabled=False), _user("a")),
        services=(_service("b", start_name="B"),),
        exclusions=(_exclusion("path:c"),),
    )
    changes = compare_snapshots(baseline, current).changes
    keys = [
        (
            change.domain,
            change.object_id,
            change.change_type.value,
            "" if change.property is None else change.property,
        )
        for change in changes
    ]
    assert keys == sorted(keys)


def test_t_wp10_052_resource_tuple_order_does_not_affect_change_order() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, local_users=())
    current_a = _snapshot(
        SnapshotKind.CURRENT,
        local_users=(_user("z"), _user("a"), _user("m")),
    )
    current_b = replace(
        current_a,
        collectors=replace(
            current_a.collectors,
            users=replace(
                current_a.collectors.users,
                data=replace(
                    current_a.collectors.users.data,
                    local_users=(_user("m"), _user("z"), _user("a")),
                ),
            ),
        ),
    )
    assert compare_snapshots(baseline, current_a).changes == compare_snapshots(
        baseline, current_b
    ).changes


def test_t_wp10_053_modified_properties_are_ordered_by_property() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, services=(_service(),))
    current = _snapshot(
        SnapshotKind.CURRENT,
        services=(_service(display_name="Z", start_name="X", path_name="Y"),),
    )
    properties = [
        change.property for change in compare_snapshots(baseline, current).changes
    ]
    assert properties == ["display_name", "path_name", "start_name"]


def test_t_wp10_054_duplicate_ids_in_covered_sequence_fail_closed() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        local_users=(_user("dup"), _user("dup", name="other")),
    )
    current = _snapshot(SnapshotKind.CURRENT)
    with pytest.raises(InvalidDiffInputError):
        compare_snapshots(baseline, current)


def test_t_wp10_055_covered_defender_configuration_none_fails_closed() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE)
    baseline = replace(
        baseline,
        collectors=replace(
            baseline.collectors,
            defender=replace(
                baseline.collectors.defender,
                data=replace(
                    baseline.collectors.defender.data,
                    configuration=None,
                ),
            ),
        ),
    )
    with pytest.raises(InvalidDiffInputError):
        compare_snapshots(baseline, _snapshot(SnapshotKind.CURRENT))


def test_t_wp10_056_covered_defender_runtime_none_fails_closed() -> None:
    current = _snapshot(SnapshotKind.CURRENT)
    current = replace(
        current,
        collectors=replace(
            current.collectors,
            defender=replace(
                current.collectors.defender,
                data=replace(current.collectors.defender.data, runtime=None),
            ),
        ),
    )
    with pytest.raises(InvalidDiffInputError):
        compare_snapshots(_snapshot(SnapshotKind.BASELINE), current)


def test_t_wp10_057_skipped_none_data_does_not_raise() -> None:
    baseline = _snapshot(
        SnapshotKind.BASELINE,
        tasks_status=CollectorStatus.FAILED,
        tasks_coverage=frozenset(),
        tasks=None,
    )
    current = _snapshot(
        SnapshotKind.CURRENT,
        tasks_status=CollectorStatus.PARTIAL,
        tasks_coverage=frozenset(),
        tasks=None,
    )
    result = compare_snapshots(baseline, current)
    assert "tasks.tasks" in result.skipped_domains


def test_covered_sequence_none_also_fails_closed() -> None:
    baseline = _snapshot(SnapshotKind.BASELINE, services=None)
    current = _snapshot(SnapshotKind.CURRENT, services=())
    with pytest.raises(InvalidDiffInputError):
        compare_snapshots(baseline, current)


def test_diff_error_codes_are_frozen_existing_codes() -> None:
    assert InvalidDiffInputError.code.value == "INVALID_SNAPSHOT"
    assert DiffSchemaMismatchError.code.value == "SCHEMA_MISMATCH"
    assert HostMismatchError.code.value == "HOST_MISMATCH"
