"""WP1 strict canonical snapshot validation tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import timezone
from typing import Any, Callable

import pytest

from driftape.models import CollectorStatus, Snapshot, SnapshotKind
from driftape.validation import SnapshotValidationError, validate_snapshot


def valid_snapshot(kind: str = "baseline") -> dict[str, Any]:
    return {
        "schema_version": "driftape.snapshot.v1",
        "tool_version": "0.1.0",
        "snapshot_kind": kind,
        "collected_at_utc": "2026-08-24T20:15:30Z",
        "host": {
            "hostname": "HOST01",
            "machine_id_sha256": "a" * 64,
            "os_name": "Windows 11",
            "os_version": "11",
            "os_build": "26200",
            "architecture": "AMD64",
        },
        "collection": {"is_elevated": True, "complete": True},
        "collectors": {
            "users": {
                "status": "success",
                "coverage": ["local_users", "administrators"],
                "data": {
                    "local_users": [
                        {
                            "id": "S-1-5-21-1000-1000-1000-1001",
                            "name": "ExampleUser",
                            "enabled": True,
                            "principal_source": "local",
                        }
                    ],
                    "administrators": [
                        {
                            "id": "S-1-5-32-544",
                            "name": "Administrators",
                            "object_class": "Group",
                            "principal_source": "local",
                        }
                    ],
                },
                "errors": [],
            },
            "services": {
                "status": "success",
                "coverage": ["services"],
                "data": {
                    "services": [
                        {
                            "id": "Example-Service",
                            "name": "Example-Service",
                            "display_name": "Example Service",
                            "start_mode": "auto",
                            "path_name": r"C:\Example\service.exe",
                            "start_name": "LocalSystem",
                        }
                    ]
                },
                "errors": [],
            },
            "tasks": {
                "status": "success",
                "coverage": ["tasks"],
                "data": {
                    "tasks": [
                        {
                            "id": r"\Example\BackupTask",
                            "task_path": "\\Example\\",
                            "task_name": "BackupTask",
                            "principals": [
                                {
                                    "id": "principal-1",
                                    "user_id": "SYSTEM",
                                    "group_id": None,
                                    "logon_type": "ServiceAccount",
                                    "run_level": "HighestAvailable",
                                }
                            ],
                            "actions": [
                                {
                                    "type": "Exec",
                                    "xml_c14n": (
                                        "<Exec><Command>backup.exe</Command></Exec>"
                                    ),
                                }
                            ],
                            "triggers": [
                                {
                                    "type": "CalendarTrigger",
                                    "xml_c14n": "<CalendarTrigger />",
                                }
                            ],
                        }
                    ]
                },
                "errors": [],
            },
            "defender": {
                "status": "success",
                "coverage": ["exclusions", "configuration", "runtime"],
                "data": {
                    "exclusions": [
                        {
                            "id": "path:C:\\Example",
                            "kind": "path",
                            "value": r"C:\Example",
                        }
                    ],
                    "configuration": {
                        "id": "microsoft_defender",
                        "disable_realtime_monitoring": False,
                    },
                    "runtime": {
                        "id": "microsoft_defender",
                        "real_time_protection_enabled": True,
                    },
                },
                "errors": [],
            },
        },
        "errors": [
            {
                "code": "ACCESS_DENIED",
                "scope": "collector.users.administrators",
                "operation": "Get-LocalGroupMember",
                "message": "Access was denied while collecting local administrators.",
                "native_code": None,
                "recoverable": True,
            }
        ],
    }


def expect_invalid(raw: dict[str, Any], path: str) -> SnapshotValidationError:
    with pytest.raises(SnapshotValidationError) as exc_info:
        validate_snapshot(raw)
    assert path in str(exc_info.value)
    assert exc_info.value.path
    assert exc_info.value.reason
    return exc_info.value


def test_complete_valid_baseline_snapshot_validates() -> None:
    """T-WP1-V-001: complete baseline mapping becomes a typed Snapshot."""
    result = validate_snapshot(valid_snapshot("baseline"))

    assert isinstance(result, Snapshot)
    assert result.snapshot_kind is SnapshotKind.BASELINE
    assert result.collection.complete is True
    assert result.collected_at_utc.tzinfo is timezone.utc
    assert isinstance(result.collectors.services.data.services, tuple)
    assert isinstance(result.collectors.users.coverage, frozenset)


def test_complete_valid_current_snapshot_validates() -> None:
    """T-WP1-V-002: current is the second valid snapshot kind."""
    result = validate_snapshot(valid_snapshot("current"))
    assert result.snapshot_kind is SnapshotKind.CURRENT


def test_valid_partial_users_collector_validates() -> None:
    """T-WP1-V-003: covered empty list is distinct from unavailable null."""
    raw = valid_snapshot()
    raw["collection"]["complete"] = False
    users = raw["collectors"]["users"]
    users["status"] = "partial"
    users["coverage"] = ["local_users"]
    users["data"]["local_users"] = []
    users["data"]["administrators"] = None

    result = validate_snapshot(raw)

    assert result.collectors.users.status is CollectorStatus.PARTIAL
    assert result.collectors.users.coverage == frozenset({"local_users"})
    assert result.collectors.users.data.local_users == ()
    assert result.collectors.users.data.administrators is None


def test_valid_failed_collector_with_empty_coverage() -> None:
    """T-WP1-V-004: failed collector claims no complete logical sections."""
    raw = valid_snapshot()
    raw["collection"]["complete"] = False
    services = raw["collectors"]["services"]
    services["status"] = "failed"
    services["coverage"] = []
    services["data"]["services"] = None

    result = validate_snapshot(raw)

    assert result.collectors.services.status is CollectorStatus.FAILED
    assert result.collectors.services.coverage == frozenset()
    assert result.collectors.services.data.services is None


def test_empty_successfully_collected_resource_lists_validate() -> None:
    """T-WP1-V-005: empty tuple represents successful zero-result collection."""
    raw = valid_snapshot()
    raw["collectors"]["users"]["data"]["local_users"] = []
    raw["collectors"]["users"]["data"]["administrators"] = []
    raw["collectors"]["services"]["data"]["services"] = []
    raw["collectors"]["tasks"]["data"]["tasks"] = []
    raw["collectors"]["defender"]["data"]["exclusions"] = []

    result = validate_snapshot(raw)

    assert result.collectors.users.data.local_users == ()
    assert result.collectors.users.data.administrators == ()
    assert result.collectors.services.data.services == ()
    assert result.collectors.tasks.data.tasks == ()
    assert result.collectors.defender.data.exclusions == ()


@pytest.mark.parametrize(
    ("mutation", "path"),
    [
        (lambda raw: raw.pop("schema_version"), "schema_version"),
        (
            lambda raw: raw.__setitem__(
                "schema_version", "driftape.snapshot.v2"
            ),
            "schema_version",
        ),
        (lambda raw: raw.__setitem__("schema_version", 1), "schema_version"),
        (lambda raw: raw.pop("tool_version"), "tool_version"),
        (lambda raw: raw.__setitem__("extra", True), "extra"),
        (lambda raw: raw.__setitem__("snapshot_kind", "golden"), "snapshot_kind"),
        (
            lambda raw: raw.__setitem__("collected_at_utc", "2026-08-24"),
            "collected_at_utc",
        ),
        (
            lambda raw: raw.__setitem__(
                "collected_at_utc", "2026-08-24T20:15:30+00:00"
            ),
            "collected_at_utc",
        ),
        (
            lambda raw: raw.__setitem__("collected_at_utc", "2026-08-24T20:15:30.123Z"),
            "collected_at_utc",
        ),
    ],
)
def test_snapshot_schema_and_root_rejections(
    mutation: Callable[[dict[str, Any]], object], path: str
) -> None:
    raw = valid_snapshot()
    mutation(raw)
    expect_invalid(raw, path)


@pytest.mark.parametrize(
    ("mutation", "path"),
    [
        (lambda raw: raw["host"].__setitem__("hostname", ""), "host.hostname"),
        (lambda raw: raw["host"].__setitem__("hostname", " HOST01"), "host.hostname"),
        (
            lambda raw: raw["host"].__setitem__("machine_id_sha256", "a" * 63),
            "host.machine_id_sha256",
        ),
        (
            lambda raw: raw["host"].__setitem__("machine_id_sha256", "A" * 64),
            "host.machine_id_sha256",
        ),
        (
            lambda raw: raw["host"].__setitem__("machine_id_sha256", "g" * 64),
            "host.machine_id_sha256",
        ),
        (lambda raw: raw["host"].pop("os_name"), "host.os_name"),
        (lambda raw: raw["host"].__setitem__("future", "x"), "host.future"),
    ],
)
def test_host_rejections(
    mutation: Callable[[dict[str, Any]], object], path: str
) -> None:
    raw = valid_snapshot()
    mutation(raw)
    expect_invalid(raw, path)


@pytest.mark.parametrize(
    ("mutation", "path"),
    [
        (
            lambda raw: raw["collectors"]["users"].__setitem__("status", "unknown"),
            "collectors.users.status",
        ),
        (
            lambda raw: raw["collectors"]["users"].__setitem__(
                "coverage", ["local_users", "bogus"]
            ),
            "collectors.users.coverage",
        ),
        (
            lambda raw: raw["collectors"]["users"].__setitem__(
                "coverage", ["local_users"]
            ),
            "collectors.users.coverage",
        ),
        (
            lambda raw: (
                raw["collectors"]["services"].__setitem__("status", "failed"),
                raw["collectors"]["services"].__setitem__("coverage", ["services"]),
            ),
            "collectors.services.coverage",
        ),
        (
            lambda raw: (
                raw["collectors"]["tasks"].__setitem__("status", "partial"),
                raw["collectors"]["tasks"].__setitem__("coverage", ["tasks"]),
            ),
            "collectors.tasks.coverage",
        ),
        (
            lambda raw: raw["collectors"]["services"]["data"].__setitem__(
                "services", None
            ),
            "collectors.services.data.services",
        ),
        (
            lambda raw: raw["collectors"]["defender"].__setitem__("extra", True),
            "collectors.defender.extra",
        ),
    ],
)
def test_collector_envelope_rejections(
    mutation: Callable[[dict[str, Any]], object], path: str
) -> None:
    raw = valid_snapshot()
    mutation(raw)
    expect_invalid(raw, path)


def test_partial_may_have_empty_coverage_and_diagnostic_data() -> None:
    raw = valid_snapshot()
    raw["collection"]["complete"] = False
    users = raw["collectors"]["users"]
    users["status"] = "partial"
    users["coverage"] = []

    result = validate_snapshot(raw)

    assert result.collectors.users.status is CollectorStatus.PARTIAL
    assert result.collectors.users.coverage == frozenset()
    assert result.collectors.users.data.local_users is not None


def test_noncovered_data_is_not_required_to_be_null() -> None:
    raw = valid_snapshot()
    raw["collection"]["complete"] = False
    users = raw["collectors"]["users"]
    users["status"] = "partial"
    users["coverage"] = ["local_users"]

    result = validate_snapshot(raw)

    assert result.collectors.users.data.administrators is not None


@pytest.mark.parametrize(
    ("collection_path", "duplicate_path"),
    [
        (
            ("collectors", "users", "data", "local_users"),
            "collectors.users.data.local_users[1].id",
        ),
        (
            ("collectors", "users", "data", "administrators"),
            "collectors.users.data.administrators[1].id",
        ),
        (
            ("collectors", "services", "data", "services"),
            "collectors.services.data.services[1].id",
        ),
        (
            ("collectors", "tasks", "data", "tasks"),
            "collectors.tasks.data.tasks[1].id",
        ),
        (
            ("collectors", "defender", "data", "exclusions"),
            "collectors.defender.data.exclusions[1].id",
        ),
    ],
)
def test_duplicate_stable_ids_rejected(
    collection_path: tuple[str, ...], duplicate_path: str
) -> None:
    raw = valid_snapshot()
    target: Any = raw
    for component in collection_path:
        target = target[component]
    target.append(deepcopy(target[0]))

    expect_invalid(raw, duplicate_path)


def test_duplicate_task_principal_id_rejected() -> None:
    raw = valid_snapshot()
    principals = raw["collectors"]["tasks"]["data"]["tasks"][0]["principals"]
    principals.append(deepcopy(principals[0]))

    expect_invalid(raw, "collectors.tasks.data.tasks[0].principals[1].id")


@pytest.mark.parametrize(
    ("mutation", "path"),
    [
        (
            lambda raw: raw["collectors"]["users"]["data"]["local_users"][
                0
            ].__setitem__("name", True),
            "collectors.users.data.local_users[0].name",
        ),
        (
            lambda raw: raw["collection"].__setitem__("is_elevated", "true"),
            "collection.is_elevated",
        ),
        (
            lambda raw: raw["collection"].__setitem__("complete", 1),
            "collection.complete",
        ),
        (lambda raw: raw.__setitem__("host", []), "host"),
        (
            lambda raw: raw["collectors"]["services"]["data"].__setitem__(
                "services", {"id": "not-an-array"}
            ),
            "collectors.services.data.services",
        ),
        (
            lambda raw: raw["errors"][0].__setitem__("native_code", True),
            "errors[0].native_code",
        ),
    ],
)
def test_scalar_and_container_type_strictness(
    mutation: Callable[[dict[str, Any]], object], path: str
) -> None:
    raw = valid_snapshot()
    mutation(raw)
    expect_invalid(raw, path)


def test_native_code_accepts_exact_string_integer_and_null() -> None:
    for native_code in (None, "0x5", 5):
        raw = valid_snapshot()
        raw["errors"][0]["native_code"] = native_code
        assert validate_snapshot(raw).errors[0].native_code == native_code


@pytest.mark.parametrize(
    ("mutation", "path"),
    [
        (
            lambda raw: raw["collectors"]["defender"]["data"][
                "configuration"
            ].__setitem__("id", "other"),
            "collectors.defender.data.configuration.id",
        ),
        (
            lambda raw: raw["collectors"]["defender"]["data"]["runtime"].__setitem__(
                "id", "other"
            ),
            "collectors.defender.data.runtime.id",
        ),
        (
            lambda raw: raw["collectors"]["defender"]["data"]["exclusions"][
                0
            ].__setitem__("kind", "registry"),
            "collectors.defender.data.exclusions[0].kind",
        ),
    ],
)
def test_defender_rejections(
    mutation: Callable[[dict[str, Any]], object], path: str
) -> None:
    raw = valid_snapshot()
    mutation(raw)
    expect_invalid(raw, path)


@pytest.mark.parametrize("status", ["partial", "failed"])
def test_complete_true_rejects_non_success_collector(status: str) -> None:
    raw = valid_snapshot()
    services = raw["collectors"]["services"]
    services["status"] = status
    services["coverage"] = []
    services["data"]["services"] = None

    expect_invalid(raw, "collection.complete")


def test_all_success_collectors_may_have_complete_false() -> None:
    raw = valid_snapshot()
    raw["collection"]["complete"] = False

    assert validate_snapshot(raw).collection.complete is False


def test_unknown_fields_rejected_recursively() -> None:
    raw = valid_snapshot()
    raw["collectors"]["users"]["data"]["local_users"][0]["enabledd"] = False

    expect_invalid(raw, "collectors.users.data.local_users[0].enabledd")


def test_missing_nested_mandatory_field_reports_path() -> None:
    raw = valid_snapshot()
    raw["collectors"]["tasks"]["data"]["tasks"][0]["actions"][0].pop("xml_c14n")

    expect_invalid(raw, "collectors.tasks.data.tasks[0].actions[0].xml_c14n")


def test_useful_nested_action_error_path() -> None:
    raw = valid_snapshot()
    actions = raw["collectors"]["tasks"]["data"]["tasks"][0]["actions"]
    actions.append({"type": "Exec", "xml_c14n": ""})

    expect_invalid(raw, "collectors.tasks.data.tasks[0].actions[1].xml_c14n")


def test_empty_and_nullable_service_display_and_source_fields_validate() -> None:
    raw = valid_snapshot()
    service = raw["collectors"]["services"]["data"]["services"][0]
    service["display_name"] = ""
    service["path_name"] = ""
    service["start_name"] = None

    result = validate_snapshot(raw)
    parsed = result.collectors.services.data.services
    assert parsed is not None
    assert parsed[0].display_name == ""
    assert parsed[0].path_name == ""
    assert parsed[0].start_name is None


def test_machine_id_sha256_null_validates() -> None:
    raw = valid_snapshot()
    raw["host"]["machine_id_sha256"] = None

    assert validate_snapshot(raw).host.machine_id_sha256 is None


def test_task_principal_may_lack_user_and_group_ids() -> None:
    raw = valid_snapshot()
    principal = raw["collectors"]["tasks"]["data"]["tasks"][0]["principals"][0]
    principal["user_id"] = None
    principal["group_id"] = None

    result = validate_snapshot(raw)
    tasks = result.collectors.tasks.data.tasks
    assert tasks is not None
    assert tasks[0].principals[0].user_id is None
    assert tasks[0].principals[0].group_id is None


def test_partial_defender_allows_unavailable_subsection() -> None:
    raw = valid_snapshot()
    raw["collection"]["complete"] = False
    defender = raw["collectors"]["defender"]
    defender["status"] = "partial"
    defender["coverage"] = ["exclusions", "configuration"]
    defender["data"]["runtime"] = None

    result = validate_snapshot(raw)
    assert result.collectors.defender.status is CollectorStatus.PARTIAL
    assert result.collectors.defender.data.runtime is None


@pytest.mark.parametrize(
    ("field", "value", "path"),
    [
        ("code", "NOT_A_CODE", "errors[0].code"),
        ("scope", "", "errors[0].scope"),
        ("operation", "", "errors[0].operation"),
        ("message", "", "errors[0].message"),
        ("recoverable", 1, "errors[0].recoverable"),
    ],
)
def test_structured_error_contract_rejections(
    field: str, value: object, path: str
) -> None:
    raw = valid_snapshot()
    raw["errors"][0][field] = value

    expect_invalid(raw, path)


def test_empty_tool_version_rejected() -> None:
    raw = valid_snapshot()
    raw["tool_version"] = ""

    expect_invalid(raw, "tool_version")
