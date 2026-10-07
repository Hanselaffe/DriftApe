"""WP2 canonical snapshot serialization tests."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import pytest

from driftape.models import SnapshotKind
from driftape.serialization import (
    SnapshotSerializationError,
    serialize_snapshot,
    snapshot_to_mapping,
)
from driftape.validation import validate_snapshot


def complete_mapping(kind: str = "baseline") -> dict[str, Any]:
    return {
        "schema_version": "driftape.snapshot.v1",
        "tool_version": "0.1.0",
        "snapshot_kind": kind,
        "collected_at_utc": "2026-08-25T10:15:30Z",
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
                "coverage": ["administrators", "local_users"],
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
                            "path_name": r"C:\Program Files\Example\service.exe",
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
                "coverage": ["configuration", "exclusions", "runtime"],
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


def partial_mapping() -> dict[str, Any]:
    raw = complete_mapping("current")
    raw["collection"] = {"is_elevated": False, "complete": False}
    raw["host"]["machine_id_sha256"] = None

    raw["collectors"]["users"] = {
        "status": "partial",
        "coverage": ["local_users"],
        "data": {"local_users": [], "administrators": None},
        "errors": [],
    }
    raw["collectors"]["services"] = {
        "status": "failed",
        "coverage": [],
        "data": {"services": None},
        "errors": [],
    }
    raw["collectors"]["tasks"] = {
        "status": "success",
        "coverage": ["tasks"],
        "data": {"tasks": []},
        "errors": [],
    }
    raw["collectors"]["defender"] = {
        "status": "partial",
        "coverage": ["configuration"],
        "data": {
            "exclusions": None,
            "configuration": {
                "id": "microsoft_defender",
                "disable_realtime_monitoring": False,
            },
            "runtime": None,
        },
        "errors": [],
    }
    raw["errors"] = []
    return raw


def _snapshot(kind: str = "baseline"):
    return validate_snapshot(complete_mapping(kind))


def _assert_json_primitives(value: object) -> None:
    if value is None or type(value) in {str, int, bool}:
        return
    if isinstance(value, list):
        for item in value:
            _assert_json_primitives(item)
        return
    if isinstance(value, dict):
        assert all(isinstance(key, str) for key in value)
        for item in value.values():
            _assert_json_primitives(item)
        return
    pytest.fail(f"non-JSON primitive leaked into mapping: {type(value)!r}")


def test_complete_baseline_snapshot_exact_mapping() -> None:
    """T-WP2-001: complete baseline becomes exact primitive mapping."""
    expected = complete_mapping("baseline")
    assert snapshot_to_mapping(validate_snapshot(expected)) == expected


def test_complete_current_snapshot_mapping() -> None:
    """T-WP2-002: complete current snapshot maps correctly."""
    expected = complete_mapping("current")
    assert snapshot_to_mapping(validate_snapshot(expected)) == expected


def test_snapshot_kind_uses_enum_value() -> None:
    """T-WP2-003: SnapshotKind is persisted via its canonical value."""
    snapshot = _snapshot()
    mapping = snapshot_to_mapping(snapshot)
    assert snapshot.snapshot_kind is SnapshotKind.BASELINE
    assert mapping["snapshot_kind"] == "baseline"
    assert not isinstance(mapping["snapshot_kind"], Enum)


def test_timestamp_exact_z_format() -> None:
    """T-WP2-004: timestamp is exact second-resolution UTC Z form."""
    assert snapshot_to_mapping(_snapshot())["collected_at_utc"] == (
        "2026-08-25T10:15:30Z"
    )


@pytest.mark.parametrize(
    ("year", "expected"),
    [
        (1, "0001-01-02T03:04:05Z"),
        (99, "0099-01-02T03:04:05Z"),
        (999, "0999-01-02T03:04:05Z"),
        (1000, "1000-01-02T03:04:05Z"),
        (2026, "2026-01-02T03:04:05Z"),
    ],
)
def test_timestamp_year_uses_exact_four_digit_width(
    year: int, expected: str
) -> None:
    """WP2 R2: public mapping path emits an exact four-digit year."""
    snapshot = replace(
        _snapshot(),
        collected_at_utc=datetime(year, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    assert snapshot_to_mapping(snapshot)["collected_at_utc"] == expected


def test_year_0001_round_trips_through_wp1_validator_and_canonical_bytes() -> None:
    """WP2 R2: repair the exact Master-reported year-0001 failure."""
    raw = complete_mapping()
    raw["collected_at_utc"] = "0001-01-02T03:04:05Z"

    snapshot = validate_snapshot(raw)
    mapping = snapshot_to_mapping(snapshot)
    serialized = serialize_snapshot(snapshot)

    assert mapping["collected_at_utc"] == "0001-01-02T03:04:05Z"
    assert validate_snapshot(mapping) == snapshot
    assert b'"collected_at_utc":"0001-01-02T03:04:05Z"' in serialized


def test_output_is_valid_utf8() -> None:
    """T-WP2-005: canonical bytes decode as UTF-8."""
    serialize_snapshot(_snapshot()).decode("utf-8")


def test_output_has_no_utf8_bom() -> None:
    """T-WP2-006: canonical bytes contain no UTF-8 BOM."""
    assert not serialize_snapshot(_snapshot()).startswith(b"\xef\xbb\xbf")


def test_output_ends_in_exactly_one_lf() -> None:
    """T-WP2-007: output terminates with exactly one LF."""
    result = serialize_snapshot(_snapshot())
    assert result.endswith(b"\n")
    assert not result.endswith(b"\n\n")


def test_output_contains_no_crlf() -> None:
    """T-WP2-008: canonical output is platform-independent LF only."""
    assert b"\r\n" not in serialize_snapshot(_snapshot())


def test_output_uses_compact_json_separators() -> None:
    """T-WP2-009: canonical JSON contains no encoder-added spaces."""
    result = serialize_snapshot(_snapshot())
    assert b'": ' not in result
    assert b", " not in result


def test_output_object_keys_are_sorted() -> None:
    """T-WP2-010: output is exactly Python canonical sorted-key JSON."""
    snapshot = _snapshot()
    expected = (
        json.dumps(
            snapshot_to_mapping(snapshot),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    assert serialize_snapshot(snapshot) == expected
    assert serialize_snapshot(snapshot).startswith(b'{"collected_at_utc":')


def test_repeated_serialization_is_byte_identical() -> None:
    """T-WP2-011: same Snapshot produces identical bytes repeatedly."""
    snapshot = _snapshot()
    assert serialize_snapshot(snapshot) == serialize_snapshot(snapshot)


def test_unicode_is_emitted_as_utf8_not_unicode_escape() -> None:
    """T-WP2-012: non-ASCII text remains direct UTF-8."""
    raw = complete_mapping()
    raw["collectors"]["services"]["data"]["services"][0]["display_name"] = (
        "Überwachungsdienst"
    )
    result = serialize_snapshot(validate_snapshot(raw))
    assert "Überwachungsdienst".encode() in result
    assert b"\\u00dcberwachungsdienst" not in result


def test_coverage_frozenset_has_lexical_order() -> None:
    """T-WP2-013: coverage is deterministically lexically sorted."""
    mapping = snapshot_to_mapping(_snapshot())
    assert mapping["collectors"]["users"]["coverage"] == [
        "administrators",
        "local_users",
    ]


def test_none_users_subsection_serializes_as_null() -> None:
    """T-WP2-014: unavailable users subsection remains null."""
    mapping = snapshot_to_mapping(validate_snapshot(partial_mapping()))
    assert mapping["collectors"]["users"]["data"]["administrators"] is None


def test_empty_tuple_serializes_as_empty_list() -> None:
    """T-WP2-015: successful zero-result tuple becomes []."""
    mapping = snapshot_to_mapping(validate_snapshot(partial_mapping()))
    assert mapping["collectors"]["users"]["data"]["local_users"] == []
    assert mapping["collectors"]["tasks"]["data"]["tasks"] == []


def test_nullable_service_members_remain_present_as_null() -> None:
    """T-WP2-016: nullable service path/account fields remain explicit."""
    raw = complete_mapping()
    service = raw["collectors"]["services"]["data"]["services"][0]
    service["path_name"] = None
    service["start_name"] = None
    mapped_service = snapshot_to_mapping(validate_snapshot(raw))["collectors"][
        "services"
    ]["data"]["services"][0]
    assert mapped_service["path_name"] is None
    assert mapped_service["start_name"] is None
    assert set(mapped_service) == {
        "id",
        "name",
        "display_name",
        "start_mode",
        "path_name",
        "start_name",
    }


def test_unavailable_defender_sections_remain_null() -> None:
    """T-WP2-017: unavailable Defender sections remain explicit null."""
    raw = partial_mapping()
    raw["collectors"]["defender"] = {
        "status": "failed",
        "coverage": [],
        "data": {"exclusions": None, "configuration": None, "runtime": None},
        "errors": [],
    }
    data = snapshot_to_mapping(validate_snapshot(raw))["collectors"]["defender"][
        "data"
    ]
    assert data == {"exclusions": None, "configuration": None, "runtime": None}


def test_task_principals_serialize_exactly() -> None:
    """T-WP2-018: task principals use the exact persisted schema."""
    principal = snapshot_to_mapping(_snapshot())["collectors"]["tasks"]["data"][
        "tasks"
    ][0]["principals"][0]
    assert principal == {
        "id": "principal-1",
        "user_id": "SYSTEM",
        "group_id": None,
        "logon_type": "ServiceAccount",
        "run_level": "HighestAvailable",
    }


def test_task_actions_serialize_exactly() -> None:
    """T-WP2-019: task actions use exact type/xml_c14n members."""
    action = snapshot_to_mapping(_snapshot())["collectors"]["tasks"]["data"][
        "tasks"
    ][0]["actions"][0]
    assert action == {
        "type": "Exec",
        "xml_c14n": "<Exec><Command>backup.exe</Command></Exec>",
    }


def test_task_triggers_serialize_exactly() -> None:
    """T-WP2-020: task triggers use exact type/xml_c14n members."""
    trigger = snapshot_to_mapping(_snapshot())["collectors"]["tasks"]["data"][
        "tasks"
    ][0]["triggers"][0]
    assert trigger == {"type": "CalendarTrigger", "xml_c14n": "<CalendarTrigger />"}


def test_task_nested_tuple_orders_are_preserved() -> None:
    """T-WP2-021: principal/action/trigger tuple ordering is unchanged."""
    raw = complete_mapping()
    task = raw["collectors"]["tasks"]["data"]["tasks"][0]
    task["principals"].append(
        {
            "id": "principal-2",
            "user_id": None,
            "group_id": "Administrators",
            "logon_type": None,
            "run_level": None,
        }
    )
    task["actions"].append({"type": "ComHandler", "xml_c14n": "<ComHandler />"})
    task["triggers"].append({"type": "BootTrigger", "xml_c14n": "<BootTrigger />"})
    mapped = snapshot_to_mapping(validate_snapshot(raw))["collectors"]["tasks"][
        "data"
    ]["tasks"][0]
    assert [item["id"] for item in mapped["principals"]] == [
        "principal-1",
        "principal-2",
    ]
    assert [item["type"] for item in mapped["actions"]] == ["Exec", "ComHandler"]
    assert [item["type"] for item in mapped["triggers"]] == [
        "CalendarTrigger",
        "BootTrigger",
    ]


def test_defender_exclusion_kind_uses_enum_value() -> None:
    """T-WP2-022: Defender exclusion kind persists canonical enum value."""
    exclusion = snapshot_to_mapping(_snapshot())["collectors"]["defender"]["data"][
        "exclusions"
    ][0]
    assert exclusion["kind"] == "path"
    assert not isinstance(exclusion["kind"], Enum)


def test_structured_error_semantics_are_preserved() -> None:
    """T-WP2-023: structured error code/native_code/recoverable are exact."""
    raw = complete_mapping()
    raw["errors"][0]["native_code"] = 5
    error = snapshot_to_mapping(validate_snapshot(raw))["errors"][0]
    assert error == {
        "code": "ACCESS_DENIED",
        "scope": "collector.users.administrators",
        "operation": "Get-LocalGroupMember",
        "message": "Access was denied while collecting local administrators.",
        "native_code": 5,
        "recoverable": True,
    }
    assert type(error["native_code"]) is int


def test_coverage_sorting_is_active_and_deterministic() -> None:
    """T-WP2-024: equivalent unordered coverage sources produce same bytes."""
    raw_a = complete_mapping()
    raw_b = deepcopy(raw_a)
    raw_a["collectors"]["users"]["coverage"] = list(
        {"local_users", "administrators"}
    )
    raw_b["collectors"]["users"]["coverage"] = list(
        {"administrators", "local_users"}
    )
    snapshot_a = validate_snapshot(raw_a)
    snapshot_b = validate_snapshot(raw_b)
    assert snapshot_a == snapshot_b
    assert serialize_snapshot(snapshot_a) == serialize_snapshot(snapshot_b)
    assert snapshot_to_mapping(snapshot_a)["collectors"]["users"]["coverage"] == [
        "administrators",
        "local_users",
    ]


def test_service_tuple_order_is_not_sorted() -> None:
    """T-WP2-025: service order remains model order B then A."""
    raw = complete_mapping()
    raw["collectors"]["services"]["data"]["services"] = [
        {
            "id": "B",
            "name": "B",
            "display_name": "Service B",
            "start_mode": "manual",
            "path_name": None,
            "start_name": None,
        },
        {
            "id": "A",
            "name": "A",
            "display_name": "Service A",
            "start_mode": "auto",
            "path_name": None,
            "start_name": None,
        },
    ]
    services = snapshot_to_mapping(validate_snapshot(raw))["collectors"]["services"][
        "data"
    ]["services"]
    assert [service["id"] for service in services] == ["B", "A"]


def test_task_action_order_is_not_sorted() -> None:
    """T-WP2-026: action order remains the normalized model order."""
    raw = complete_mapping()
    raw["collectors"]["tasks"]["data"]["tasks"][0]["actions"] = [
        {"type": "Zeta", "xml_c14n": "<Zeta />"},
        {"type": "Alpha", "xml_c14n": "<Alpha />"},
    ]
    actions = snapshot_to_mapping(validate_snapshot(raw))["collectors"]["tasks"][
        "data"
    ]["tasks"][0]["actions"]
    assert [action["type"] for action in actions] == ["Zeta", "Alpha"]


def test_non_utc_datetime_is_rejected() -> None:
    """T-WP2-027: non-UTC datetime cannot be serialized with Z."""
    snapshot = replace(
        _snapshot(),
        collected_at_utc=datetime(
            2026, 8, 25, 12, 15, 30, tzinfo=timezone(timedelta(hours=2))
        ),
    )
    with pytest.raises(SnapshotSerializationError, match="timezone-aware UTC"):
        serialize_snapshot(snapshot)


def test_datetime_with_microseconds_is_rejected() -> None:
    """T-WP2-028: non-zero microseconds are never silently truncated."""
    snapshot = replace(
        _snapshot(),
        collected_at_utc=datetime(2026, 8, 25, 10, 15, 30, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(SnapshotSerializationError, match="fractional seconds"):
        serialize_snapshot(snapshot)


def test_complete_mapping_round_trips_through_wp1_validator() -> None:
    """T-WP2-029: complete typed model mapping round-trips exactly."""
    snapshot = _snapshot()
    assert validate_snapshot(snapshot_to_mapping(snapshot)) == snapshot


def test_partial_mapping_round_trips_through_wp1_validator() -> None:
    """T-WP2-030: partial typed model mapping preserves null/empty semantics."""
    snapshot = validate_snapshot(partial_mapping())
    assert validate_snapshot(snapshot_to_mapping(snapshot)) == snapshot


def test_snapshot_to_mapping_contains_only_json_compatible_primitives() -> None:
    """AC-WP2-03: no Enum/datetime/tuple/frozenset/dataclass leaks."""
    _assert_json_primitives(snapshot_to_mapping(_snapshot()))


def test_root_and_collector_envelope_fields_are_exact() -> None:
    """AC-WP2-13/14: required root/envelope fields are explicit and exact."""
    mapping = snapshot_to_mapping(validate_snapshot(partial_mapping()))
    assert set(mapping) == {
        "schema_version",
        "tool_version",
        "snapshot_kind",
        "collected_at_utc",
        "host",
        "collection",
        "collectors",
        "errors",
    }
    assert set(mapping["collectors"]) == {"users", "services", "tasks", "defender"}
    for collector in mapping["collectors"].values():
        assert set(collector) == {"status", "coverage", "data", "errors"}
