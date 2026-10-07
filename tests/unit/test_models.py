"""WP1 canonical model tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone

import pytest

from driftape.models import (
    CollectionInfo,
    CollectorSet,
    CollectorStatus,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderData,
    DefenderExclusionKind,
    DefenderRuntime,
    ErrorCode,
    HostInfo,
    PrincipalSource,
    ServicesCollectorResult,
    ServicesData,
    ServiceStartMode,
    Snapshot,
    SnapshotKind,
    TasksCollectorResult,
    TasksData,
    UsersCollectorResult,
    UsersData,
)


def _empty_collectors() -> CollectorSet:
    return CollectorSet(
        users=UsersCollectorResult(
            status=CollectorStatus.SUCCESS,
            coverage=frozenset({"local_users", "administrators"}),
            data=UsersData(local_users=(), administrators=()),
            errors=(),
        ),
        services=ServicesCollectorResult(
            status=CollectorStatus.SUCCESS,
            coverage=frozenset({"services"}),
            data=ServicesData(services=()),
            errors=(),
        ),
        tasks=TasksCollectorResult(
            status=CollectorStatus.SUCCESS,
            coverage=frozenset({"tasks"}),
            data=TasksData(tasks=()),
            errors=(),
        ),
        defender=DefenderCollectorResult(
            status=CollectorStatus.SUCCESS,
            coverage=frozenset({"exclusions", "configuration", "runtime"}),
            data=DefenderData(
                exclusions=(),
                configuration=DefenderConfiguration(
                    id="microsoft_defender",
                    disable_realtime_monitoring=False,
                ),
                runtime=DefenderRuntime(
                    id="microsoft_defender",
                    real_time_protection_enabled=True,
                ),
            ),
            errors=(),
        ),
    )


def _snapshot() -> Snapshot:
    return Snapshot(
        schema_version="driftape.snapshot.v1",
        tool_version="0.1.0",
        snapshot_kind=SnapshotKind.BASELINE,
        collected_at_utc=datetime(2026, 8, 24, 20, 0, 0, tzinfo=timezone.utc),
        host=HostInfo(
            hostname="HOST01",
            machine_id_sha256="a" * 64,
            os_name="Windows 11",
            os_version="11",
            os_build="26200",
            architecture="AMD64",
        ),
        collection=CollectionInfo(is_elevated=True, complete=True),
        collectors=_empty_collectors(),
        errors=(),
    )


def test_frozen_value_equality_behavior() -> None:
    """T-WP1-M-001: canonical models are frozen and compare by value."""
    left = _snapshot()
    right = _snapshot()

    assert left == right
    with pytest.raises(FrozenInstanceError):
        left.schema_version = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("enum_type", "expected"),
    [
        (SnapshotKind, {"baseline", "current"}),
        (CollectorStatus, {"success", "partial", "failed"}),
        (
            PrincipalSource,
            {
                "local",
                "active_directory",
                "microsoft_entra",
                "microsoft_account",
                "unknown",
            },
        ),
        (
            ServiceStartMode,
            {"auto", "manual", "disabled", "boot", "system", "unknown"},
        ),
        (DefenderExclusionKind, {"path", "process", "extension", "ip_address"}),
        (
            ErrorCode,
            {
                "COLLECTOR_UNAVAILABLE",
                "ACCESS_DENIED",
                "COMMAND_FAILED",
                "COMMAND_TIMEOUT",
                "UNEXPECTED_OUTPUT",
                "UNSUPPORTED_OS",
                "INVALID_SNAPSHOT",
                "INVALID_MANIFEST",
                "SCHEMA_MISMATCH",
                "INTEGRITY_FAILURE",
                "HOST_MISMATCH",
                "IO_ERROR",
                "INTERNAL_ERROR",
            },
        ),
    ],
)
def test_enums_expose_exact_authorized_values(
    enum_type: type[object], expected: set[str]
) -> None:
    """T-WP1-M-002: enums expose no unauthorized public values."""
    actual = {member.value for member in enum_type}  # type: ignore[attr-defined]
    assert actual == expected


def test_canonical_nested_collection_types_are_immutable() -> None:
    """T-WP1-M-003: canonical sequences/coverage use tuples and frozensets."""
    collectors = _empty_collectors()

    assert isinstance(collectors.users.coverage, frozenset)
    assert isinstance(collectors.users.errors, tuple)
    assert isinstance(collectors.users.data.local_users, tuple)
    assert isinstance(collectors.services.data.services, tuple)
    assert isinstance(collectors.tasks.data.tasks, tuple)
    assert isinstance(collectors.defender.data.exclusions, tuple)


def test_snapshot_collector_set_has_exact_domains() -> None:
    """T-WP1-M-004: CollectorSet exposes exactly the frozen four domains."""
    assert tuple(field.name for field in fields(CollectorSet)) == (
        "users",
        "services",
        "tasks",
        "defender",
    )
