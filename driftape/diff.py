"""Typed, deterministic, coverage-aware snapshot comparison for DriftApe v0.1."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, TypeVar

from driftape.constants import SNAPSHOT_SCHEMA_VERSION
from driftape.models import (
    AdministratorMember,
    DefenderConfiguration,
    DefenderExclusion,
    DefenderRuntime,
    ErrorCode,
    LocalUser,
    ScheduledTaskInfo,
    ServiceInfo,
    Snapshot,
    SnapshotKind,
    TaskAction,
    TaskPrincipal,
    TaskTrigger,
)


class ChangeType(StrEnum):
    """Canonical neutral change kinds."""

    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"


class ComparisonStatus(StrEnum):
    """Overall completeness of a seven-domain comparison."""

    COMPLETE = "complete"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class Change:
    """One canonical neutral fact about snapshot drift."""

    change_id: str
    domain: str
    object_type: str
    object_id: str
    object_name: str
    change_type: ChangeType
    property: str | None
    old_value: object
    new_value: object


@dataclass(frozen=True, slots=True)
class DiffResult:
    """Deterministic result of comparing two compatible typed snapshots."""

    status: ComparisonStatus
    compared_domains: tuple[str, ...]
    skipped_domains: tuple[str, ...]
    changes: tuple[Change, ...]


class DiffError(RuntimeError):
    """Base class for comparison-layer failures."""

    code: ErrorCode


class InvalidDiffInputError(DiffError):
    """Raised when typed comparison input violates required invariants."""

    code = ErrorCode.INVALID_SNAPSHOT


class DiffSchemaMismatchError(DiffError):
    """Raised when a snapshot schema is not supported by this comparison layer."""

    code = ErrorCode.SCHEMA_MISMATCH


class HostMismatchError(DiffError):
    """Raised when baseline and current snapshots identify different hosts."""

    code = ErrorCode.HOST_MISMATCH


_DOMAINS = (
    "users.local_users",
    "users.administrators",
    "services.services",
    "tasks.tasks",
    "defender.exclusions",
    "defender.configuration",
    "defender.runtime",
)


class _HasId(Protocol):
    id: str


_ResourceT = TypeVar("_ResourceT", bound=_HasId)


def _local_user_to_mapping(resource: LocalUser) -> dict[str, object]:
    return {
        "id": resource.id,
        "name": resource.name,
        "enabled": resource.enabled,
        "principal_source": resource.principal_source.value,
    }


def _administrator_to_mapping(resource: AdministratorMember) -> dict[str, object]:
    return {
        "id": resource.id,
        "name": resource.name,
        "object_class": resource.object_class,
        "principal_source": resource.principal_source.value,
    }


def _service_to_mapping(resource: ServiceInfo) -> dict[str, object]:
    return {
        "id": resource.id,
        "name": resource.name,
        "display_name": resource.display_name,
        "start_mode": resource.start_mode.value,
        "path_name": resource.path_name,
        "start_name": resource.start_name,
    }


def _task_principal_to_mapping(resource: TaskPrincipal) -> dict[str, object]:
    return {
        "id": resource.id,
        "user_id": resource.user_id,
        "group_id": resource.group_id,
        "logon_type": resource.logon_type,
        "run_level": resource.run_level,
    }


def _task_action_to_mapping(resource: TaskAction) -> dict[str, object]:
    return {"type": resource.type, "xml_c14n": resource.xml_c14n}


def _task_trigger_to_mapping(resource: TaskTrigger) -> dict[str, object]:
    return {"type": resource.type, "xml_c14n": resource.xml_c14n}


def _task_to_mapping(resource: ScheduledTaskInfo) -> dict[str, object]:
    return {
        "id": resource.id,
        "task_path": resource.task_path,
        "task_name": resource.task_name,
        "principals": [
            _task_principal_to_mapping(principal) for principal in resource.principals
        ],
        "actions": [_task_action_to_mapping(action) for action in resource.actions],
        "triggers": [
            _task_trigger_to_mapping(trigger) for trigger in resource.triggers
        ],
    }


def _defender_exclusion_to_mapping(resource: DefenderExclusion) -> dict[str, object]:
    return {"id": resource.id, "kind": resource.kind.value, "value": resource.value}


def _defender_configuration_to_mapping(
    resource: DefenderConfiguration,
) -> dict[str, object]:
    return {
        "id": resource.id,
        "disable_realtime_monitoring": resource.disable_realtime_monitoring,
    }


def _defender_runtime_to_mapping(resource: DefenderRuntime) -> dict[str, object]:
    return {
        "id": resource.id,
        "real_time_protection_enabled": resource.real_time_protection_enabled,
    }


def _change_id(
    *,
    domain: str,
    object_id: str,
    change_type: ChangeType,
    property_name: str | None,
    old_value: object,
    new_value: object,
) -> str:
    payload = {
        "domain": domain,
        "object_id": object_id,
        "change_type": change_type.value,
        "property": property_name,
        "old_value": old_value,
        "new_value": new_value,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(f"{canonical}\n".encode()).hexdigest()


def _make_change(
    *,
    domain: str,
    object_type: str,
    object_id: str,
    object_name: str,
    change_type: ChangeType,
    property_name: str | None,
    old_value: object,
    new_value: object,
) -> Change:
    return Change(
        change_id=_change_id(
            domain=domain,
            object_id=object_id,
            change_type=change_type,
            property_name=property_name,
            old_value=old_value,
            new_value=new_value,
        ),
        domain=domain,
        object_type=object_type,
        object_id=object_id,
        object_name=object_name,
        change_type=change_type,
        property=property_name,
        old_value=old_value,
        new_value=new_value,
    )


def _index_resources(
    resources: tuple[_ResourceT, ...] | None,
    *,
    domain: str,
) -> dict[str, _ResourceT]:
    if resources is None:
        raise InvalidDiffInputError(f"covered domain {domain!r} has null data")
    indexed: dict[str, _ResourceT] = {}
    for resource in resources:
        if resource.id in indexed:
            raise InvalidDiffInputError(
                f"covered domain {domain!r} contains duplicate id {resource.id!r}"
            )
        indexed[resource.id] = resource
    return indexed


def _compare_sequence(
    *,
    domain: str,
    object_type: str,
    baseline_resources: tuple[_ResourceT, ...] | None,
    current_resources: tuple[_ResourceT, ...] | None,
    properties: tuple[str, ...],
    to_mapping: Callable[[_ResourceT], dict[str, object]],
    object_name: Callable[[_ResourceT], str],
) -> list[Change]:
    baseline_by_id = _index_resources(baseline_resources, domain=domain)
    current_by_id = _index_resources(current_resources, domain=domain)
    changes: list[Change] = []

    for resource_id in baseline_by_id.keys() - current_by_id.keys():
        resource = baseline_by_id[resource_id]
        changes.append(
            _make_change(
                domain=domain,
                object_type=object_type,
                object_id=resource_id,
                object_name=object_name(resource),
                change_type=ChangeType.REMOVED,
                property_name=None,
                old_value=to_mapping(resource),
                new_value=None,
            )
        )

    for resource_id in current_by_id.keys() - baseline_by_id.keys():
        resource = current_by_id[resource_id]
        changes.append(
            _make_change(
                domain=domain,
                object_type=object_type,
                object_id=resource_id,
                object_name=object_name(resource),
                change_type=ChangeType.ADDED,
                property_name=None,
                old_value=None,
                new_value=to_mapping(resource),
            )
        )

    for resource_id in baseline_by_id.keys() & current_by_id.keys():
        baseline_resource = baseline_by_id[resource_id]
        current_resource = current_by_id[resource_id]
        baseline_mapping = to_mapping(baseline_resource)
        current_mapping = to_mapping(current_resource)
        for property_name in properties:
            old_value = baseline_mapping[property_name]
            new_value = current_mapping[property_name]
            if old_value != new_value:
                changes.append(
                    _make_change(
                        domain=domain,
                        object_type=object_type,
                        object_id=resource_id,
                        object_name=object_name(current_resource),
                        change_type=ChangeType.MODIFIED,
                        property_name=property_name,
                        old_value=old_value,
                        new_value=new_value,
                    )
                )
    return changes


def _singleton_tuple(
    resource: _ResourceT | None,
    *,
    domain: str,
) -> tuple[_ResourceT, ...]:
    if resource is None:
        raise InvalidDiffInputError(f"covered domain {domain!r} has null data")
    return (resource,)


def _validate_snapshot_roles(baseline: Snapshot, current: Snapshot) -> None:
    if baseline.snapshot_kind is not SnapshotKind.BASELINE:
        raise InvalidDiffInputError("baseline snapshot_kind must be baseline")
    if current.snapshot_kind is not SnapshotKind.CURRENT:
        raise InvalidDiffInputError("current snapshot_kind must be current")


def _validate_schema(baseline: Snapshot, current: Snapshot) -> None:
    if baseline.schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise DiffSchemaMismatchError(
            f"baseline schema must equal {SNAPSHOT_SCHEMA_VERSION!r}"
        )
    if current.schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise DiffSchemaMismatchError(
            f"current schema must equal {SNAPSHOT_SCHEMA_VERSION!r}"
        )


def _validate_host_identity(baseline: Snapshot, current: Snapshot) -> None:
    baseline_machine_id = baseline.host.machine_id_sha256
    current_machine_id = current.host.machine_id_sha256
    if baseline_machine_id is not None and current_machine_id is not None:
        if baseline_machine_id != current_machine_id:
            raise HostMismatchError("snapshot machine fingerprints do not match")
        return
    if baseline.host.hostname.casefold() != current.host.hostname.casefold():
        raise HostMismatchError("snapshot hostnames do not match")


def _covered_on_both(
    baseline_coverage: frozenset[str],
    current_coverage: frozenset[str],
    member: str,
) -> bool:
    return member in baseline_coverage and member in current_coverage


def _change_sort_key(change: Change) -> tuple[str, str, str, str]:
    return (
        change.domain,
        change.object_id,
        change.change_type.value,
        "" if change.property is None else change.property,
    )


def compare_snapshots(baseline: Snapshot, current: Snapshot) -> DiffResult:
    """Compare compatible typed baseline/current snapshots without side effects."""
    if not isinstance(baseline, Snapshot):
        raise TypeError("baseline must be Snapshot")
    if not isinstance(current, Snapshot):
        raise TypeError("current must be Snapshot")

    _validate_snapshot_roles(baseline, current)
    _validate_schema(baseline, current)
    _validate_host_identity(baseline, current)

    compared: list[str] = []
    skipped: list[str] = []
    changes: list[Change] = []

    domain = _DOMAINS[0]
    if _covered_on_both(
        baseline.collectors.users.coverage,
        current.collectors.users.coverage,
        "local_users",
    ):
        compared.append(domain)
        changes.extend(
            _compare_sequence(
                domain=domain,
                object_type="local_user",
                baseline_resources=baseline.collectors.users.data.local_users,
                current_resources=current.collectors.users.data.local_users,
                properties=("name", "enabled", "principal_source"),
                to_mapping=_local_user_to_mapping,
                object_name=lambda resource: resource.name,
            )
        )
    else:
        skipped.append(domain)

    domain = _DOMAINS[1]
    if _covered_on_both(
        baseline.collectors.users.coverage,
        current.collectors.users.coverage,
        "administrators",
    ):
        compared.append(domain)
        changes.extend(
            _compare_sequence(
                domain=domain,
                object_type="administrator",
                baseline_resources=baseline.collectors.users.data.administrators,
                current_resources=current.collectors.users.data.administrators,
                properties=("name", "object_class", "principal_source"),
                to_mapping=_administrator_to_mapping,
                object_name=lambda resource: resource.name,
            )
        )
    else:
        skipped.append(domain)

    domain = _DOMAINS[2]
    if _covered_on_both(
        baseline.collectors.services.coverage,
        current.collectors.services.coverage,
        "services",
    ):
        compared.append(domain)
        changes.extend(
            _compare_sequence(
                domain=domain,
                object_type="service",
                baseline_resources=baseline.collectors.services.data.services,
                current_resources=current.collectors.services.data.services,
                properties=(
                    "name",
                    "display_name",
                    "start_mode",
                    "path_name",
                    "start_name",
                ),
                to_mapping=_service_to_mapping,
                object_name=lambda resource: resource.name,
            )
        )
    else:
        skipped.append(domain)

    domain = _DOMAINS[3]
    if _covered_on_both(
        baseline.collectors.tasks.coverage,
        current.collectors.tasks.coverage,
        "tasks",
    ):
        compared.append(domain)
        changes.extend(
            _compare_sequence(
                domain=domain,
                object_type="scheduled_task",
                baseline_resources=baseline.collectors.tasks.data.tasks,
                current_resources=current.collectors.tasks.data.tasks,
                properties=(
                    "task_path",
                    "task_name",
                    "principals",
                    "actions",
                    "triggers",
                ),
                to_mapping=_task_to_mapping,
                object_name=lambda resource: resource.task_path + resource.task_name,
            )
        )
    else:
        skipped.append(domain)

    domain = _DOMAINS[4]
    if _covered_on_both(
        baseline.collectors.defender.coverage,
        current.collectors.defender.coverage,
        "exclusions",
    ):
        compared.append(domain)
        changes.extend(
            _compare_sequence(
                domain=domain,
                object_type="defender_exclusion",
                baseline_resources=baseline.collectors.defender.data.exclusions,
                current_resources=current.collectors.defender.data.exclusions,
                properties=("kind", "value"),
                to_mapping=_defender_exclusion_to_mapping,
                object_name=lambda resource: resource.value,
            )
        )
    else:
        skipped.append(domain)

    domain = _DOMAINS[5]
    if _covered_on_both(
        baseline.collectors.defender.coverage,
        current.collectors.defender.coverage,
        "configuration",
    ):
        compared.append(domain)
        changes.extend(
            _compare_sequence(
                domain=domain,
                object_type="defender_configuration",
                baseline_resources=_singleton_tuple(
                    baseline.collectors.defender.data.configuration,
                    domain=domain,
                ),
                current_resources=_singleton_tuple(
                    current.collectors.defender.data.configuration,
                    domain=domain,
                ),
                properties=("disable_realtime_monitoring",),
                to_mapping=_defender_configuration_to_mapping,
                object_name=lambda _resource: "Microsoft Defender configuration",
            )
        )
    else:
        skipped.append(domain)

    domain = _DOMAINS[6]
    if _covered_on_both(
        baseline.collectors.defender.coverage,
        current.collectors.defender.coverage,
        "runtime",
    ):
        compared.append(domain)
        changes.extend(
            _compare_sequence(
                domain=domain,
                object_type="defender_runtime",
                baseline_resources=_singleton_tuple(
                    baseline.collectors.defender.data.runtime,
                    domain=domain,
                ),
                current_resources=_singleton_tuple(
                    current.collectors.defender.data.runtime,
                    domain=domain,
                ),
                properties=("real_time_protection_enabled",),
                to_mapping=_defender_runtime_to_mapping,
                object_name=lambda _resource: "Microsoft Defender runtime",
            )
        )
    else:
        skipped.append(domain)

    ordered_changes = tuple(sorted(changes, key=_change_sort_key))
    status = (
        ComparisonStatus.COMPLETE if not skipped else ComparisonStatus.PARTIAL
    )
    return DiffResult(
        status=status,
        compared_domains=tuple(compared),
        skipped_domains=tuple(skipped),
        changes=ordered_changes,
    )
