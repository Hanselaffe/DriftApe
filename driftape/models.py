"""Canonical typed domain models for DriftApe v0.1 snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class SnapshotKind(StrEnum):
    """Supported snapshot kinds."""

    BASELINE = "baseline"
    CURRENT = "current"


class CollectorStatus(StrEnum):
    """Collector completion status."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class PrincipalSource(StrEnum):
    """Canonical principal source identifiers."""

    LOCAL = "local"
    ACTIVE_DIRECTORY = "active_directory"
    MICROSOFT_ENTRA = "microsoft_entra"
    MICROSOFT_ACCOUNT = "microsoft_account"
    UNKNOWN = "unknown"


class ServiceStartMode(StrEnum):
    """Canonical service start modes."""

    AUTO = "auto"
    MANUAL = "manual"
    DISABLED = "disabled"
    BOOT = "boot"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class DefenderExclusionKind(StrEnum):
    """Supported Microsoft Defender exclusion kinds."""

    PATH = "path"
    PROCESS = "process"
    EXTENSION = "extension"
    IP_ADDRESS = "ip_address"


class ErrorCode(StrEnum):
    """Canonical persisted operational error codes."""

    COLLECTOR_UNAVAILABLE = "COLLECTOR_UNAVAILABLE"
    ACCESS_DENIED = "ACCESS_DENIED"
    COMMAND_FAILED = "COMMAND_FAILED"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    UNEXPECTED_OUTPUT = "UNEXPECTED_OUTPUT"
    UNSUPPORTED_OS = "UNSUPPORTED_OS"
    INVALID_SNAPSHOT = "INVALID_SNAPSHOT"
    INVALID_MANIFEST = "INVALID_MANIFEST"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    HOST_MISMATCH = "HOST_MISMATCH"
    IO_ERROR = "IO_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True, slots=True)
class DriftApeError:
    """Persistable operational error information."""

    code: ErrorCode
    scope: str
    operation: str
    message: str
    native_code: str | int | None
    recoverable: bool


@dataclass(frozen=True, slots=True)
class HostInfo:
    """Canonical host identity and operating-system metadata."""

    hostname: str
    machine_id_sha256: str | None
    os_name: str
    os_version: str
    os_build: str
    architecture: str


@dataclass(frozen=True, slots=True)
class CollectionInfo:
    """Snapshot-level collection metadata."""

    is_elevated: bool
    complete: bool


@dataclass(frozen=True, slots=True)
class LocalUser:
    """Canonical local user record."""

    id: str
    name: str
    enabled: bool
    principal_source: PrincipalSource


@dataclass(frozen=True, slots=True)
class AdministratorMember:
    """Canonical local Administrators-group membership record."""

    id: str
    name: str
    object_class: str
    principal_source: PrincipalSource


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    """Canonical Windows service definition."""

    id: str
    name: str
    display_name: str
    start_mode: ServiceStartMode
    path_name: str | None
    start_name: str | None


@dataclass(frozen=True, slots=True)
class TaskPrincipal:
    """Canonical scheduled-task principal."""

    id: str
    user_id: str | None
    group_id: str | None
    logon_type: str | None
    run_level: str | None


@dataclass(frozen=True, slots=True)
class TaskAction:
    """Canonical scheduled-task action payload."""

    type: str
    xml_c14n: str


@dataclass(frozen=True, slots=True)
class TaskTrigger:
    """Canonical scheduled-task trigger payload."""

    type: str
    xml_c14n: str


@dataclass(frozen=True, slots=True)
class ScheduledTaskInfo:
    """Canonical scheduled task definition."""

    id: str
    task_path: str
    task_name: str
    principals: tuple[TaskPrincipal, ...]
    actions: tuple[TaskAction, ...]
    triggers: tuple[TaskTrigger, ...]


@dataclass(frozen=True, slots=True)
class DefenderExclusion:
    """Canonical Microsoft Defender exclusion."""

    id: str
    kind: DefenderExclusionKind
    value: str


@dataclass(frozen=True, slots=True)
class DefenderConfiguration:
    """Canonical Microsoft Defender configuration state."""

    id: str
    disable_realtime_monitoring: bool


@dataclass(frozen=True, slots=True)
class DefenderRuntime:
    """Canonical Microsoft Defender runtime state."""

    id: str
    real_time_protection_enabled: bool


@dataclass(frozen=True, slots=True)
class UsersData:
    """Canonical users collector data."""

    local_users: tuple[LocalUser, ...] | None
    administrators: tuple[AdministratorMember, ...] | None


@dataclass(frozen=True, slots=True)
class ServicesData:
    """Canonical services collector data."""

    services: tuple[ServiceInfo, ...] | None


@dataclass(frozen=True, slots=True)
class TasksData:
    """Canonical scheduled-tasks collector data."""

    tasks: tuple[ScheduledTaskInfo, ...] | None


@dataclass(frozen=True, slots=True)
class DefenderData:
    """Canonical Microsoft Defender collector data."""

    exclusions: tuple[DefenderExclusion, ...] | None
    configuration: DefenderConfiguration | None
    runtime: DefenderRuntime | None


@dataclass(frozen=True, slots=True)
class UsersCollectorResult:
    """Typed users collector envelope."""

    status: CollectorStatus
    coverage: frozenset[str]
    data: UsersData
    errors: tuple[DriftApeError, ...]


@dataclass(frozen=True, slots=True)
class ServicesCollectorResult:
    """Typed services collector envelope."""

    status: CollectorStatus
    coverage: frozenset[str]
    data: ServicesData
    errors: tuple[DriftApeError, ...]


@dataclass(frozen=True, slots=True)
class TasksCollectorResult:
    """Typed scheduled-tasks collector envelope."""

    status: CollectorStatus
    coverage: frozenset[str]
    data: TasksData
    errors: tuple[DriftApeError, ...]


@dataclass(frozen=True, slots=True)
class DefenderCollectorResult:
    """Typed Microsoft Defender collector envelope."""

    status: CollectorStatus
    coverage: frozenset[str]
    data: DefenderData
    errors: tuple[DriftApeError, ...]


@dataclass(frozen=True, slots=True)
class CollectorSet:
    """The exact four collector domains in a v0.1 snapshot."""

    users: UsersCollectorResult
    services: ServicesCollectorResult
    tasks: TasksCollectorResult
    defender: DefenderCollectorResult


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Canonical validated DriftApe v0.1 snapshot."""

    schema_version: str
    tool_version: str
    snapshot_kind: SnapshotKind
    collected_at_utc: datetime
    host: HostInfo
    collection: CollectionInfo
    collectors: CollectorSet
    errors: tuple[DriftApeError, ...]
