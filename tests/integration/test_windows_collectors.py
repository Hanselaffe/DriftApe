"""Read-only real-host integration verification for DriftApe WP14.

Windows runtime tests intentionally skip unless the host is Windows 11 x64 with
64-bit Python 3.12 or 3.13.  The source-level read-only guard runs everywhere.
"""

from __future__ import annotations

import json
import platform
import struct
import sys
from dataclasses import fields
from pathlib import Path

import pytest

from driftape import platform_windows
from driftape.cli import main
from driftape.collectors.defender import collect_defender
from driftape.collectors.services import collect_services
from driftape.collectors.tasks import collect_tasks
from driftape.collectors.users import collect_users
from driftape.constants import CHANGE_SCHEMA_VERSION, SNAPSHOT_SCHEMA_VERSION
from driftape.diff import Change, ComparisonStatus, compare_snapshots
from driftape.integrity import derive_baseline_manifest_path, load_baseline_path
from driftape.models import (
    AdministratorMember,
    CollectorStatus,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderData,
    DefenderExclusion,
    DefenderRuntime,
    DriftApeError,
    ErrorCode,
    HostInfo,
    LocalUser,
    ScheduledTaskInfo,
    ServiceInfo,
    ServicesCollectorResult,
    ServicesData,
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
from driftape.serialization import serialize_snapshot
from driftape.snapshot import collect_snapshot
from driftape.validation import validate_snapshot

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SKIP_REASON = "supported Windows 11 x64 runtime unavailable"
_SUPPORTED_MACHINES = frozenset({"amd64", "x86_64"})

_SOURCE_GUARD_PATHS = (
    "driftape/acquisition/powershell.py",
    "driftape/platform_windows.py",
    "driftape/collectors/users.py",
    "driftape/collectors/services.py",
    "driftape/collectors/tasks.py",
    "driftape/collectors/defender.py",
    "driftape/snapshot.py",
    "driftape/cli.py",
)

_FORBIDDEN_TOKENS = (
    "New-LocalUser",
    "Remove-LocalUser",
    "Set-LocalUser",
    "Add-LocalGroupMember",
    "Remove-LocalGroupMember",
    "New-Service",
    "Set-Service",
    "Remove-Service",
    "Start-Service",
    "Stop-Service",
    "Register-ScheduledTask",
    "Unregister-ScheduledTask",
    "Set-ScheduledTask",
    "Disable-ScheduledTask",
    "Enable-ScheduledTask",
    "Start-ScheduledTask",
    "Stop-ScheduledTask",
    "Set-MpPreference",
    "Add-MpPreference",
    "Remove-MpPreference",
    "Set-ExecutionPolicy",
    "ExecutionPolicy Bypass",
    "EncodedCommand",
    "Invoke-Command",
    "New-PSSession",
    "Enter-PSSession",
    "runas",
    "ShellExecuteW",
    "ShellExecuteEx",
    "Start-Process -Verb RunAs",
)

_ALLOWED_READ_ONLY_TOKENS = (
    "Get-LocalUser",
    "Get-LocalGroupMember",
    "Get-CimInstance",
    "Get-ScheduledTask",
    "Export-ScheduledTask",
    "Get-MpPreference",
    "Get-MpComputerStatus",
)

_DOMAIN_COVERAGE = {
    "users.local_users": ("users", "local_users"),
    "users.administrators": ("users", "administrators"),
    "services.services": ("services", "services"),
    "tasks.tasks": ("tasks", "tasks"),
    "defender.exclusions": ("defender", "exclusions"),
    "defender.configuration": ("defender", "configuration"),
    "defender.runtime": ("defender", "runtime"),
}


def _fail(message: str) -> None:
    pytest.fail(message, pytrace=False)


def _require_windows_11_host() -> HostInfo:
    if sys.platform != "win32":
        pytest.skip(_SKIP_REASON)
    if struct.calcsize("P") != 8:
        pytest.skip(_SKIP_REASON)
    if platform.machine().casefold() not in _SUPPORTED_MACHINES:
        pytest.skip(_SKIP_REASON)
    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        pytest.skip(_SKIP_REASON)

    version = sys.getwindowsversion()
    if version.product_type != 1:
        pytest.skip(_SKIP_REASON)
    if version.major != 10 or version.minor != 0 or version.build < 22000:
        pytest.skip(_SKIP_REASON)

    return platform_windows.collect_host_info()


def _check_errors(errors: object, label: str) -> None:
    if errors.__class__ is not tuple:
        _fail(f"{label}: errors must be an exact tuple")
    for error in errors:
        if error.__class__ is not DriftApeError:
            _fail(f"{label}: persisted error must be exact DriftApeError")
        if error.code.__class__ is not ErrorCode:
            _fail(f"{label}: error code must be a frozen ErrorCode")
        for field_name in ("scope", "operation", "message"):
            value = getattr(error, field_name)
            if value.__class__ is not str or value == "":
                _fail(f"{label}: error {field_name} must be non-empty text")
        for dataclass_field in fields(error):
            if isinstance(getattr(error, dataclass_field.name), BaseException):
                _fail(f"{label}: native Python exception persisted in error envelope")


def _check_status_and_coverage(
    *,
    status: object,
    coverage: object,
    full_coverage: frozenset[str],
    label: str,
    partial_must_be_strict_subset: bool = True,
) -> None:
    if status.__class__ is not CollectorStatus:
        _fail(f"{label}: status must be a frozen CollectorStatus")
    if coverage.__class__ is not frozenset:
        _fail(f"{label}: coverage must be an exact frozenset")
    if not coverage <= full_coverage:
        _fail(f"{label}: coverage contains an unauthorized logical section")
    if status is CollectorStatus.SUCCESS and coverage != full_coverage:
        _fail(f"{label}: SUCCESS must claim full mandatory coverage")
    if status is CollectorStatus.FAILED and coverage:
        _fail(f"{label}: FAILED must not claim complete logical coverage")
    if (
        status is CollectorStatus.PARTIAL
        and partial_must_be_strict_subset
        and not coverage < full_coverage
    ):
        _fail(f"{label}: PARTIAL must claim less than full mandatory coverage")


def _check_exact_sequence(
    values: object,
    item_type: type[object],
    *,
    label: str,
    require_sorted_ids: bool = False,
) -> None:
    if values.__class__ is not tuple:
        _fail(f"{label}: populated collection must be an exact tuple")
    ids: list[str] = []
    for item in values:
        if item.__class__ is not item_type:
            _fail(f"{label}: item has an unexpected concrete type")
        if hasattr(item, "id"):
            identifier = getattr(item, "id")
            if identifier.__class__ is not str or identifier == "":
                _fail(f"{label}: item identity must be non-empty text")
            ids.append(identifier)
    if len(ids) != len(set(ids)):
        _fail(f"{label}: populated identities are not unique")
    if require_sorted_ids and ids != sorted(ids):
        _fail(f"{label}: canonical identity ordering is not normalized")


def _check_users_result(result: object) -> None:
    if result.__class__ is not UsersCollectorResult:
        _fail("users: collector returned an unexpected envelope type")
    if result.data.__class__ is not UsersData:
        _fail("users: collector returned an unexpected data type")
    full = frozenset({"local_users", "administrators"})
    _check_status_and_coverage(
        status=result.status,
        coverage=result.coverage,
        full_coverage=full,
        label="users",
    )
    _check_errors(result.errors, "users")

    sections = (
        ("local_users", result.data.local_users, LocalUser),
        ("administrators", result.data.administrators, AdministratorMember),
    )
    for coverage_name, values, item_type in sections:
        if coverage_name in result.coverage:
            if values is None:
                _fail(f"users.{coverage_name}: covered data is missing")
            _check_exact_sequence(
                values,
                item_type,
                label=f"users.{coverage_name}",
                require_sorted_ids=True,
            )
        elif values is not None:
            _fail(f"users.{coverage_name}: uncovered data must not be persisted")


def _check_services_result(result: object) -> None:
    if result.__class__ is not ServicesCollectorResult:
        _fail("services: collector returned an unexpected envelope type")
    if result.data.__class__ is not ServicesData:
        _fail("services: collector returned an unexpected data type")
    full = frozenset({"services"})
    _check_status_and_coverage(
        status=result.status,
        coverage=result.coverage,
        full_coverage=full,
        label="services",
    )
    _check_errors(result.errors, "services")
    if "services" in result.coverage:
        if result.data.services is None:
            _fail("services: covered service data is missing")
        _check_exact_sequence(
            result.data.services,
            ServiceInfo,
            label="services.services",
            require_sorted_ids=True,
        )
    elif result.data.services is not None:
        _fail("services: uncovered service data must not be persisted")


def _check_tasks_result(result: object) -> None:
    if result.__class__ is not TasksCollectorResult:
        _fail("tasks: collector returned an unexpected envelope type")
    if result.data.__class__ is not TasksData:
        _fail("tasks: collector returned an unexpected data type")
    full = frozenset({"tasks"})
    _check_status_and_coverage(
        status=result.status,
        coverage=result.coverage,
        full_coverage=full,
        label="tasks",
    )
    _check_errors(result.errors, "tasks")

    values = result.data.tasks
    if result.status is CollectorStatus.FAILED:
        if values is not None:
            _fail("tasks: FAILED result must not persist complete task data")
        return
    if values is None:
        _fail("tasks: successful/partial acquisition must return its bounded task tuple")
    _check_exact_sequence(
        values,
        ScheduledTaskInfo,
        label="tasks.tasks",
        require_sorted_ids=True,
    )
    for task in values:
        _check_exact_sequence(
            task.principals,
            TaskPrincipal,
            label="tasks.task.principals",
            require_sorted_ids=True,
        )
        _check_exact_sequence(task.actions, TaskAction, label="tasks.task.actions")
        _check_exact_sequence(task.triggers, TaskTrigger, label="tasks.task.triggers")
        trigger_keys = [(trigger.type, trigger.xml_c14n) for trigger in task.triggers]
        if trigger_keys != sorted(trigger_keys):
            _fail("tasks.task.triggers: canonical trigger ordering is not normalized")


def _check_defender_result(result: object) -> None:
    if result.__class__ is not DefenderCollectorResult:
        _fail("defender: collector returned an unexpected envelope type")
    if result.data.__class__ is not DefenderData:
        _fail("defender: collector returned an unexpected data type")
    full = frozenset({"exclusions", "configuration", "runtime"})
    _check_status_and_coverage(
        status=result.status,
        coverage=result.coverage,
        full_coverage=full,
        label="defender",
    )
    _check_errors(result.errors, "defender")

    if "exclusions" in result.coverage:
        if result.data.exclusions is None:
            _fail("defender.exclusions: covered data is missing")
        _check_exact_sequence(
            result.data.exclusions,
            DefenderExclusion,
            label="defender.exclusions",
            require_sorted_ids=True,
        )
    elif result.data.exclusions is not None:
        _fail("defender.exclusions: uncovered data must not be persisted")

    singleton_sections = (
        ("configuration", result.data.configuration, DefenderConfiguration),
        ("runtime", result.data.runtime, DefenderRuntime),
    )
    for coverage_name, value, item_type in singleton_sections:
        if coverage_name in result.coverage:
            if value is None or value.__class__ is not item_type:
                _fail(f"defender.{coverage_name}: covered typed data is missing")
        elif value is not None:
            _fail(f"defender.{coverage_name}: uncovered data must not be persisted")


def _check_snapshot_envelopes(snapshot: Snapshot) -> None:
    _check_users_result(snapshot.collectors.users)
    _check_services_result(snapshot.collectors.services)
    _check_tasks_result(snapshot.collectors.tasks)
    _check_defender_result(snapshot.collectors.defender)
    _check_errors(snapshot.errors, "snapshot")

    expected_complete = all(
        result.status is CollectorStatus.SUCCESS
        for result in (
            snapshot.collectors.users,
            snapshot.collectors.services,
            snapshot.collectors.tasks,
            snapshot.collectors.defender,
        )
    )
    if snapshot.collection.complete is not expected_complete:
        _fail("snapshot: collection.complete does not reflect collector completion")


def _check_canonical_snapshot_bytes(snapshot: Snapshot) -> bytes:
    data = serialize_snapshot(snapshot)
    if data.startswith(b"\xef\xbb\xbf"):
        _fail("snapshot serialization contains a UTF-8 BOM")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        _fail("snapshot serialization must contain exactly one trailing LF")
    return data


def _coverage_for_domain(snapshot: Snapshot, domain: str) -> frozenset[str]:
    collector_name, coverage_name = _DOMAIN_COVERAGE[domain]
    collector = getattr(snapshot.collectors, collector_name)
    return collector.coverage if coverage_name in collector.coverage else frozenset()


def _validate_current_bytes(data: bytes) -> Snapshot:
    if data.startswith(b"\xef\xbb\xbf"):
        _fail("current snapshot contains a UTF-8 BOM")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        _fail("current snapshot must contain exactly one trailing LF")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("current snapshot is not valid UTF-8 JSON")
    if parsed.__class__ is not dict:
        _fail("current snapshot root is not an object")
    snapshot = validate_snapshot(parsed)
    if snapshot.snapshot_kind is not SnapshotKind.CURRENT:
        _fail("current snapshot does not validate as SnapshotKind.CURRENT")
    if serialize_snapshot(snapshot) != data:
        _fail("current snapshot bytes are not canonical")
    return snapshot


def test_wp14_static_production_collection_stack_is_read_only() -> None:
    combined_parts: list[str] = []
    for relative_path in _SOURCE_GUARD_PATHS:
        source_path = _PROJECT_ROOT / relative_path
        try:
            combined_parts.append(source_path.read_text(encoding="utf-8"))
        except OSError:
            _fail("static guard could not read an authorized production source file")
    combined = "\n".join(combined_parts)
    folded = combined.casefold()

    for token in _FORBIDDEN_TOKENS:
        if token.casefold() in folded:
            _fail("static guard found a forbidden mutation/elevation/remote-operation token")

    for token in _ALLOWED_READ_ONLY_TOKENS:
        if token not in combined:
            _fail("static guard could not find an expected read-only acquisition primitive")


def test_wp14_supported_windows_platform_and_host_identity() -> None:
    host = _require_windows_11_host()
    version = sys.getwindowsversion()
    if platform_windows.is_supported_platform() is not True:
        _fail("platform helper did not recognize the supported Windows x64 runtime")
    if sys.platform != "win32":
        _fail("supported integration runtime is not win32")
    if struct.calcsize("P") != 8:
        _fail("supported integration runtime is not a 64-bit Python process")
    if platform.machine().casefold() not in _SUPPORTED_MACHINES:
        _fail("supported integration runtime is not AMD64/x86_64")
    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        _fail("supported integration runtime is not Python 3.12/3.13")
    if version.product_type != 1:
        _fail("supported integration runtime is not a Windows client/workstation")
    if version.major != 10 or version.minor != 0 or version.build < 22000:
        _fail("supported integration runtime is not a Windows 11 build")
    if host.__class__ is not HostInfo:
        _fail("collect_host_info did not return the exact HostInfo type")
    if host.os_name.__class__ is not str or host.os_name == "":
        _fail("HostInfo.os_name is not a non-empty registry ProductName string")
    if host.os_build != str(version.build):
        _fail("HostInfo.os_build does not match the native Windows build")
    expected_version = f"{version.major}.{version.minor}.{version.build}"
    if host.os_version != expected_version:
        _fail("HostInfo.os_version does not match the native Windows version")
    if host.architecture != "AMD64":
        _fail("HostInfo.architecture is not the accepted AMD64 value")
    if host.machine_id_sha256 is not None:
        fingerprint = host.machine_id_sha256
        if (
            fingerprint.__class__ is not str
            or len(fingerprint) != 64
            or any(ch not in "0123456789abcdef" for ch in fingerprint)
        ):
            _fail("HostInfo.machine_id_sha256 is not exactly 64 lowercase hex characters")
    if hasattr(host, "MachineGuid") or hasattr(host, "machine_guid"):
        _fail("HostInfo exposes a raw MachineGuid field")


def test_wp14_users_collector_real_host_contract() -> None:
    _require_windows_11_host()
    _check_users_result(collect_users())


def test_wp14_services_collector_real_host_contract() -> None:
    _require_windows_11_host()
    _check_services_result(collect_services())


def test_wp14_tasks_collector_real_host_contract() -> None:
    _require_windows_11_host()
    _check_tasks_result(collect_tasks())


def test_wp14_defender_collector_real_host_contract() -> None:
    _require_windows_11_host()
    _check_defender_result(collect_defender())


def test_wp14_two_immediate_snapshots_and_diff() -> None:
    _require_windows_11_host()
    baseline = collect_snapshot(SnapshotKind.BASELINE)
    current = collect_snapshot(SnapshotKind.CURRENT)

    if baseline.__class__ is not Snapshot or current.__class__ is not Snapshot:
        _fail("snapshot orchestration did not return exact Snapshot objects")
    if baseline.schema_version != SNAPSHOT_SCHEMA_VERSION:
        _fail("baseline snapshot schema version is not driftape.snapshot.v1")
    if current.schema_version != SNAPSHOT_SCHEMA_VERSION:
        _fail("current snapshot schema version is not driftape.snapshot.v1")
    _check_snapshot_envelopes(baseline)
    _check_snapshot_envelopes(current)
    _check_canonical_snapshot_bytes(baseline)
    _check_canonical_snapshot_bytes(current)

    baseline_fingerprint = baseline.host.machine_id_sha256
    current_fingerprint = current.host.machine_id_sha256
    if baseline_fingerprint is not None and current_fingerprint is not None:
        if baseline_fingerprint != current_fingerprint:
            _fail("two immediate snapshots do not satisfy local machine identity policy")
    elif baseline.host.hostname.casefold() != current.host.hostname.casefold():
        _fail("two immediate snapshots do not satisfy local hostname identity policy")

    result = compare_snapshots(baseline, current)
    if result.status not in {ComparisonStatus.COMPLETE, ComparisonStatus.PARTIAL}:
        _fail("snapshot comparison returned an invalid comparison status")
    for change in result.changes:
        if change.__class__ is not Change:
            _fail("comparison mixed a non-Change object into changes")
    for domain in result.skipped_domains:
        if domain not in _DOMAIN_COVERAGE:
            _fail("comparison reported an unknown skipped logical domain")
        collector_name, coverage_name = _DOMAIN_COVERAGE[domain]
        baseline_collector = getattr(baseline.collectors, collector_name)
        current_collector = getattr(current.collectors, collector_name)
        if coverage_name in baseline_collector.coverage and coverage_name in current_collector.coverage:
            _fail("comparison skipped a domain that was complete in both snapshots")


def test_wp14_cli_baseline_scan_diff_real_host(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _require_windows_11_host()
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    changes_path = tmp_path / "changes.json"

    baseline_exit = main(["baseline", "--output", str(baseline_path)])
    baseline_io = capsys.readouterr()
    if baseline_exit not in {0, 2}:
        _fail("baseline CLI returned an operational failure exit outside 0/2")
    if baseline_io.err:
        _fail("baseline CLI emitted unexpected stderr on a usable collection")

    scan_exit = main(["scan", "--output", str(current_path)])
    scan_io = capsys.readouterr()
    if scan_exit not in {0, 2}:
        _fail("scan CLI returned an operational failure exit outside 0/2")
    if scan_io.err:
        _fail("scan CLI emitted unexpected stderr on a usable collection")

    diff_exit = main(
        [
            "diff",
            str(baseline_path),
            str(current_path),
            "--output",
            str(changes_path),
        ]
    )
    diff_io = capsys.readouterr()
    if diff_exit not in {0, 1, 2}:
        _fail("diff CLI returned an operational failure exit outside 0/1/2")
    if diff_io.err:
        _fail("diff CLI emitted unexpected stderr on a usable comparison")

    manifest_path = derive_baseline_manifest_path(baseline_path)
    for path, label in (
        (baseline_path, "baseline.json"),
        (manifest_path, "baseline.manifest.json"),
        (current_path, "current.json"),
        (changes_path, "changes.json"),
    ):
        if not path.is_file():
            _fail(f"CLI did not create required temporary artifact {label}")

    loaded_baseline = load_baseline_path(baseline_path)
    if loaded_baseline.snapshot_kind is not SnapshotKind.BASELINE:
        _fail("load_baseline_path did not return a baseline snapshot")
    _validate_current_bytes(current_path.read_bytes())

    try:
        changes_root = json.loads(changes_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("changes output is not valid UTF-8 JSON")
    if changes_root.__class__ is not dict:
        _fail("changes JSON root is not an object")
    if changes_root.get("schema_version") != CHANGE_SCHEMA_VERSION:
        _fail("changes JSON root schema is not driftape.changes.v1")

    if not diff_io.out.startswith("DriftApe 0.1.0\n"):
        _fail("diff stdout is not the accepted human terminal summary")
    if diff_io.out.lstrip().startswith("{") or '"schema_version"' in diff_io.out:
        _fail("diff stdout contains serialized JSON")


def test_wp14_cli_overwrite_protection_is_byte_preserving(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _require_windows_11_host()
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    changes_path = tmp_path / "changes.json"
    manifest_path = derive_baseline_manifest_path(baseline_path)

    if main(["baseline", "--output", str(baseline_path)]) not in {0, 2}:
        _fail("initial baseline CLI run was not usable")
    capsys.readouterr()
    baseline_before = baseline_path.read_bytes()
    manifest_before = manifest_path.read_bytes()

    if main(["baseline", "--output", str(baseline_path)]) != 3:
        _fail("baseline overwrite without --force did not return exit 3")
    capsys.readouterr()
    if baseline_path.read_bytes() != baseline_before or manifest_path.read_bytes() != manifest_before:
        _fail("baseline overwrite protection changed existing baseline/manifest bytes")

    if main(["scan", "--output", str(current_path)]) not in {0, 2}:
        _fail("initial scan CLI run was not usable")
    capsys.readouterr()
    current_before = current_path.read_bytes()
    if main(["scan", "--output", str(current_path)]) != 3:
        _fail("scan overwrite without --force did not return exit 3")
    capsys.readouterr()
    if current_path.read_bytes() != current_before:
        _fail("scan overwrite protection changed existing current snapshot bytes")

    if main([
        "diff",
        str(baseline_path),
        str(current_path),
        "--output",
        str(changes_path),
    ]) not in {0, 1, 2}:
        _fail("initial diff CLI run was not usable")
    capsys.readouterr()
    changes_before = changes_path.read_bytes()
    if main([
        "diff",
        str(baseline_path),
        str(current_path),
        "--output",
        str(changes_path),
    ]) != 3:
        _fail("diff overwrite without --force did not return exit 3")
    capsys.readouterr()
    if changes_path.read_bytes() != changes_before:
        _fail("diff overwrite protection changed existing changes bytes")
