"""WP13 operational CLI tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import driftape.cli as cli_module
from driftape.constants import SNAPSHOT_SCHEMA_VERSION
from driftape.diff import (
    Change,
    ChangeType,
    ComparisonStatus,
    DiffResult,
    DiffSchemaMismatchError,
    HostMismatchError,
    InvalidDiffInputError,
)
from driftape.integrity import (
    BaselineIOError,
    BaselineIntegrityError,
    BaselineSchemaMismatchError,
    InvalidBaselineSnapshotError,
    InvalidManifestError,
    derive_baseline_manifest_path,
    load_baseline_path,
    write_baseline_path,
)
from driftape.models import (
    CollectionInfo,
    CollectorSet,
    CollectorStatus,
    DefenderCollectorResult,
    DefenderConfiguration,
    DefenderData,
    DefenderRuntime,
    HostInfo,
    LocalUser,
    PrincipalSource,
    ServicesCollectorResult,
    ServicesData,
    Snapshot,
    SnapshotKind,
    TasksCollectorResult,
    TasksData,
    UsersCollectorResult,
    UsersData,
)
from driftape.platform_windows import UnsupportedPlatformError
from driftape.reporting import build_report, serialize_report
from driftape.serialization import serialize_snapshot, snapshot_to_mapping
from driftape.snapshot import SnapshotCollectionError


def _snapshot(
    kind: SnapshotKind,
    *,
    complete: bool = True,
    local_users: tuple[LocalUser, ...] = (),
    timestamp: datetime | None = None,
) -> Snapshot:
    if timestamp is None:
        timestamp = datetime(2026, 8, 28, 10, 11, 12, tzinfo=timezone.utc)
    users = UsersCollectorResult(
        status=CollectorStatus.SUCCESS,
        coverage=frozenset({"local_users", "administrators"}),
        data=UsersData(local_users=local_users, administrators=()),
        errors=(),
    )
    services = ServicesCollectorResult(
        status=CollectorStatus.SUCCESS,
        coverage=frozenset({"services"}),
        data=ServicesData(services=()),
        errors=(),
    )
    tasks = TasksCollectorResult(
        status=CollectorStatus.SUCCESS,
        coverage=frozenset({"tasks"}),
        data=TasksData(tasks=()),
        errors=(),
    )
    defender = DefenderCollectorResult(
        status=CollectorStatus.SUCCESS,
        coverage=frozenset({"exclusions", "configuration", "runtime"}),
        data=DefenderData(
            exclusions=(),
            configuration=DefenderConfiguration("microsoft_defender", False),
            runtime=DefenderRuntime("microsoft_defender", True),
        ),
        errors=(),
    )
    if not complete:
        tasks = TasksCollectorResult(
            status=CollectorStatus.FAILED,
            coverage=frozenset(),
            data=TasksData(tasks=None),
            errors=(),
        )
    return Snapshot(
        schema_version=SNAPSHOT_SCHEMA_VERSION,
        tool_version="0.1.0",
        snapshot_kind=kind,
        collected_at_utc=timestamp,
        host=HostInfo(
            hostname="HOST01",
            machine_id_sha256="a" * 64,
            os_name="Windows 11 Pro",
            os_version="10.0.26100",
            os_build="26100",
            architecture="AMD64",
        ),
        collection=CollectionInfo(is_elevated=False, complete=complete),
        collectors=CollectorSet(users, services, tasks, defender),
        errors=(),
    )


def _current_file(path: Path, snapshot: Snapshot | None = None) -> Snapshot:
    current = snapshot or _snapshot(SnapshotKind.CURRENT)
    path.write_bytes(serialize_snapshot(current))
    return current


def _baseline_pair(path: Path, snapshot: Snapshot | None = None) -> Snapshot:
    baseline = snapshot or _snapshot(SnapshotKind.BASELINE)
    write_baseline_path(baseline, path)
    return baseline


def test_baseline_calls_exact_kind_and_writes_default_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    snapshot = _snapshot(SnapshotKind.BASELINE)
    calls: list[SnapshotKind] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda kind: calls.append(kind) or snapshot)

    assert cli_module.main(["baseline"]) == 0
    assert calls == [SnapshotKind.BASELINE]
    assert (tmp_path / "baseline.json").read_bytes() == serialize_snapshot(snapshot)
    assert (tmp_path / "baseline.manifest.json").is_file()
    captured = capsys.readouterr()
    assert "DriftApe 0.1.0" in captured.out
    assert "Output: baseline.json" in captured.out
    assert "Manifest: baseline.manifest.json" in captured.out
    assert "Collection: COMPLETE" in captured.out
    assert "{" not in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    ("name", "manifest"),
    (("gold.json", "gold.manifest.json"), ("host-a.snapshot", "host-a.manifest.json")),
)
def test_baseline_custom_manifest_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    manifest: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module, "collect_snapshot", lambda _kind: _snapshot(SnapshotKind.BASELINE)
    )
    assert cli_module.main(["baseline", "--output", name]) == 0
    assert (tmp_path / name).is_file()
    assert (tmp_path / manifest).is_file()


@pytest.mark.parametrize("conflict", ("baseline", "manifest"))
def test_baseline_no_force_conflict_is_precollection_and_untouched(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    conflict: str,
) -> None:
    output = tmp_path / "gold.json"
    manifest = derive_baseline_manifest_path(output)
    target = output if conflict == "baseline" else manifest
    target.write_bytes(b"original")
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: pytest.fail("collected"))

    assert cli_module.main(["baseline", "--output", str(output)]) == 3
    assert target.read_bytes() == b"original"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err


def test_baseline_force_replaces_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "gold.json"
    output.write_bytes(b"old")
    derive_baseline_manifest_path(output).write_bytes(b"old-manifest")
    snapshot = _snapshot(SnapshotKind.BASELINE)
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: snapshot)
    assert cli_module.main(["baseline", "--output", str(output), "--force"]) == 0
    assert output.read_bytes() == serialize_snapshot(snapshot)
    assert load_baseline_path(output) == snapshot


def test_baseline_partial_writes_and_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "baseline.json"
    snapshot = _snapshot(SnapshotKind.BASELINE, complete=False)
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: snapshot)
    assert cli_module.main(["baseline", "--output", str(output)]) == 2
    assert load_baseline_path(output) == snapshot
    assert "PARTIAL" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("exc", "code"),
    ((UnsupportedPlatformError("unsupported"), 8), (SnapshotCollectionError("fatal"), 3)),
)
def test_baseline_collection_error_mapping_no_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    exc: Exception,
    code: int,
) -> None:
    output = tmp_path / "baseline.json"
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: (_ for _ in ()).throw(exc))
    assert cli_module.main(["baseline", "--output", str(output)]) == code
    assert not output.exists()
    assert not derive_baseline_manifest_path(output).exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err


def test_baseline_io_error_maps_3(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        cli_module, "collect_snapshot", lambda _kind: _snapshot(SnapshotKind.BASELINE)
    )
    monkeypatch.setattr(
        cli_module, "write_baseline_path", lambda *_args: (_ for _ in ()).throw(BaselineIOError("io"))
    )
    assert cli_module.main(["baseline", "--output", "x.json"]) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err


def test_scan_exact_kind_bytes_no_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "now.json"
    snapshot = _snapshot(SnapshotKind.CURRENT)
    calls: list[SnapshotKind] = []
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda kind: calls.append(kind) or snapshot)
    assert cli_module.main(["scan", "--output", str(output)]) == 0
    assert calls == [SnapshotKind.CURRENT]
    assert output.read_bytes() == serialize_snapshot(snapshot)
    assert not derive_baseline_manifest_path(output).exists()
    captured = capsys.readouterr()
    assert "COMPLETE" in captured.out
    assert "{" not in captured.out
    assert captured.err == ""


def test_scan_default_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: _snapshot(SnapshotKind.CURRENT))
    assert cli_module.main(["scan"]) == 0
    assert (tmp_path / "current.json").is_file()


def test_scan_conflict_and_force(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "current.json"
    output.write_bytes(b"old")
    snapshot = _snapshot(SnapshotKind.CURRENT)
    calls = 0

    def collect(_kind: SnapshotKind) -> Snapshot:
        nonlocal calls
        calls += 1
        return snapshot

    monkeypatch.setattr(cli_module, "collect_snapshot", collect)
    assert cli_module.main(["scan", "--output", str(output)]) == 3
    assert calls == 0
    assert output.read_bytes() == b"old"
    assert cli_module.main(["scan", "--output", str(output), "--force"]) == 0
    assert calls == 1
    assert output.read_bytes() == serialize_snapshot(snapshot)


def test_scan_partial_still_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "current.json"
    snapshot = _snapshot(SnapshotKind.CURRENT, complete=False)
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: snapshot)
    assert cli_module.main(["scan", "--output", str(output)]) == 2
    assert output.read_bytes() == serialize_snapshot(snapshot)


@pytest.mark.parametrize(
    ("exc", "code"),
    ((UnsupportedPlatformError("unsupported"), 8), (SnapshotCollectionError("fatal"), 3)),
)
def test_scan_collection_error_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exc: Exception, code: int
) -> None:
    output = tmp_path / "current.json"
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: (_ for _ in ()).throw(exc))
    assert cli_module.main(["scan", "--output", str(output)]) == code
    assert not output.exists()


def test_scan_filesystem_failure_maps_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli_module, "collect_snapshot", lambda _kind: _snapshot(SnapshotKind.CURRENT))
    monkeypatch.setattr(
        cli_module, "_atomic_write_bytes", lambda *_args: (_ for _ in ()).throw(cli_module._OutputIOError("write"))
    )
    assert cli_module.main(["scan", "--output", str(tmp_path / "x.json")]) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err


def test_current_loader_accepts_canonical_current(tmp_path: Path) -> None:
    path = tmp_path / "current.json"
    snapshot = _current_file(path)
    loaded = cli_module._load_current_path(path)
    assert loaded == snapshot
    assert serialize_snapshot(loaded) == path.read_bytes()


@pytest.mark.parametrize(
    "payload",
    (
        b"\xef\xbb\xbf{}",
        b"",
        b"   \n",
        b"\xff",
        b"{",
        b"[]\n",
    ),
)
def test_current_loader_malformed_inputs(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "current.json"
    path.write_bytes(payload)
    with pytest.raises(cli_module._CurrentSnapshotError):
        cli_module._load_current_path(path)


def test_current_loader_schema_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "current.json"
    mapping = snapshot_to_mapping(_snapshot(SnapshotKind.CURRENT))
    mapping["schema_version"] = "driftape.snapshot.v999"
    path.write_text(json.dumps(mapping), encoding="utf-8")
    with pytest.raises(cli_module._CurrentSchemaMismatchError):
        cli_module._load_current_path(path)


@pytest.mark.parametrize("mutation", ("missing", "wrong_type", "baseline_kind", "pretty"))
def test_current_loader_rejects_invalid_or_noncanonical(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "current.json"
    mapping = snapshot_to_mapping(_snapshot(SnapshotKind.CURRENT))
    if mutation == "missing":
        del mapping["host"]
        data = json.dumps(mapping, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    elif mutation == "wrong_type":
        mapping["host"] = "bad"
        data = json.dumps(mapping, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    elif mutation == "baseline_kind":
        mapping["snapshot_kind"] = "baseline"
        data = json.dumps(mapping, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    else:
        data = json.dumps(mapping, indent=2, sort_keys=True).encode() + b"\n"
    path.write_bytes(data)
    with pytest.raises(cli_module._CurrentSnapshotError):
        cli_module._load_current_path(path)


def test_current_loader_io_failure(tmp_path: Path) -> None:
    with pytest.raises(cli_module._CurrentIOError):
        cli_module._load_current_path(tmp_path / "missing.json")


def test_diff_real_pipeline_no_changes_exact_report_and_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output_path = tmp_path / "changes.json"
    baseline = _baseline_pair(baseline_path)
    _current_file(current_path)

    assert cli_module.main(
        ["diff", str(baseline_path), str(current_path), "--output", str(output_path)]
    ) == 0
    report_mapping = json.loads(output_path.read_text(encoding="utf-8"))
    assert report_mapping["baseline"]["path"] == str(baseline_path)
    assert report_mapping["current"]["path"] == str(current_path)
    assert report_mapping["baseline"]["sha256"] == hashlib.sha256(
        serialize_snapshot(baseline)
    ).hexdigest()
    assert report_mapping["comparison"]["status"] == "complete"
    assert report_mapping["changes"] == []
    captured = capsys.readouterr()
    assert captured.out.startswith("DriftApe 0.1.0\n\nBaseline integrity: VERIFIED\n")
    assert f"Output: {output_path}\n" in captured.out
    assert "{" not in captured.out
    assert captured.err == ""


def test_diff_changes_exit_1(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _baseline_pair(baseline_path)
    current = _snapshot(
        SnapshotKind.CURRENT,
        local_users=(LocalUser("S-1-5-21-1", "alice", True, PrincipalSource.LOCAL),),
    )
    _current_file(current_path, current)
    assert cli_module.main(["diff", str(baseline_path), str(current_path)]) == 1
    assert (Path.cwd() / "changes.json").exists()
    (Path.cwd() / "changes.json").unlink()


@pytest.mark.parametrize("with_change", (False, True))
def test_diff_partial_precedence_exit_2(tmp_path: Path, with_change: bool) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output = tmp_path / "changes.json"
    baseline = _snapshot(SnapshotKind.BASELINE, complete=False)
    current = _snapshot(
        SnapshotKind.CURRENT,
        complete=False,
        local_users=(
            (LocalUser("S-1-5-21-1", "alice", True, PrincipalSource.LOCAL),)
            if with_change
            else ()
        ),
    )
    _baseline_pair(baseline_path, baseline)
    _current_file(current_path, current)
    assert cli_module.main(
        ["diff", str(baseline_path), str(current_path), "--output", str(output)]
    ) == 2
    assert json.loads(output.read_text())["comparison"]["status"] == "partial"


def test_diff_composes_accepted_apis_and_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = _snapshot(SnapshotKind.BASELINE)
    current = _snapshot(SnapshotKind.CURRENT, timestamp=datetime(2026, 8, 28, 11, 22, 33, tzinfo=timezone.utc))
    diff_result = DiffResult(ComparisonStatus.COMPLETE, (), (), ())
    output = tmp_path / "out.json"
    seen: dict[str, Any] = {}

    monkeypatch.setattr(cli_module, "load_baseline_path", lambda path: seen.setdefault("baseline_path", path) or baseline)
    # setdefault above returns Path, so use explicit functions instead
    def load(path: Path) -> Snapshot:
        seen["baseline_path"] = path
        return baseline

    def load_current(path: Path) -> Snapshot:
        seen["current_path"] = path
        return current

    def compare(b: Snapshot, c: Snapshot) -> DiffResult:
        seen["compare"] = (b, c)
        return diff_result

    def evaluate(changes: tuple[Change, ...]) -> tuple[()]:
        seen["evaluate"] = changes
        return ()

    def report_builder(**kwargs: Any) -> Any:
        seen["report"] = kwargs
        return build_report(**kwargs)

    monkeypatch.setattr(cli_module, "load_baseline_path", load)
    monkeypatch.setattr(cli_module, "_load_current_path", load_current)
    monkeypatch.setattr(cli_module, "compare_snapshots", compare)
    monkeypatch.setattr(cli_module, "evaluate_changes", evaluate)
    monkeypatch.setattr(cli_module, "build_report", report_builder)
    monkeypatch.setattr(cli_module, "_utc_timestamp", lambda value=None: "2026-08-28T12:34:56Z" if value is None else cli_module._utc_timestamp.__wrapped__(value) if hasattr(cli_module._utc_timestamp, "__wrapped__") else value.strftime("%Y-%m-%dT%H:%M:%SZ"))

    assert cli_module.main(["diff", "B-LABEL", "C-LABEL", "--output", str(output)]) == 0
    assert seen["baseline_path"] == Path("B-LABEL")
    assert seen["current_path"] == Path("C-LABEL")
    assert seen["compare"] == (baseline, current)
    assert seen["evaluate"] is diff_result.changes
    kwargs = seen["report"]
    assert kwargs["baseline_path"] == "B-LABEL"
    assert kwargs["current_path"] == "C-LABEL"
    assert kwargs["baseline_sha256"] == hashlib.sha256(serialize_snapshot(baseline)).hexdigest()
    assert kwargs["generated_at_utc"] == "2026-08-28T12:34:56Z"
    assert kwargs["diff_result"] is diff_result
    assert kwargs["findings"] == ()


@pytest.mark.parametrize(
    ("stage", "exc", "code"),
    (
        ("baseline", BaselineIntegrityError("integrity"), 4),
        ("baseline", BaselineSchemaMismatchError("schema"), 5),
        ("baseline", InvalidManifestError("manifest"), 6),
        ("baseline", InvalidBaselineSnapshotError("baseline"), 6),
        ("current", cli_module._CurrentSchemaMismatchError("schema"), 5),
        ("current", cli_module._CurrentSnapshotError("invalid"), 6),
        ("compare", HostMismatchError("host"), 7),
        ("compare", InvalidDiffInputError("diff"), 6),
        ("baseline", BaselineIOError("io"), 3),
        ("current", cli_module._CurrentIOError("io"), 3),
        ("compare", RuntimeError("unexpected"), 3),
    ),
)
def test_diff_frozen_error_mapping_no_output_no_success_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stage: str,
    exc: Exception,
    code: int,
) -> None:
    output = tmp_path / "changes.json"
    baseline = _snapshot(SnapshotKind.BASELINE)
    current = _snapshot(SnapshotKind.CURRENT)

    def maybe_raise(name: str, value: Any) -> Any:
        if stage == name:
            raise exc
        return value

    monkeypatch.setattr(cli_module, "load_baseline_path", lambda _p: maybe_raise("baseline", baseline))
    monkeypatch.setattr(cli_module, "_load_current_path", lambda _p: maybe_raise("current", current))
    monkeypatch.setattr(cli_module, "compare_snapshots", lambda _b, _c: maybe_raise("compare", DiffResult(ComparisonStatus.COMPLETE, (), (), ())))

    assert cli_module.main(["diff", "base.json", "cur.json", "--output", str(output)]) == code
    assert not output.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
    assert len(captured.err) < 1000


def test_diff_output_conflict_prevents_input_load_and_preserves_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "changes.json"
    output.write_bytes(b"old")
    monkeypatch.setattr(cli_module, "load_baseline_path", lambda _p: pytest.fail("loaded"))
    assert cli_module.main(["diff", "base", "current", "--output", str(output)]) == 3
    assert output.read_bytes() == b"old"


def test_diff_force_replaces_existing_output(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output = tmp_path / "changes.json"
    _baseline_pair(baseline_path)
    _current_file(current_path)
    output.write_bytes(b"old")
    assert cli_module.main(
        ["diff", str(baseline_path), str(current_path), "--output", str(output), "--force"]
    ) == 0
    assert output.read_bytes() != b"old"
    assert output.read_bytes().endswith(b"\n")


def test_atomic_writer_same_directory_and_os_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "nested" / "out.json"
    real_mkstemp = tempfile.mkstemp
    real_replace = cli_module.os.replace
    observed: dict[str, Any] = {}

    def mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        observed["dir"] = kwargs["dir"]
        return real_mkstemp(*args, **kwargs)

    def replace_spy(src: Any, dst: Any) -> None:
        observed["replace"] = (Path(src), Path(dst))
        real_replace(src, dst)

    monkeypatch.setattr(cli_module.tempfile, "mkstemp", mkstemp)
    monkeypatch.setattr(cli_module.os, "replace", replace_spy)
    cli_module._atomic_write_bytes(output, b"exact\n")
    assert Path(observed["dir"]) == output.parent
    assert observed["replace"][1] == output
    assert observed["replace"][0].parent == output.parent
    assert output.read_bytes() == b"exact\n"


def test_atomic_writer_cleanup_and_old_target_survives_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "out.json"
    output.write_bytes(b"old")
    monkeypatch.setattr(
        cli_module.os,
        "replace",
        lambda _src, _dst: (_ for _ in ()).throw(OSError("replace failed")),
    )
    with pytest.raises(cli_module._OutputIOError):
        cli_module._atomic_write_bytes(output, b"new")
    assert output.read_bytes() == b"old"
    assert list(tmp_path.glob(".out.json.*.tmp")) == []


def test_diff_summary_only_after_successful_output_write(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = _snapshot(SnapshotKind.BASELINE)
    current = _snapshot(SnapshotKind.CURRENT)
    monkeypatch.setattr(cli_module, "load_baseline_path", lambda _p: baseline)
    monkeypatch.setattr(cli_module, "_load_current_path", lambda _p: current)
    monkeypatch.setattr(
        cli_module,
        "_atomic_write_bytes",
        lambda *_args: (_ for _ in ()).throw(cli_module._OutputIOError("failed")),
    )
    assert cli_module.main(["diff", "b", "c", "--output", "out.json"]) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err


def test_scope_has_no_forbidden_implementation_markers() -> None:
    source = Path(cli_module.__file__).read_text(encoding="utf-8")
    forbidden = (
        "PowerShell scripts",
        "Get-LocalUser",
        "Get-LocalGroupMember",
        "Get-CimInstance",
        "Get-ScheduledTask",
        "Export-ScheduledTask",
        "Get-MpPreference",
        "Get-MpComputerStatus",
        "Invoke-Command",
        "New-PSSession",
        "ExecutionPolicy Bypass",
        "EncodedCommand",
        "shell=True",
        "severity rule tables",
        "DA-USR-",
        "DA-ADM-",
        "DA-SVC-",
        "DA-TASK-",
        "DA-DEF-",
        "HTML",
        "remote scanning",
        "remediation",
    )
    assert all(marker not in source for marker in forbidden)
    assert "driftape.collectors" not in source
    assert "driftape.acquisition" not in source
