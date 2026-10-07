"""Operational command-line interface for DriftApe v0.1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from driftape import __version__
from driftape.constants import APPLICATION_NAME, SNAPSHOT_SCHEMA_VERSION
from driftape.diff import (
    ComparisonStatus,
    DiffSchemaMismatchError,
    HostMismatchError,
    InvalidDiffInputError,
    compare_snapshots,
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
from driftape.models import Snapshot, SnapshotKind
from driftape.platform_windows import UnsupportedPlatformError
from driftape.reporting import (
    InvalidReportInputError,
    build_report,
    render_terminal_summary,
    serialize_report,
)
from driftape.rules import InvalidRuleInputError, evaluate_changes
from driftape.serialization import SnapshotSerializationError, serialize_snapshot
from driftape.snapshot import SnapshotCollectionError, collect_snapshot
from driftape.validation import SnapshotValidationError, validate_snapshot

_UTF8_BOM = b"\xef\xbb\xbf"


class _CurrentInputError(RuntimeError):
    """Base class for private CURRENT-input failures."""


class _CurrentIOError(_CurrentInputError):
    """CURRENT input could not be read."""


class _CurrentSchemaMismatchError(_CurrentInputError):
    """CURRENT input declares an incompatible snapshot schema."""


class _CurrentSnapshotError(_CurrentInputError):
    """CURRENT input is malformed, invalid, or noncanonical."""


class _OutputIOError(RuntimeError):
    """CLI-owned non-baseline output persistence failed."""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driftape",
        description="Local defensive Windows drift utility.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="show the DriftApe version and exit",
    )

    subparsers = parser.add_subparsers(dest="command")

    baseline = subparsers.add_parser("baseline", help="collect and persist a baseline")
    baseline.add_argument("--output", default="baseline.json", metavar="PATH")
    baseline.add_argument("--force", action="store_true")

    scan = subparsers.add_parser("scan", help="collect and persist a current snapshot")
    scan.add_argument("--output", default="current.json", metavar="PATH")
    scan.add_argument("--force", action="store_true")

    diff = subparsers.add_parser("diff", help="compare a baseline and current snapshot")
    diff.add_argument("BASELINE")
    diff.add_argument("CURRENT")
    diff.add_argument("--output", default="changes.json", metavar="PATH")
    diff.add_argument("--force", action="store_true")

    return parser


def _utc_timestamp(value: datetime | None = None) -> str:
    current = datetime.now(timezone.utc) if value is None else value
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    current = current.astimezone(timezone.utc).replace(microsecond=0)
    return (
        f"{current.year:04d}-{current.month:02d}-{current.day:02d}"
        f"T{current.hour:02d}:{current.minute:02d}:{current.second:02d}Z"
    )


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        raise _OutputIOError("failed to inspect output path") from exc


def _preflight_output(paths: tuple[Path, ...], force: bool) -> None:
    if force:
        return
    for path in paths:
        if _path_exists(path):
            raise _OutputIOError(f"output already exists: {path}")


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    """Atomically persist exact bytes to one non-baseline CLI output path."""
    if not isinstance(target, Path):
        raise TypeError("target must be a pathlib.Path")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    descriptor: int | None = None
    temp_path: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        temp_path = Path(temp_name)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, target)
        temp_path = None
    except OSError as exc:
        raise _OutputIOError("failed to persist output atomically") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def _load_current_path(current_path: Path) -> Snapshot:
    """Load exactly one strict canonical CURRENT snapshot from a caller path."""
    try:
        data = current_path.read_bytes()
    except OSError as exc:
        raise _CurrentIOError("failed to read current snapshot") from exc

    if data.startswith(_UTF8_BOM):
        raise _CurrentSnapshotError("current snapshot must not contain a UTF-8 BOM")
    if not data or data.strip() == b"":
        raise _CurrentSnapshotError("current snapshot is empty")

    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _CurrentSnapshotError("current snapshot is not valid UTF-8") from exc

    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _CurrentSnapshotError("current snapshot is not valid JSON") from exc
    if not isinstance(parsed, Mapping):
        raise _CurrentSnapshotError("current snapshot root must be an object")

    raw = cast(Mapping[str, object], parsed)
    schema_version = raw.get("schema_version")
    if schema_version.__class__ is str and schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise _CurrentSchemaMismatchError("current snapshot schema version is unsupported")

    try:
        snapshot = validate_snapshot(raw)
    except SnapshotValidationError as exc:
        raise _CurrentSnapshotError("current snapshot validation failed") from exc

    if snapshot.snapshot_kind is not SnapshotKind.CURRENT:
        raise _CurrentSnapshotError("current snapshot kind must be current")

    try:
        canonical_bytes = serialize_snapshot(snapshot)
    except (SnapshotSerializationError, TypeError, ValueError) as exc:
        raise _CurrentSnapshotError("current snapshot cannot be serialized") from exc
    if canonical_bytes != data:
        raise _CurrentSnapshotError("current snapshot bytes are not canonical")
    return snapshot


def _print_collection_summary(
    *,
    output_path: Path,
    complete: bool,
    manifest_path: Path | None = None,
) -> None:
    print(f"{APPLICATION_NAME} {__version__}")
    print(f"Output: {output_path}")
    if manifest_path is not None:
        print(f"Manifest: {manifest_path}")
    print(f"Collection: {'COMPLETE' if complete else 'PARTIAL'}")


def _print_error(message: str) -> None:
    print(f"{APPLICATION_NAME}: {message}", file=sys.stderr)


def _run_baseline(output_label: str, force: bool) -> int:
    output_path = Path(output_label)
    try:
        manifest_path = derive_baseline_manifest_path(output_path)
        _preflight_output((output_path, manifest_path), force)
        snapshot = collect_snapshot(SnapshotKind.BASELINE)
        write_baseline_path(snapshot, output_path)
    except UnsupportedPlatformError as exc:
        _print_error(str(exc))
        return 8
    except (SnapshotCollectionError, BaselineIOError, _OutputIOError) as exc:
        _print_error(str(exc))
        return 3
    except Exception as exc:
        _print_error(f"operational failure: {exc}")
        return 3

    _print_collection_summary(
        output_path=output_path,
        manifest_path=manifest_path,
        complete=snapshot.collection.complete,
    )
    return 0 if snapshot.collection.complete else 2


def _run_scan(output_label: str, force: bool) -> int:
    output_path = Path(output_label)
    try:
        _preflight_output((output_path,), force)
        snapshot = collect_snapshot(SnapshotKind.CURRENT)
        snapshot_bytes = serialize_snapshot(snapshot)
        _atomic_write_bytes(output_path, snapshot_bytes)
    except UnsupportedPlatformError as exc:
        _print_error(str(exc))
        return 8
    except (SnapshotCollectionError, _OutputIOError) as exc:
        _print_error(str(exc))
        return 3
    except (SnapshotSerializationError, TypeError, ValueError) as exc:
        _print_error(f"snapshot serialization failed: {exc}")
        return 3
    except Exception as exc:
        _print_error(f"operational failure: {exc}")
        return 3

    _print_collection_summary(
        output_path=output_path,
        complete=snapshot.collection.complete,
    )
    return 0 if snapshot.collection.complete else 2


def _run_diff(
    baseline_label: str,
    current_label: str,
    output_label: str,
    force: bool,
) -> int:
    baseline_path = Path(baseline_label)
    current_path = Path(current_label)
    output_path = Path(output_label)

    try:
        _preflight_output((output_path,), force)
        baseline = load_baseline_path(baseline_path)
        current = _load_current_path(current_path)
        diff_result = compare_snapshots(baseline, current)
        findings = evaluate_changes(diff_result.changes)
        baseline_bytes = serialize_snapshot(baseline)
        report = build_report(
            generated_at_utc=_utc_timestamp(),
            baseline_path=baseline_label,
            baseline_sha256=hashlib.sha256(baseline_bytes).hexdigest(),
            baseline_collected_at_utc=_utc_timestamp(baseline.collected_at_utc),
            current_path=current_label,
            current_collected_at_utc=_utc_timestamp(current.collected_at_utc),
            diff_result=diff_result,
            findings=findings,
        )
        report_bytes = serialize_report(report)
        _atomic_write_bytes(output_path, report_bytes)
        terminal_text = render_terminal_summary(report, output_label)
    except BaselineIntegrityError as exc:
        _print_error(str(exc))
        return 4
    except (BaselineSchemaMismatchError, DiffSchemaMismatchError, _CurrentSchemaMismatchError) as exc:
        _print_error(str(exc))
        return 5
    except (
        InvalidManifestError,
        InvalidBaselineSnapshotError,
        InvalidDiffInputError,
        _CurrentSnapshotError,
    ) as exc:
        _print_error(str(exc))
        return 6
    except HostMismatchError as exc:
        _print_error(str(exc))
        return 7
    except (BaselineIOError, _CurrentIOError, _OutputIOError) as exc:
        _print_error(str(exc))
        return 3
    except (
        InvalidRuleInputError,
        InvalidReportInputError,
        SnapshotSerializationError,
        TypeError,
        ValueError,
    ) as exc:
        _print_error(f"internal orchestration failure: {exc}")
        return 3
    except Exception as exc:
        _print_error(f"operational failure: {exc}")
        return 3

    sys.stdout.write(terminal_text)
    if diff_result.status is ComparisonStatus.PARTIAL:
        return 2
    return 1 if diff_result.changes else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the frozen DriftApe v0.1 CLI dispatcher."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"{APPLICATION_NAME} {__version__}")
        return 0

    if args.command == "baseline":
        return _run_baseline(args.output, args.force)
    if args.command == "scan":
        return _run_scan(args.output, args.force)
    if args.command == "diff":
        return _run_diff(args.BASELINE, args.CURRENT, args.output, args.force)

    parser.print_help()
    return 0
