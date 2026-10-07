"""Baseline persistence and byte-integrity support for DriftApe v0.1."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from driftape.constants import BASELINE_MANIFEST_SCHEMA_VERSION, SNAPSHOT_SCHEMA_VERSION
from driftape.models import ErrorCode, Snapshot, SnapshotKind
from driftape.serialization import (
    SnapshotSerializationError,
    serialize_snapshot,
)
from driftape.validation import SnapshotValidationError, validate_snapshot

_BASELINE_FILE = "baseline.json"
_MANIFEST_FILE = "baseline.manifest.json"
_HASH_ALGORITHM = "sha256"
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "tool_version",
        "snapshot_schema_version",
        "baseline_file",
        "hash_algorithm",
        "baseline_sha256",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_UTF8_BOM = b"\xef\xbb\xbf"


class BaselineError(RuntimeError):
    """Base error for baseline persistence and integrity failures."""

    code: ErrorCode


class BaselineIOError(BaselineError):
    """Filesystem access for a baseline artifact failed."""

    code = ErrorCode.IO_ERROR


class InvalidManifestError(BaselineError):
    """The baseline manifest is malformed or inconsistently bound."""

    code = ErrorCode.INVALID_MANIFEST


class BaselineSchemaMismatchError(BaselineError):
    """A persisted baseline schema version is unsupported."""

    code = ErrorCode.SCHEMA_MISMATCH


class BaselineIntegrityError(BaselineError):
    """The persisted baseline bytes do not match the manifest digest."""

    code = ErrorCode.INTEGRITY_FAILURE


class InvalidBaselineSnapshotError(BaselineError):
    """The persisted or supplied baseline snapshot is invalid."""

    code = ErrorCode.INVALID_SNAPSHOT


@dataclass(frozen=True, slots=True)
class BaselineManifest:
    """Typed v0.1 baseline manifest."""

    schema_version: str
    tool_version: str
    snapshot_schema_version: str
    baseline_file: str
    hash_algorithm: str
    baseline_sha256: str


def _require_snapshot(snapshot: object) -> Snapshot:
    if not isinstance(snapshot, Snapshot):
        raise TypeError("snapshot must be a Snapshot")
    return snapshot


def _require_directory(directory: object) -> Path:
    if not isinstance(directory, Path):
        raise TypeError("directory must be a pathlib.Path")
    return directory


def _require_baseline_path(baseline_path: object) -> Path:
    if not isinstance(baseline_path, Path):
        raise TypeError("baseline_path must be a pathlib.Path")
    if baseline_path.name == "":
        raise ValueError("baseline_path must include a final filename component")
    return baseline_path


def _require_manifest(manifest: object) -> BaselineManifest:
    if not isinstance(manifest, BaselineManifest):
        raise TypeError("manifest must be a BaselineManifest")
    return manifest


def _require_baseline_kind(snapshot: Snapshot) -> None:
    if snapshot.snapshot_kind is not SnapshotKind.BASELINE:
        raise InvalidBaselineSnapshotError("snapshot kind must be baseline")


def _build_baseline_manifest(
    snapshot: Snapshot,
    baseline_bytes: bytes,
    baseline_file: str,
) -> BaselineManifest:
    checked_snapshot = _require_snapshot(snapshot)
    if baseline_bytes.__class__ is not bytes:
        raise TypeError("baseline_bytes must be bytes")
    _require_baseline_kind(checked_snapshot)

    try:
        canonical_bytes = serialize_snapshot(checked_snapshot)
    except (SnapshotSerializationError, TypeError, ValueError) as exc:
        raise InvalidBaselineSnapshotError(
            "snapshot cannot be serialized canonically"
        ) from exc
    if canonical_bytes != baseline_bytes:
        raise InvalidBaselineSnapshotError(
            "baseline bytes do not match canonical snapshot serialization"
        )

    digest = hashlib.sha256(baseline_bytes).hexdigest()
    return BaselineManifest(
        schema_version=BASELINE_MANIFEST_SCHEMA_VERSION,
        tool_version=checked_snapshot.tool_version,
        snapshot_schema_version=checked_snapshot.schema_version,
        baseline_file=baseline_file,
        hash_algorithm=_HASH_ALGORITHM,
        baseline_sha256=digest,
    )


def build_baseline_manifest(
    snapshot: Snapshot,
    baseline_bytes: bytes,
) -> BaselineManifest:
    """Build a fixed-name manifest that binds exact canonical baseline bytes."""
    return _build_baseline_manifest(snapshot, baseline_bytes, _BASELINE_FILE)


def baseline_manifest_to_mapping(
    manifest: BaselineManifest,
) -> dict[str, object]:
    """Convert a manifest to its exact persisted primitive mapping."""
    checked_manifest = _require_manifest(manifest)
    return {
        "schema_version": checked_manifest.schema_version,
        "tool_version": checked_manifest.tool_version,
        "snapshot_schema_version": checked_manifest.snapshot_schema_version,
        "baseline_file": checked_manifest.baseline_file,
        "hash_algorithm": checked_manifest.hash_algorithm,
        "baseline_sha256": checked_manifest.baseline_sha256,
    }


def serialize_baseline_manifest(
    manifest: BaselineManifest,
) -> bytes:
    """Serialize a baseline manifest to canonical UTF-8 JSON bytes."""
    mapping = baseline_manifest_to_mapping(manifest)
    text = json.dumps(
        mapping,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"{text}\n".encode("utf-8")


def _manifest_string(raw: Mapping[str, object], key: str) -> str:
    value = raw[key]
    if not isinstance(value, str) or value.__class__ is not str or value == "":
        raise InvalidManifestError(f"manifest field {key!r} must be a non-empty string")
    return value


def _validate_manifest_baseline_file(
    baseline_file: str,
    expected_baseline_file: str,
) -> None:
    if baseline_file != expected_baseline_file:
        raise InvalidManifestError(
            "manifest baseline_file does not match baseline path"
        )
    if (
        baseline_file in {".", ".."}
        or "/" in baseline_file
        or "\\" in baseline_file
        or ".." in baseline_file
        or _WINDOWS_DRIVE_RE.match(baseline_file) is not None
    ):
        raise InvalidManifestError("manifest baseline_file must be a plain filename")


def _validate_baseline_manifest(
    raw: Mapping[str, object],
    expected_baseline_file: str,
) -> BaselineManifest:
    if not isinstance(raw, Mapping):
        raise InvalidManifestError("manifest root must be an object")
    if set(raw.keys()) != _MANIFEST_KEYS:
        raise InvalidManifestError("manifest must contain exactly the required fields")

    schema_version = _manifest_string(raw, "schema_version")
    tool_version = _manifest_string(raw, "tool_version")
    snapshot_schema_version = _manifest_string(raw, "snapshot_schema_version")
    baseline_file = _manifest_string(raw, "baseline_file")
    hash_algorithm = _manifest_string(raw, "hash_algorithm")
    baseline_sha256 = _manifest_string(raw, "baseline_sha256")

    if schema_version != BASELINE_MANIFEST_SCHEMA_VERSION:
        raise BaselineSchemaMismatchError(
            "baseline manifest schema version is unsupported"
        )
    if snapshot_schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise BaselineSchemaMismatchError("snapshot schema version is unsupported")
    _validate_manifest_baseline_file(baseline_file, expected_baseline_file)
    if hash_algorithm != _HASH_ALGORITHM:
        raise InvalidManifestError("manifest hash_algorithm must be sha256")
    if _SHA256_RE.fullmatch(baseline_sha256) is None:
        raise InvalidManifestError(
            "manifest baseline_sha256 must be lowercase SHA-256 hex"
        )

    return BaselineManifest(
        schema_version=schema_version,
        tool_version=tool_version,
        snapshot_schema_version=snapshot_schema_version,
        baseline_file=baseline_file,
        hash_algorithm=hash_algorithm,
        baseline_sha256=baseline_sha256,
    )


def validate_baseline_manifest(
    raw: Mapping[str, object],
) -> BaselineManifest:
    """Strictly validate one fixed-name v0.1 baseline manifest mapping."""
    return _validate_baseline_manifest(raw, _BASELINE_FILE)


def derive_baseline_manifest_path(baseline_path: Path) -> Path:
    """Derive the same-directory manifest path for a caller-selected baseline path."""
    checked_path = _require_baseline_path(baseline_path)
    if checked_path.suffix:
        return checked_path.with_suffix(".manifest.json")
    return checked_path.with_name(f"{checked_path.name}.manifest.json")


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_replace_bytes(target: Path, data: bytes) -> None:
    descriptor: int | None = None
    temp_path: Path | None = None
    try:
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
        _fsync_directory(target.parent)
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


def _write_baseline_pair(
    snapshot: Snapshot,
    baseline_path: Path,
    manifest_path: Path,
    manifest_baseline_file: str,
) -> None:
    checked_snapshot = _require_snapshot(snapshot)
    _require_baseline_kind(checked_snapshot)

    try:
        baseline_bytes = serialize_snapshot(checked_snapshot)
    except (SnapshotSerializationError, TypeError, ValueError) as exc:
        raise InvalidBaselineSnapshotError(
            "snapshot cannot be serialized canonically"
        ) from exc
    manifest = _build_baseline_manifest(
        checked_snapshot,
        baseline_bytes,
        manifest_baseline_file,
    )
    manifest_bytes = serialize_baseline_manifest(manifest)

    try:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_replace_bytes(baseline_path, baseline_bytes)
        _atomic_replace_bytes(manifest_path, manifest_bytes)
    except OSError as exc:
        raise BaselineIOError("failed to write baseline artifacts") from exc


def write_baseline(snapshot: Snapshot, directory: Path) -> None:
    """Persist the accepted fixed-name baseline and manifest pair."""
    checked_directory = _require_directory(directory)
    _write_baseline_pair(
        snapshot,
        checked_directory / _BASELINE_FILE,
        checked_directory / _MANIFEST_FILE,
        _BASELINE_FILE,
    )


def write_baseline_path(snapshot: Snapshot, baseline_path: Path) -> None:
    """Persist a baseline at a caller-selected path with a bound manifest."""
    checked_path = _require_baseline_path(baseline_path)
    _write_baseline_pair(
        snapshot,
        checked_path,
        derive_baseline_manifest_path(checked_path),
        checked_path.name,
    )


def _read_artifact(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise BaselineIOError(f"failed to read {label}") from exc


def _parse_manifest_bytes(
    data: bytes,
    expected_baseline_file: str = _BASELINE_FILE,
) -> BaselineManifest:
    if data.startswith(_UTF8_BOM):
        raise InvalidManifestError("baseline manifest must not contain a UTF-8 BOM")
    if not data or data.strip() == b"":
        raise InvalidManifestError("baseline manifest is empty")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InvalidManifestError("baseline manifest is not valid UTF-8") from exc
    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidManifestError("baseline manifest is not valid JSON") from exc
    if not isinstance(parsed, Mapping):
        raise InvalidManifestError("baseline manifest root must be an object")

    manifest = _validate_baseline_manifest(
        cast(Mapping[str, object], parsed),
        expected_baseline_file,
    )
    if serialize_baseline_manifest(manifest) != data:
        raise InvalidManifestError("baseline manifest bytes are not canonical")
    return manifest


def _parse_baseline_bytes(data: bytes) -> Snapshot:
    if data.startswith(_UTF8_BOM):
        raise InvalidBaselineSnapshotError(
            "baseline snapshot must not contain a UTF-8 BOM"
        )
    if not data or data.strip() == b"":
        raise InvalidBaselineSnapshotError("baseline snapshot is empty")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InvalidBaselineSnapshotError(
            "baseline snapshot is not valid UTF-8"
        ) from exc
    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidBaselineSnapshotError(
            "baseline snapshot is not valid JSON"
        ) from exc
    if not isinstance(parsed, Mapping):
        raise InvalidBaselineSnapshotError("baseline snapshot root must be an object")

    raw = cast(Mapping[str, object], parsed)
    schema_version = raw.get("schema_version")
    if schema_version.__class__ is str and schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise BaselineSchemaMismatchError(
            "baseline snapshot schema version is unsupported"
        )

    try:
        snapshot = validate_snapshot(raw)
    except SnapshotValidationError as exc:
        raise InvalidBaselineSnapshotError(
            "baseline snapshot validation failed"
        ) from exc

    try:
        canonical_bytes = serialize_snapshot(snapshot)
    except (SnapshotSerializationError, TypeError, ValueError) as exc:
        raise InvalidBaselineSnapshotError(
            "baseline snapshot cannot be serialized"
        ) from exc
    if canonical_bytes != data:
        raise InvalidBaselineSnapshotError("baseline snapshot bytes are not canonical")
    if snapshot.snapshot_kind is not SnapshotKind.BASELINE:
        raise InvalidBaselineSnapshotError("persisted snapshot kind must be baseline")
    return snapshot


def _load_baseline_pair(
    baseline_path: Path,
    manifest_path: Path,
    expected_baseline_file: str,
) -> Snapshot:
    manifest_bytes = _read_artifact(manifest_path, "baseline manifest")
    manifest = _parse_manifest_bytes(manifest_bytes, expected_baseline_file)

    baseline_bytes = _read_artifact(baseline_path, "baseline")
    actual_digest = hashlib.sha256(baseline_bytes).hexdigest()
    if not hmac.compare_digest(actual_digest, manifest.baseline_sha256):
        raise BaselineIntegrityError("baseline digest does not match manifest")

    snapshot = _parse_baseline_bytes(baseline_bytes)
    if manifest.snapshot_schema_version != snapshot.schema_version:
        raise BaselineSchemaMismatchError(
            "manifest and baseline snapshot schemas differ"
        )
    if manifest.tool_version != snapshot.tool_version:
        raise InvalidManifestError("manifest and baseline tool versions differ")
    return snapshot


def load_baseline(directory: Path) -> Snapshot:
    """Load the accepted fixed-name persisted baseline snapshot."""
    checked_directory = _require_directory(directory)
    return _load_baseline_pair(
        checked_directory / _BASELINE_FILE,
        checked_directory / _MANIFEST_FILE,
        _BASELINE_FILE,
    )


def load_baseline_path(baseline_path: Path) -> Snapshot:
    """Load a caller-selected baseline without trusting manifest path data."""
    checked_path = _require_baseline_path(baseline_path)
    return _load_baseline_pair(
        checked_path,
        derive_baseline_manifest_path(checked_path),
        checked_path.name,
    )
