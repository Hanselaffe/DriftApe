"""WP9 baseline integrity and persistence tests."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import driftape.integrity as integrity_module
from driftape.constants import (
    BASELINE_MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_SCHEMA_VERSION,
    TOOL_VERSION,
)
from driftape.integrity import (
    BaselineIOError,
    BaselineIntegrityError,
    BaselineManifest,
    BaselineSchemaMismatchError,
    InvalidBaselineSnapshotError,
    InvalidManifestError,
    baseline_manifest_to_mapping,
    build_baseline_manifest,
    derive_baseline_manifest_path,
    load_baseline,
    load_baseline_path,
    serialize_baseline_manifest,
    validate_baseline_manifest,
    write_baseline,
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
    ErrorCode,
    HostInfo,
    ServicesCollectorResult,
    ServicesData,
    Snapshot,
    SnapshotKind,
    TasksCollectorResult,
    TasksData,
    UsersCollectorResult,
    UsersData,
)
from driftape.serialization import serialize_snapshot, snapshot_to_mapping
from driftape.validation import validate_snapshot


def _snapshot(
    *,
    kind: SnapshotKind = SnapshotKind.BASELINE,
    complete: bool = True,
    tool_version: str = TOOL_VERSION,
) -> Snapshot:
    users = UsersCollectorResult(
        status=CollectorStatus.SUCCESS,
        coverage=frozenset({"local_users", "administrators"}),
        data=UsersData(local_users=(), administrators=()),
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
    )
    if not complete:
        tasks = TasksCollectorResult(
            status=CollectorStatus.PARTIAL,
            coverage=frozenset(),
            data=TasksData(tasks=()),
            errors=(),
        )
    return Snapshot(
        schema_version=SNAPSHOT_SCHEMA_VERSION,
        tool_version=tool_version,
        snapshot_kind=kind,
        collected_at_utc=datetime(2026, 8, 25, 15, 30, 45, tzinfo=timezone.utc),
        host=HostInfo(
            hostname="HOST01",
            machine_id_sha256="a" * 64,
            os_name="Windows 11 Pro",
            os_version="10.0.26200",
            os_build="26200",
            architecture="AMD64",
        ),
        collection=CollectionInfo(is_elevated=True, complete=complete),
        collectors=CollectorSet(
            users=users,
            services=services,
            tasks=tasks,
            defender=defender,
        ),
        errors=(),
    )


def _manifest(snapshot: Snapshot | None = None) -> BaselineManifest:
    snap = snapshot or _snapshot()
    data = serialize_snapshot(snap)
    return build_baseline_manifest(snap, data)


def _manifest_mapping(snapshot: Snapshot | None = None) -> dict[str, object]:
    return baseline_manifest_to_mapping(_manifest(snapshot))


def _canonical_json_bytes(mapping: dict[str, object]) -> bytes:
    return (
        json.dumps(mapping, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _rewrite_manifest(
    directory: Path,
    *,
    baseline_bytes: bytes | None = None,
    **updates: object,
) -> None:
    path = directory / "baseline.manifest.json"
    mapping = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(mapping, dict)
    if baseline_bytes is not None:
        mapping["baseline_sha256"] = hashlib.sha256(baseline_bytes).hexdigest()
    mapping.update(updates)
    path.write_bytes(_canonical_json_bytes(mapping))


# T-WP9-001..008: manifest construction.
def test_t_wp9_001_build_manifest_exact_fields() -> None:
    manifest = _manifest()
    assert manifest.schema_version == BASELINE_MANIFEST_SCHEMA_VERSION
    assert set(baseline_manifest_to_mapping(manifest)) == {
        "schema_version",
        "tool_version",
        "snapshot_schema_version",
        "baseline_file",
        "hash_algorithm",
        "baseline_sha256",
    }


def test_t_wp9_002_digest_is_exact_baseline_sha256() -> None:
    snapshot = _snapshot()
    data = serialize_snapshot(snapshot)
    assert build_baseline_manifest(snapshot, data).baseline_sha256 == hashlib.sha256(
        data
    ).hexdigest()


def test_t_wp9_003_manifest_tool_version_from_snapshot() -> None:
    snapshot = _snapshot(tool_version="0.1.0-producer")
    assert _manifest(snapshot).tool_version == "0.1.0-producer"


def test_t_wp9_004_manifest_snapshot_schema_from_snapshot() -> None:
    assert _manifest().snapshot_schema_version == _snapshot().schema_version


def test_t_wp9_005_manifest_baseline_file_exact() -> None:
    assert _manifest().baseline_file == "baseline.json"


def test_t_wp9_006_manifest_hash_algorithm_exact() -> None:
    assert _manifest().hash_algorithm == "sha256"


def test_t_wp9_007_current_snapshot_rejected_by_builder() -> None:
    snapshot = _snapshot(kind=SnapshotKind.CURRENT)
    with pytest.raises(InvalidBaselineSnapshotError):
        build_baseline_manifest(snapshot, serialize_snapshot(snapshot))


def test_t_wp9_008_mismatched_baseline_bytes_rejected() -> None:
    with pytest.raises(InvalidBaselineSnapshotError):
        build_baseline_manifest(_snapshot(), b"{}\n")


# T-WP9-009..015: manifest serialization.
def test_t_wp9_009_manifest_mapping_has_six_keys() -> None:
    assert len(baseline_manifest_to_mapping(_manifest())) == 6


def test_t_wp9_010_manifest_utf8_without_bom() -> None:
    data = serialize_baseline_manifest(_manifest())
    data.decode("utf-8")
    assert not data.startswith(b"\xef\xbb\xbf")


def test_t_wp9_011_manifest_has_exactly_one_trailing_lf() -> None:
    data = serialize_baseline_manifest(_manifest())
    assert data.endswith(b"\n")
    assert not data.endswith(b"\n\n")


def test_t_wp9_012_manifest_is_compact_without_indentation() -> None:
    data = serialize_baseline_manifest(_manifest())
    assert b": " not in data
    assert b", " not in data
    assert data.count(b"\n") == 1


def test_t_wp9_013_manifest_keys_sorted() -> None:
    text = serialize_baseline_manifest(_manifest()).decode()
    assert text.index('"baseline_file"') < text.index('"baseline_sha256"')
    assert text.index('"baseline_sha256"') < text.index('"hash_algorithm"')
    assert text.index('"hash_algorithm"') < text.index('"schema_version"')


def test_t_wp9_014_manifest_serialization_repeats_identically() -> None:
    manifest = _manifest()
    assert serialize_baseline_manifest(manifest) == serialize_baseline_manifest(
        manifest
    )


def test_t_wp9_015_no_dataclass_asdict_serializer() -> None:
    source = inspect.getsource(integrity_module.baseline_manifest_to_mapping)
    assert "asdict" not in source


# T-WP9-016..025: manifest validation.
def test_t_wp9_016_valid_manifest_validates() -> None:
    manifest = _manifest()
    assert (
        validate_baseline_manifest(baseline_manifest_to_mapping(manifest)) == manifest
    )


def test_t_wp9_017_unknown_manifest_field_rejected() -> None:
    raw = _manifest_mapping()
    raw["extra"] = "x"
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


def test_t_wp9_018_missing_manifest_field_rejected() -> None:
    raw = _manifest_mapping()
    del raw["tool_version"]
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


def test_t_wp9_019_wrong_scalar_type_rejected_without_coercion() -> None:
    raw = _manifest_mapping()
    raw["tool_version"] = 1
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


def test_t_wp9_020_wrong_manifest_schema_is_schema_mismatch() -> None:
    raw = _manifest_mapping()
    raw["schema_version"] = "driftape.baseline-manifest.v2"
    with pytest.raises(BaselineSchemaMismatchError):
        validate_baseline_manifest(raw)


def test_t_wp9_021_wrong_snapshot_schema_is_schema_mismatch() -> None:
    raw = _manifest_mapping()
    raw["snapshot_schema_version"] = "driftape.snapshot.v2"
    with pytest.raises(BaselineSchemaMismatchError):
        validate_baseline_manifest(raw)


def test_t_wp9_022_wrong_baseline_file_rejected() -> None:
    raw = _manifest_mapping()
    raw["baseline_file"] = "other.json"
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


def test_t_wp9_023_wrong_hash_algorithm_rejected() -> None:
    raw = _manifest_mapping()
    raw["hash_algorithm"] = "sha512"
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


def test_t_wp9_024_uppercase_digest_rejected() -> None:
    raw = _manifest_mapping()
    raw["baseline_sha256"] = "A" * 64
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


@pytest.mark.parametrize("digest", ["a" * 63, "a" * 65, "g" * 64])
def test_t_wp9_025_wrong_digest_shape_rejected(digest: str) -> None:
    raw = _manifest_mapping()
    raw["baseline_sha256"] = digest
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


# T-WP9-026..035: writes and atomic replacement.
def test_t_wp9_026_write_creates_directory(tmp_path: Path) -> None:
    directory = tmp_path / "nested" / "baseline"
    write_baseline(_snapshot(), directory)
    assert directory.is_dir()


def test_t_wp9_027_write_has_exact_final_artifacts(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    assert {p.name for p in tmp_path.iterdir()} == {
        "baseline.json",
        "baseline.manifest.json",
    }


def test_t_wp9_028_written_baseline_equals_serializer(tmp_path: Path) -> None:
    snapshot = _snapshot()
    write_baseline(snapshot, tmp_path)
    assert (tmp_path / "baseline.json").read_bytes() == serialize_snapshot(snapshot)


def test_t_wp9_029_written_manifest_digest_matches_baseline(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    baseline = (tmp_path / "baseline.json").read_bytes()
    manifest = json.loads((tmp_path / "baseline.manifest.json").read_text())
    assert manifest["baseline_sha256"] == hashlib.sha256(baseline).hexdigest()


def test_t_wp9_030_baseline_replaced_before_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    order: list[str] = []

    def fake_replace(target: Path, data: bytes) -> None:
        del data
        order.append(target.name)

    monkeypatch.setattr(integrity_module, "_atomic_replace_bytes", fake_replace)
    write_baseline(_snapshot(), tmp_path)
    assert order == ["baseline.json", "baseline.manifest.json"]


def test_t_wp9_031_temp_file_is_same_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen_dirs: list[Path] = []
    real_mkstemp = tempfile.mkstemp

    def tracking_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        seen_dirs.append(Path(kwargs["dir"]))
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(integrity_module.tempfile, "mkstemp", tracking_mkstemp)
    integrity_module._atomic_replace_bytes(tmp_path / "x", b"abc")
    assert seen_dirs == [tmp_path]


def test_t_wp9_032_file_fsync_precedes_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def tracking_fsync(fd: int) -> None:
        events.append("fsync")
        real_fsync(fd)

    def tracking_replace(
        src: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        dst: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> None:
        events.append("replace")
        real_replace(src, dst)

    monkeypatch.setattr(integrity_module.os, "fsync", tracking_fsync)
    monkeypatch.setattr(integrity_module.os, "replace", tracking_replace)
    integrity_module._atomic_replace_bytes(tmp_path / "x", b"abc")
    assert events[0:2] == ["fsync", "replace"]


def test_t_wp9_033_atomic_helper_uses_os_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    called = False
    real_replace = os.replace

    def tracking_replace(
        src: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        dst: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> None:
        nonlocal called
        called = True
        real_replace(src, dst)

    monkeypatch.setattr(integrity_module.os, "replace", tracking_replace)
    integrity_module._atomic_replace_bytes(tmp_path / "x", b"abc")
    assert called


def test_t_wp9_034_temp_cleaned_when_replace_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail_replace(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("synthetic")

    monkeypatch.setattr(integrity_module.os, "replace", fail_replace)
    with pytest.raises(OSError):
        integrity_module._atomic_replace_bytes(tmp_path / "x", b"abc")
    assert list(tmp_path.iterdir()) == []


def test_t_wp9_035_filesystem_write_failure_maps_to_io_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail_write(target: Path, data: bytes) -> None:
        del target, data
        raise OSError("synthetic")

    monkeypatch.setattr(integrity_module, "_atomic_replace_bytes", fail_write)
    with pytest.raises(BaselineIOError):
        write_baseline(_snapshot(), tmp_path)


# T-WP9-036..041: successful load and load ordering/bindings.
def test_t_wp9_036_round_trip_equal_snapshot(tmp_path: Path) -> None:
    snapshot = _snapshot()
    write_baseline(snapshot, tmp_path)
    assert load_baseline(tmp_path) == snapshot


def test_t_wp9_037_partial_baseline_round_trip(tmp_path: Path) -> None:
    snapshot = _snapshot(complete=False)
    write_baseline(snapshot, tmp_path)
    assert load_baseline(tmp_path) == snapshot


def test_t_wp9_038_manifest_validated_before_baseline_read(tmp_path: Path) -> None:
    (tmp_path / "baseline.manifest.json").write_bytes(b"not-json")
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


def test_t_wp9_039_integrity_checked_before_snapshot_parse(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    (tmp_path / "baseline.json").write_bytes(b"not-json")
    with pytest.raises(BaselineIntegrityError):
        load_baseline(tmp_path)


def test_t_wp9_040_tool_version_binding_enforced(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    _rewrite_manifest(tmp_path, tool_version="different-producer")
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


def test_t_wp9_041_snapshot_schema_binding_enforced(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    _rewrite_manifest(tmp_path, snapshot_schema_version="driftape.snapshot.v2")
    with pytest.raises(BaselineSchemaMismatchError):
        load_baseline(tmp_path)


# T-WP9-042..045: integrity failures.
def test_t_wp9_042_one_byte_flip_is_integrity_failure(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    path = tmp_path / "baseline.json"
    data = bytearray(path.read_bytes())
    data[0] ^= 1
    path.write_bytes(data)
    with pytest.raises(BaselineIntegrityError):
        load_baseline(tmp_path)


def test_t_wp9_043_other_valid_snapshot_without_manifest_update_fails(
    tmp_path: Path,
) -> None:
    write_baseline(_snapshot(), tmp_path)
    other = replace(_snapshot(), tool_version="other")
    (tmp_path / "baseline.json").write_bytes(serialize_snapshot(other))
    with pytest.raises(BaselineIntegrityError):
        load_baseline(tmp_path)


def test_t_wp9_044_malformed_baseline_with_mismatch_is_integrity_failure(
    tmp_path: Path,
) -> None:
    write_baseline(_snapshot(), tmp_path)
    (tmp_path / "baseline.json").write_bytes(b"{broken")
    with pytest.raises(BaselineIntegrityError):
        load_baseline(tmp_path)


def test_t_wp9_045_digest_from_another_baseline_is_integrity_failure(
    tmp_path: Path,
) -> None:
    write_baseline(_snapshot(), tmp_path)
    other_digest = hashlib.sha256(
        serialize_snapshot(replace(_snapshot(), tool_version="other"))
    ).hexdigest()
    _rewrite_manifest(tmp_path, baseline_sha256=other_digest)
    with pytest.raises(BaselineIntegrityError):
        load_baseline(tmp_path)


# T-WP9-046..052: invalid manifest files.
def test_t_wp9_046_missing_manifest_is_io_error(tmp_path: Path) -> None:
    with pytest.raises(BaselineIOError):
        load_baseline(tmp_path)


def test_t_wp9_047_invalid_utf8_manifest(tmp_path: Path) -> None:
    (tmp_path / "baseline.manifest.json").write_bytes(b"\xff")
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


def test_t_wp9_048_manifest_bom_rejected(tmp_path: Path) -> None:
    (tmp_path / "baseline.manifest.json").write_bytes(b"\xef\xbb\xbf{}\n")
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


@pytest.mark.parametrize("data", [b"", b" \t\r\n"])
def test_t_wp9_049_empty_manifest_rejected(tmp_path: Path, data: bytes) -> None:
    (tmp_path / "baseline.manifest.json").write_bytes(data)
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


def test_t_wp9_050_malformed_manifest_json_rejected(tmp_path: Path) -> None:
    (tmp_path / "baseline.manifest.json").write_bytes(b"{\n")
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


@pytest.mark.parametrize("value", [[], 1, "x", None])
def test_t_wp9_051_non_object_manifest_root_rejected(
    tmp_path: Path, value: object
) -> None:
    (tmp_path / "baseline.manifest.json").write_text(
        json.dumps(value), encoding="utf-8"
    )
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


def test_t_wp9_052_noncanonical_manifest_bytes_rejected(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    mapping = json.loads((tmp_path / "baseline.manifest.json").read_text())
    (tmp_path / "baseline.manifest.json").write_text(
        json.dumps(mapping, indent=2) + "\n", encoding="utf-8"
    )
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


# T-WP9-053..060: invalid baseline files with matching digests where needed.
def test_t_wp9_053_missing_baseline_is_io_error(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    (tmp_path / "baseline.json").unlink()
    with pytest.raises(BaselineIOError):
        load_baseline(tmp_path)


def test_t_wp9_054_invalid_utf8_baseline_with_matching_digest(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    data = b"\xff"
    (tmp_path / "baseline.json").write_bytes(data)
    _rewrite_manifest(tmp_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline(tmp_path)


def test_t_wp9_055_baseline_bom_with_matching_digest(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    data = b"\xef\xbb\xbf" + serialize_snapshot(_snapshot())
    (tmp_path / "baseline.json").write_bytes(data)
    _rewrite_manifest(tmp_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline(tmp_path)


def test_t_wp9_056_malformed_baseline_json_with_matching_digest(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    data = b"{broken"
    (tmp_path / "baseline.json").write_bytes(data)
    _rewrite_manifest(tmp_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline(tmp_path)


def test_t_wp9_057_non_object_baseline_root_with_matching_digest(
    tmp_path: Path,
) -> None:
    write_baseline(_snapshot(), tmp_path)
    data = b"[]\n"
    (tmp_path / "baseline.json").write_bytes(data)
    _rewrite_manifest(tmp_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline(tmp_path)


def test_t_wp9_058_wrong_snapshot_schema_with_matching_digest(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    mapping = snapshot_to_mapping(_snapshot())
    mapping["schema_version"] = "driftape.snapshot.v2"
    data = _canonical_json_bytes(mapping)
    (tmp_path / "baseline.json").write_bytes(data)
    _rewrite_manifest(tmp_path, baseline_bytes=data)
    with pytest.raises(BaselineSchemaMismatchError):
        load_baseline(tmp_path)


def test_t_wp9_059_canonical_current_snapshot_rejected(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    current = _snapshot(kind=SnapshotKind.CURRENT)
    data = serialize_snapshot(current)
    (tmp_path / "baseline.json").write_bytes(data)
    _rewrite_manifest(tmp_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline(tmp_path)


def test_t_wp9_060_noncanonical_baseline_with_matching_digest(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    mapping = snapshot_to_mapping(_snapshot())
    data = (
        json.dumps(mapping, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()
    (tmp_path / "baseline.json").write_bytes(data)
    _rewrite_manifest(tmp_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline(tmp_path)


# T-WP9-061..065: exact error-code mapping.
def test_t_wp9_061_io_error_code() -> None:
    assert BaselineIOError("x").code == ErrorCode.IO_ERROR


def test_t_wp9_062_invalid_manifest_error_code() -> None:
    assert InvalidManifestError("x").code == ErrorCode.INVALID_MANIFEST


def test_t_wp9_063_schema_mismatch_error_code() -> None:
    assert BaselineSchemaMismatchError("x").code == ErrorCode.SCHEMA_MISMATCH


def test_t_wp9_064_integrity_error_code() -> None:
    assert BaselineIntegrityError("x").code == ErrorCode.INTEGRITY_FAILURE


def test_t_wp9_065_invalid_snapshot_error_code() -> None:
    assert InvalidBaselineSnapshotError("x").code == ErrorCode.INVALID_SNAPSHOT


# T-WP9-066..069: strict public argument types.
def test_t_wp9_066_wrong_snapshot_type_to_write(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        write_baseline("baseline", tmp_path)  # type: ignore[arg-type]


def test_t_wp9_067_wrong_directory_type_to_write() -> None:
    with pytest.raises(TypeError):
        write_baseline(_snapshot(), ".")  # type: ignore[arg-type]


def test_t_wp9_068_wrong_directory_type_to_load() -> None:
    with pytest.raises(TypeError):
        load_baseline(".")  # type: ignore[arg-type]


def test_t_wp9_069_wrong_baseline_bytes_type() -> None:
    with pytest.raises(TypeError):
        build_baseline_manifest(_snapshot(), bytearray(b"x"))  # type: ignore[arg-type]


# T-WP9-070: no current-host dependency.
def test_t_wp9_070_load_has_no_host_or_collector_dependency(tmp_path: Path) -> None:
    source = inspect.getsource(integrity_module)
    assert "platform_windows" not in source
    assert "collect_snapshot" not in source
    write_baseline(_snapshot(), tmp_path)
    assert load_baseline(tmp_path) == _snapshot()


def test_deterministic_pairs_are_byte_identical(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    snapshot = _snapshot()
    write_baseline(snapshot, first)
    write_baseline(snapshot, second)
    assert (first / "baseline.json").read_bytes() == (
        second / "baseline.json"
    ).read_bytes()
    assert (first / "baseline.manifest.json").read_bytes() == (
        second / "baseline.manifest.json"
    ).read_bytes()


def test_regression_integration_round_trip_contract(tmp_path: Path) -> None:
    snapshot = _snapshot()
    write_baseline(snapshot, tmp_path)
    loaded = load_baseline(tmp_path)
    assert loaded == snapshot
    assert validate_snapshot(snapshot_to_mapping(loaded)) == loaded
    assert serialize_snapshot(loaded) == (tmp_path / "baseline.json").read_bytes()


def test_manifest_root_must_be_mapping() -> None:
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest([])  # type: ignore[arg-type]


def test_all_manifest_values_must_be_nonempty_real_strings() -> None:
    class StringSubclass(str):
        pass

    raw = _manifest_mapping()
    raw["tool_version"] = ""
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)
    raw = _manifest_mapping()
    raw["tool_version"] = StringSubclass("0.1.0")
    with pytest.raises(InvalidManifestError):
        validate_baseline_manifest(raw)


def test_builder_rejects_wrong_snapshot_type() -> None:
    with pytest.raises(TypeError):
        build_baseline_manifest(object(), b"x")  # type: ignore[arg-type]


def test_write_current_snapshot_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidBaselineSnapshotError):
        write_baseline(_snapshot(kind=SnapshotKind.CURRENT), tmp_path)
    assert not tmp_path.joinpath("baseline.json").exists()


# WP9 Baseline Path Compatibility Rework R1.
def _rewrite_path_manifest(
    baseline_path: Path,
    *,
    baseline_bytes: bytes | None = None,
    **updates: object,
) -> None:
    manifest_path = derive_baseline_manifest_path(baseline_path)
    mapping = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(mapping, dict)
    if baseline_bytes is not None:
        mapping["baseline_sha256"] = hashlib.sha256(baseline_bytes).hexdigest()
    mapping.update(updates)
    manifest_path.write_bytes(_canonical_json_bytes(mapping))


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("baseline.json", "baseline.manifest.json"),
        ("gold.json", "gold.manifest.json"),
        ("host-a.snapshot", "host-a.manifest.json"),
        ("baseline", "baseline.manifest.json"),
    ],
)
def test_path_rework_manifest_derivation(name: str, expected: str) -> None:
    parent = Path("relative") / "nested"
    baseline_path = parent / name
    derived = derive_baseline_manifest_path(baseline_path)
    assert derived == parent / expected
    assert derived.parent == baseline_path.parent


def test_path_rework_derivation_requires_path() -> None:
    with pytest.raises(TypeError):
        derive_baseline_manifest_path("gold.json")  # type: ignore[arg-type]


def test_path_rework_derivation_requires_filename() -> None:
    with pytest.raises(ValueError):
        derive_baseline_manifest_path(Path("/"))


def test_path_rework_derivation_does_not_consult_filesystem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        raise AssertionError("filesystem consultation is forbidden")

    monkeypatch.setattr(Path, "exists", forbidden)
    monkeypatch.setattr(Path, "is_file", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    assert derive_baseline_manifest_path(Path("missing/gold.json")) == Path(
        "missing/gold.manifest.json"
    )


def test_path_rework_write_custom_json_pair(tmp_path: Path) -> None:
    snapshot = _snapshot()
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(snapshot, baseline_path)

    assert {path.name for path in tmp_path.iterdir()} == {
        "gold.json",
        "gold.manifest.json",
    }
    baseline_bytes = baseline_path.read_bytes()
    manifest_bytes = (tmp_path / "gold.manifest.json").read_bytes()
    manifest_mapping = json.loads(manifest_bytes)
    assert baseline_bytes == serialize_snapshot(snapshot)
    assert manifest_mapping["baseline_file"] == "gold.json"
    assert manifest_mapping["baseline_sha256"] == hashlib.sha256(
        baseline_bytes
    ).hexdigest()
    manifest = integrity_module._parse_manifest_bytes(manifest_bytes, "gold.json")
    assert serialize_baseline_manifest(manifest) == manifest_bytes


def test_path_rework_write_custom_suffix_binding(tmp_path: Path) -> None:
    baseline_path = tmp_path / "host-a.snapshot"
    write_baseline_path(_snapshot(), baseline_path)
    manifest_path = tmp_path / "host-a.manifest.json"
    assert baseline_path.exists()
    assert manifest_path.exists()
    assert json.loads(manifest_path.read_text())["baseline_file"] == "host-a.snapshot"


def test_path_rework_write_creates_parent_directory(tmp_path: Path) -> None:
    baseline_path = tmp_path / "nested" / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    assert baseline_path.is_file()
    assert derive_baseline_manifest_path(baseline_path).is_file()


def test_path_rework_write_replaces_baseline_before_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    order: list[str] = []

    def fake_replace(target: Path, data: bytes) -> None:
        del data
        order.append(target.name)

    monkeypatch.setattr(integrity_module, "_atomic_replace_bytes", fake_replace)
    write_baseline_path(_snapshot(), tmp_path / "gold.json")
    assert order == ["gold.json", "gold.manifest.json"]


def test_path_rework_write_failure_maps_to_io_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_replace(target: Path, data: bytes) -> None:
        del target, data
        raise OSError("simulated write failure")

    monkeypatch.setattr(integrity_module, "_atomic_replace_bytes", fail_replace)
    with pytest.raises(BaselineIOError):
        write_baseline_path(_snapshot(), tmp_path / "gold.json")


def test_path_rework_atomic_temp_cleanup_on_replace_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_replace(src: object, dst: object) -> None:
        del src, dst
        raise OSError("simulated replace failure")

    monkeypatch.setattr(integrity_module.os, "replace", fail_replace)
    with pytest.raises(OSError):
        integrity_module._atomic_replace_bytes(tmp_path / "gold.json", b"abc")
    assert list(tmp_path.iterdir()) == []


def test_path_rework_round_trip_custom_pair(tmp_path: Path) -> None:
    snapshot = _snapshot()
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(snapshot, baseline_path)
    assert load_baseline_path(baseline_path) == snapshot


def test_path_rework_manifest_validated_before_baseline_trust(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    derive_baseline_manifest_path(baseline_path).write_bytes(b"{broken")
    with pytest.raises(InvalidManifestError):
        load_baseline_path(baseline_path)


def test_path_rework_digest_verified_before_baseline_parse(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    baseline_path.write_bytes(b"{broken")
    with pytest.raises(BaselineIntegrityError):
        load_baseline_path(baseline_path)


def test_path_rework_single_byte_corruption_is_integrity_error(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    data = bytearray(baseline_path.read_bytes())
    data[-2] ^= 1
    baseline_path.write_bytes(bytes(data))
    with pytest.raises(BaselineIntegrityError):
        load_baseline_path(baseline_path)


def test_path_rework_different_valid_baseline_without_manifest_update_fails(
    tmp_path: Path,
) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    baseline_path.write_bytes(serialize_snapshot(_snapshot(tool_version="other")))
    with pytest.raises(BaselineIntegrityError):
        load_baseline_path(baseline_path)


def test_path_rework_wrong_manifest_schema(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    _rewrite_path_manifest(
        baseline_path,
        schema_version="driftape.baseline-manifest.v2",
    )
    with pytest.raises(BaselineSchemaMismatchError):
        load_baseline_path(baseline_path)


def test_path_rework_wrong_snapshot_schema_after_valid_digest(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    mapping = snapshot_to_mapping(_snapshot())
    mapping["schema_version"] = "driftape.snapshot.v2"
    data = _canonical_json_bytes(mapping)
    baseline_path.write_bytes(data)
    _rewrite_path_manifest(baseline_path, baseline_bytes=data)
    with pytest.raises(BaselineSchemaMismatchError):
        load_baseline_path(baseline_path)


def test_path_rework_malformed_manifest(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    derive_baseline_manifest_path(baseline_path).write_bytes(b"not-json")
    with pytest.raises(InvalidManifestError):
        load_baseline_path(baseline_path)


def test_path_rework_invalid_snapshot_after_valid_digest(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    data = b"{}\n"
    baseline_path.write_bytes(data)
    _rewrite_path_manifest(baseline_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline_path(baseline_path)


def test_path_rework_manifest_tool_version_mismatch(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    _rewrite_path_manifest(baseline_path, tool_version="other")
    with pytest.raises(InvalidManifestError):
        load_baseline_path(baseline_path)


def test_path_rework_manifest_baseline_file_mismatch(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    _rewrite_path_manifest(baseline_path, baseline_file="other.json")
    with pytest.raises(InvalidManifestError):
        load_baseline_path(baseline_path)


@pytest.mark.parametrize(
    "redirect",
    [
        "../gold.json",
        "sub/gold.json",
        r"sub\gold.json",
        "/tmp/gold.json",
        r"C:\temp\gold.json",
        "..",
    ],
)
def test_path_rework_manifest_path_redirection_rejected(
    tmp_path: Path,
    redirect: str,
) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    _rewrite_path_manifest(baseline_path, baseline_file=redirect)
    with pytest.raises(InvalidManifestError):
        load_baseline_path(baseline_path)


def test_path_rework_manifest_cannot_redirect_to_existing_file(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    other_path = tmp_path / "other.json"
    other_path.write_bytes(serialize_snapshot(_snapshot(tool_version="other")))
    _rewrite_path_manifest(
        baseline_path,
        baseline_bytes=other_path.read_bytes(),
        baseline_file="other.json",
        tool_version="other",
    )
    baseline_path.unlink()
    with pytest.raises(InvalidManifestError):
        load_baseline_path(baseline_path)


def test_path_rework_noncanonical_snapshot_after_valid_digest(tmp_path: Path) -> None:
    baseline_path = tmp_path / "gold.json"
    write_baseline_path(_snapshot(), baseline_path)
    mapping = snapshot_to_mapping(_snapshot())
    data = (
        json.dumps(mapping, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()
    baseline_path.write_bytes(data)
    _rewrite_path_manifest(baseline_path, baseline_bytes=data)
    with pytest.raises(InvalidBaselineSnapshotError):
        load_baseline_path(baseline_path)


def test_path_rework_old_api_remains_fixed_name_only(tmp_path: Path) -> None:
    write_baseline(_snapshot(), tmp_path)
    assert {path.name for path in tmp_path.iterdir()} == {
        "baseline.json",
        "baseline.manifest.json",
    }
    assert load_baseline(tmp_path) == _snapshot()
    mapping = json.loads((tmp_path / "baseline.manifest.json").read_text())
    assert mapping["baseline_file"] == "baseline.json"
    mapping["baseline_file"] = "gold.json"
    (tmp_path / "baseline.manifest.json").write_bytes(_canonical_json_bytes(mapping))
    with pytest.raises(InvalidManifestError):
        load_baseline(tmp_path)


def test_path_rework_new_public_apis_require_path(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        write_baseline_path(
            _snapshot(), str(tmp_path / "gold.json")  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError):
        load_baseline_path(str(tmp_path / "gold.json"))  # type: ignore[arg-type]
