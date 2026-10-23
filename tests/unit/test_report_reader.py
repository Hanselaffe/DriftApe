"""Positive/negative tests for Phase-2 strictly canonical report input."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from driftape.reporting.json_reader import (
    MAX_REPORT_BYTES,
    InvalidStoredReportError,
    ReportReadError,
    UnsupportedReportSchemaError,
    load_change_report,
)

EXAMPLE = Path(__file__).parents[2] / "examples" / "changes.synthetic.json"


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def example() -> dict:
    return json.loads(EXAMPLE.read_bytes())


def load_bytes(tmp_path: Path, raw: bytes):
    path = tmp_path / "report.json"
    path.write_bytes(raw)
    return load_change_report(path)


def test_synthetic_v01_report_bytes_preserved(tmp_path: Path) -> None:
    before = EXAMPLE.read_bytes()
    report = load_change_report(EXAMPLE)
    assert report.tool_version == "0.1.0"
    assert report.canonical_bytes == before == EXAMPLE.read_bytes()
    assert report.mapping == json.loads(before)
    assert load_bytes(tmp_path, before).canonical_bytes == before


def test_v02_metadata_is_not_a_schema_switch(tmp_path: Path) -> None:
    item = example()
    item["tool_version"] = "0.2.0.dev0"
    assert load_bytes(tmp_path, canonical(item)).tool_version == "0.2.0.dev0"
    item["tool_version"] = "0.2.0"
    assert load_bytes(tmp_path, canonical(item)).tool_version == "0.2.0"


def test_partial_no_changes_and_unicode_nested_data(tmp_path: Path) -> None:
    item = example()
    domains = item["comparison"]["compared_domains"]
    item["comparison"]["compared_domains"] = domains[:2]
    item["comparison"]["skipped_domains"] = domains[2:]
    item["comparison"]["status"] = "partial"
    item["changes"] = []
    item["findings"] = []
    item["summary"] = {
        "changes": 0,
        "findings": 0,
        "severity": dict.fromkeys(("HIGH", "MEDIUM", "LOW", "INFO"), 0),
    }
    item["baseline"]["path"] = "C:/界面/<script>&.json"
    assert load_bytes(tmp_path, canonical(item)).mapping == item
    item["comparison"]["compared_domains"] = domains
    item["comparison"]["skipped_domains"] = []
    item["comparison"]["status"] = "complete"
    assert load_bytes(tmp_path, canonical(item)).mapping == item


def test_nested_values_and_deterministic_calls(tmp_path: Path) -> None:
    item = example()
    item["changes"][0]["new_value"] = {"nested": ["Ω", {"a": [1, True, None]}]}
    raw = canonical(item)
    first = load_bytes(tmp_path, raw)
    second = load_bytes(tmp_path, raw)
    assert first == second
    assert first.mapping["changes"][0]["new_value"] == item["changes"][0]["new_value"]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"null\n",
        b"[]\n",
        b"{}\n",
        b"\xef\xbb\xbf{}\n",
        b"\xff\n",
        b'{"a":NaN}\n',
        b'{"a":Infinity}\n',
        b'{"a":-Infinity}\n',
        EXAMPLE.read_bytes().rstrip(b"\n"),
        EXAMPLE.read_bytes() + b"\n",
        b" " + EXAMPLE.read_bytes(),
        b'{"a":1,"a":2}\n',
        b'{"a":{"b":1,"b":2}}\n',
    ],
)
def test_malformed_or_noncanonical_bytes(tmp_path: Path, raw: bytes) -> None:
    with pytest.raises(InvalidStoredReportError):
        load_bytes(tmp_path, raw)


def test_wrong_schema_has_distinct_error(tmp_path: Path) -> None:
    item = example()
    item["schema_version"] = "driftape.changes.v2"
    with pytest.raises(UnsupportedReportSchemaError):
        load_bytes(tmp_path, canonical(item))


@pytest.mark.parametrize(
    "path,value",
    [
        (("tool_version",), 4),
        (("tool_version",), ""),
        (("generated_at_utc",), "2026-02-30T12:00:00Z"),
        (("generated_at_utc",), "2026-01-01T01:00:00+01:00"),
        (("baseline", "path"), ""),
        (("baseline", "sha256"), "A" * 64),
        (("baseline", "collected_at_utc"), "2026-99-01T12:00:00Z"),
        (("current", "path"), 7),
        (("current", "collected_at_utc"), None),
        (("comparison", "status"), "COMPLETE"),
        (("comparison", "errors"), ["oops"]),
        (("comparison", "compared_domains"), []),
        (("comparison", "skipped_domains"), ["bogus"]),
        (("changes", 0, "change_type"), "BROKEN"),
        (("changes", 0, "object_id"), False),
        (("changes", 0, "object_name"), None),
        (("changes", 0, "object_type"), ""),
        (("changes", 0, "change_id"), ""),
        (("changes", 0, "property"), "unexpected"),
        (("changes", 0, "old_value"), "unexpected"),
        (("findings", 0, "severity"), "CRITICAL"),
        (("findings", 0, "severity"), []),
        (("findings", 0, "finding_id"), ""),
        (("findings", 0, "rule_id"), False),
        (("findings", 0, "message"), None),
        (("findings", 0, "title"), ""),
        (("findings", 0, "change_ids"), []),
        (("findings", 0, "change_ids"), ["missing"]),
        (("findings", 0, "change_ids"), ["c1", "c2"]),
        (("findings", 0, "domain"), "invalid"),
        (("summary", "changes"), True),
        (("summary", "findings"), -1),
        (("summary", "severity", "HIGH"), True),
        (("summary", "severity", "MEDIUM"), 999),
    ],
)
def test_invalid_structural_fields(tmp_path: Path, path: tuple, value: object) -> None:
    item = example()
    target = item
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(InvalidStoredReportError):
        load_bytes(tmp_path, canonical(item))


@pytest.mark.parametrize(
    "path",
    [
        ("generated_at_utc",),
        ("baseline", "path"),
        ("current", "path"),
        ("comparison", "errors"),
        ("changes", 0, "change_id"),
        ("findings", 0, "finding_id"),
        ("summary", "changes"),
    ],
)
def test_missing_keys(tmp_path: Path, path: tuple) -> None:
    item = example()
    target = item
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    with pytest.raises(InvalidStoredReportError):
        load_bytes(tmp_path, canonical(item))


def test_extra_keys_nested_and_root(tmp_path: Path) -> None:
    for key in ("baseline", "current", "comparison", "summary", None):
        item = example()
        (item if key is None else item[key])["unexpected"] = 1
        with pytest.raises(InvalidStoredReportError):
            load_bytes(tmp_path, canonical(item))


def test_domain_duplicates_and_order(tmp_path: Path) -> None:
    for variation in ("duplicate", "swap", "unknown", "status"):
        item = example()
        compared = item["comparison"]["compared_domains"]
        if variation == "duplicate":
            compared[0] = compared[1]
        elif variation == "swap":
            compared[0], compared[1] = compared[1], compared[0]
        elif variation == "unknown":
            compared[0] = "other.domain"
        else:
            item["comparison"]["status"] = "partial"
        with pytest.raises(InvalidStoredReportError):
            load_bytes(tmp_path, canonical(item))


def test_duplicate_unsorted_or_orphan_records(tmp_path: Path) -> None:
    for kind in (
        "change_dup",
        "change_unsorted",
        "finding_dup",
        "finding_unsorted",
        "orphan",
        "wrong_domain",
    ):
        item = example()
        if kind == "change_dup":
            item["changes"][1]["change_id"] = item["changes"][0]["change_id"]
        elif kind == "change_unsorted":
            item["changes"].reverse()
        elif kind == "finding_dup":
            item["findings"][1]["finding_id"] = item["findings"][0]["finding_id"]
        elif kind == "finding_unsorted":
            item["findings"].reverse()
        elif kind == "orphan":
            item["findings"][0]["change_ids"] = ["unknown"]
        else:
            item["findings"][0]["domain"] = "users.local_users"
        with pytest.raises(InvalidStoredReportError):
            load_bytes(tmp_path, canonical(item))


def test_oversize_is_rejected_before_read(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    with path.open("wb") as stream:
        stream.truncate(MAX_REPORT_BYTES + 1)
    with pytest.raises(InvalidStoredReportError):
        load_change_report(path)


def test_overlong_json_integer_is_invalid_stored_report(tmp_path: Path) -> None:
    """An integer beyond Python's JSON digit limit is malformed file content."""
    raw = (
        b'{"schema_version":"driftape.changes.v1","summary":{"changes":'
        + b"1" * 5000
        + b"}}\n"
    )
    with pytest.raises(InvalidStoredReportError) as exc_info:
        load_bytes(tmp_path, raw)
    assert type(exc_info.value) is InvalidStoredReportError


def test_missing_file_is_io_error(tmp_path: Path) -> None:
    with pytest.raises(ReportReadError):
        load_change_report(tmp_path / "missing.json")


def test_directory_is_not_regular_file(tmp_path: Path) -> None:
    with pytest.raises((InvalidStoredReportError, ReportReadError)):
        load_change_report(tmp_path)


def test_exact_64_mib_canonical_boundary(tmp_path: Path) -> None:
    item = example()
    item["changes"] = []
    item["findings"] = []
    item["summary"] = {
        "changes": 0,
        "findings": 0,
        "severity": dict.fromkeys(("HIGH", "MEDIUM", "LOW", "INFO"), 0),
    }
    base = len(canonical(item))
    item["baseline"]["path"] += "a" * (MAX_REPORT_BYTES - base)
    raw = canonical(item)
    assert len(raw) == MAX_REPORT_BYTES
    assert load_bytes(tmp_path, raw).canonical_bytes == raw


def test_fifo_without_writer_fails_fast(tmp_path: Path) -> None:
    """Use a bounded subprocess so a FIFO regression cannot hang pytest."""
    if os.name != "posix" or not hasattr(os, "mkfifo"):
        pytest.skip("POSIX os.mkfifo unavailable")
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    script = (
        "from pathlib import Path\n"
        "from driftape.reporting.json_reader import "
        "InvalidStoredReportError, load_change_report\n"
        "try:\n"
        "    load_change_report(Path(__import__('sys').argv[1]))\n"
        "except InvalidStoredReportError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(2)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script, str(fifo)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail("FIFO input blocked the report reader")
    assert proc.returncode == 0, (stdout, stderr)
