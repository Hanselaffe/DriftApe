"""Strict, read-only importer for canonical driftape.changes.v1 report bytes.

The imported mapping is retained without interpretation of source path labels.
Errors are separated for future CLI mapping: I/O (3), schema (5), invalid (6).
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Never

from driftape.constants import CHANGE_SCHEMA_VERSION
from driftape.diff import _DOMAINS

MAX_REPORT_BYTES = 64 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_DOMAINS_SET = set(_DOMAINS)
_SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")


class ReportReadError(OSError):
    """Local report file could not be opened or read."""


class UnsupportedReportSchemaError(ValueError):
    """The report schema is not driftape.changes.v1."""


class InvalidStoredReportError(ValueError):
    """The report is not an exact valid canonical v1 report."""


@dataclass(frozen=True, slots=True)
class LoadedChangeReport:
    """Validated report mapping, original report tool version and source bytes.

    Treat ``mapping`` as untrusted read-only input: do not mutate it; renderers
    must escape all values for their output context.
    """

    mapping: dict[str, Any]
    tool_version: str
    canonical_bytes: bytes


def _invalid(message: str) -> Never:
    raise InvalidStoredReportError(message)


def _keys(obj: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != expected:
        _invalid(f"{label}: wrong object keys or type")
    return obj


def _string(value: object, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        _invalid(f"{label}: expected {'nonempty ' if nonempty else ''}string")
    return value


def _time(value: object, label: str) -> None:
    s = _string(value, label)
    if not _TIME.fullmatch(s):
        _invalid(f"{label}: invalid UTC timestamp format")
    try:
        datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
        datetime(
            int(s[:4]),
            int(s[5:7]),
            int(s[8:10]),
            int(s[11:13]),
            int(s[14:16]),
            int(s[17:19]),
        )
    except ValueError:
        _invalid(f"{label}: invalid UTC timestamp")


def _count(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        _invalid(f"{label}: expected nonnegative integer")
    return value


def _array(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        _invalid(f"{label}: expected array")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            _invalid(f"duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def _constant(value: str) -> None:
    _invalid(f"nonfinite JSON number: {value}")


def _validate(data: dict[str, Any]) -> None:
    _keys(
        data,
        {
            "schema_version",
            "tool_version",
            "generated_at_utc",
            "baseline",
            "current",
            "comparison",
            "changes",
            "findings",
            "summary",
        },
        "root",
    )
    if data["schema_version"] != CHANGE_SCHEMA_VERSION:
        raise UnsupportedReportSchemaError("unsupported report schema_version")
    _string(data["tool_version"], "tool_version")
    _time(data["generated_at_utc"], "generated_at_utc")
    base = _keys(data["baseline"], {"path", "sha256", "collected_at_utc"}, "baseline")
    cur = _keys(data["current"], {"path", "collected_at_utc"}, "current")
    _string(base["path"], "baseline.path")
    _string(cur["path"], "current.path")
    if not isinstance(base["sha256"], str) or not _SHA.fullmatch(base["sha256"]):
        _invalid("baseline.sha256: expected lowercase SHA-256")
    _time(base["collected_at_utc"], "baseline.collected_at_utc")
    _time(cur["collected_at_utc"], "current.collected_at_utc")
    comp = _keys(
        data["comparison"],
        {"status", "compared_domains", "skipped_domains", "errors"},
        "comparison",
    )
    compared = _array(comp["compared_domains"], "compared_domains")
    skipped = _array(comp["skipped_domains"], "skipped_domains")
    if (
        any(type(x) is not str for x in compared + skipped)
        or set(compared) | set(skipped) != _DOMAINS_SET
        or len(compared) + len(skipped) != len(_DOMAINS)
    ):
        _invalid("comparison: incorrect seven-domain partition")
    if compared != [d for d in _DOMAINS if d in compared] or skipped != [
        d for d in _DOMAINS if d in skipped
    ]:
        _invalid("comparison: incorrect domain order")
    if comp["errors"] != [] or not isinstance(comp["errors"], list):
        _invalid("comparison.errors must be empty array")
    if comp["status"] != ("partial" if skipped else "complete"):
        _invalid("comparison.status disagrees with coverage")
    changes = _array(data["changes"], "changes")
    seen: dict[str, str] = {}
    change_order: list[tuple[str, str, str, str]] = []
    for i, raw in enumerate(changes):
        c = _keys(
            raw,
            {
                "change_id",
                "domain",
                "object_type",
                "object_id",
                "object_name",
                "change_type",
                "property",
                "old_value",
                "new_value",
            },
            f"changes[{i}]",
        )
        for field in ("change_id", "domain", "object_type", "object_id", "object_name"):
            _string(c[field], f"changes[{i}].{field}")
        if c["domain"] not in compared or c["change_type"] not in (
            "ADDED",
            "REMOVED",
            "MODIFIED",
        ):
            _invalid("change domain/type invalid")
        prop = c["property"]
        if c["change_type"] == "MODIFIED":
            _string(prop, "modified property")
        elif prop is not None:
            _invalid("added/removed property must be null")
        if c["change_type"] == "ADDED" and c["old_value"] is not None:
            _invalid("added old_value must be null")
        if c["change_type"] == "REMOVED" and c["new_value"] is not None:
            _invalid("removed new_value must be null")
        cid = c["change_id"]
        if cid in seen:
            _invalid("duplicate change ID")
        seen[cid] = c["domain"]
        change_order.append((c["domain"], c["object_id"], c["change_type"], prop or ""))
    if change_order != sorted(change_order):
        _invalid("unsorted changes")
    findings = _array(data["findings"], "findings")
    finding_ids: set[str] = set()
    finding_order: list[tuple[str, str]] = []
    counts = dict.fromkeys(_SEVERITIES, 0)
    for i, raw in enumerate(findings):
        f = _keys(
            raw,
            {
                "finding_id",
                "rule_id",
                "severity",
                "title",
                "message",
                "domain",
                "change_ids",
            },
            f"findings[{i}]",
        )
        for field in ("finding_id", "rule_id", "title", "message", "domain"):
            _string(f[field], f"findings[{i}].{field}")
        if f["finding_id"] in finding_ids:
            _invalid("duplicate finding ID")
        finding_ids.add(f["finding_id"])
        if type(f["severity"]) is not str or f["severity"] not in counts:
            _invalid("invalid finding severity")
        ids = _array(f["change_ids"], "finding.change_ids")
        if (
            len(ids) != 1
            or type(ids[0]) is not str
            or ids[0] not in seen
            or seen[ids[0]] != f["domain"]
        ):
            _invalid("finding change reference/domain invalid")
        counts[f["severity"]] += 1
        finding_order.append((f["rule_id"], ids[0]))
    if finding_order != sorted(finding_order):
        _invalid("unsorted findings")
    summary = _keys(data["summary"], {"changes", "findings", "severity"}, "summary")
    if _count(summary["changes"], "summary.changes") != len(changes) or _count(
        summary["findings"], "summary.findings"
    ) != len(findings):
        _invalid("summary totals mismatch")
    severity = _keys(summary["severity"], set(_SEVERITIES), "summary.severity")
    for key in _SEVERITIES:
        if _count(severity[key], key) != counts[key]:
            _invalid("severity totals mismatch")


def load_change_report(path: Path) -> LoadedChangeReport:
    """Load and validate a local canonical v1 report without mutating it.

    ``ReportReadError`` indicates file access failures, ``UnsupportedReportSchemaError``
    an unsupported schema, and ``InvalidStoredReportError`` malformed/noncanonical data.
    No report path labels are dereferenced.
    """
    try:
        # Stat before open: a FIFO with no writer would otherwise block at open().
        path_stat = path.stat()
        if not stat.S_ISREG(path_stat.st_mode):
            _invalid("report must be a regular file")
        # O_NONBLOCK closes the POSIX stat/open race for FIFOs.  On Windows
        # this flag is not available; the pre-open type check still applies.
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            file_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                _invalid("report must be a regular file")
            if file_stat.st_size > MAX_REPORT_BYTES:
                _invalid("report exceeds 64 MiB")
            raw = stream.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ReportReadError(str(exc)) from exc
    if len(raw) > MAX_REPORT_BYTES:
        _invalid("report exceeds 64 MiB")
    try:
        decoded = raw.decode("utf-8", errors="strict")
        data = json.loads(decoded, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InvalidStoredReportError("invalid UTF-8/JSON report") from exc
    if not isinstance(data, dict):
        _invalid("report root must be object")
    if "schema_version" in data and data["schema_version"] != CHANGE_SCHEMA_VERSION:
        raise UnsupportedReportSchemaError("unsupported report schema_version")
    try:
        canonical = (
            json.dumps(
                data,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidStoredReportError("unserializable JSON report") from exc
    if raw != canonical:
        _invalid("report is not byte-canonical JSON")
    _validate(data)
    return LoadedChangeReport(
        mapping=data, tool_version=data["tool_version"], canonical_bytes=raw
    )
