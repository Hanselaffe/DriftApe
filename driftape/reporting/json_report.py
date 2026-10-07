"""Canonical DriftApe v0.1 change-report construction and serialization."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime

from driftape.constants import CHANGE_SCHEMA_VERSION, TOOL_VERSION
from driftape.diff import Change, ComparisonStatus, DiffResult
from driftape.rules import Finding, FindingSeverity


class InvalidReportInputError(ValueError):
    """Raised when reporting input violates the frozen WP12 contract."""


@dataclass(frozen=True, slots=True)
class ChangeReport:
    """Typed canonical reporting input assembled from accepted comparison results."""

    generated_at_utc: str
    baseline_path: str
    baseline_sha256: str
    baseline_collected_at_utc: str
    current_path: str
    current_collected_at_utc: str
    comparison_status: ComparisonStatus
    compared_domains: tuple[str, ...]
    skipped_domains: tuple[str, ...]
    changes: tuple[Change, ...]
    findings: tuple[Finding, ...]


_TIMESTAMP_RE = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})Z"
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _validate_timestamp(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise InvalidReportInputError(f"{field_name} must be a canonical UTC timestamp string")
    match = _TIMESTAMP_RE.fullmatch(value)
    if match is None:
        raise InvalidReportInputError(
            f"{field_name} must use exact YYYY-MM-DDTHH:MM:SSZ format"
        )
    try:
        datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
        )
    except ValueError as exc:
        raise InvalidReportInputError(f"{field_name} is not a valid UTC timestamp") from exc
    return value


def _validate_path_label(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise InvalidReportInputError(f"{field_name} must be a non-empty string")
    return value


def _validate_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise InvalidReportInputError(
            "baseline_sha256 must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def _change_sort_key(change: Change) -> tuple[str, str, str, str]:
    return (
        change.domain,
        change.object_id,
        change.change_type.value,
        "" if change.property is None else change.property,
    )


def _validate_changes(changes: object) -> tuple[Change, ...]:
    if not isinstance(changes, tuple):
        raise InvalidReportInputError("diff_result.changes must be a tuple")
    seen_change_ids: set[str] = set()
    previous_key: tuple[str, str, str, str] | None = None
    for change in changes:
        if not isinstance(change, Change):
            raise InvalidReportInputError("diff_result.changes contains a non-Change member")
        if change.change_id in seen_change_ids:
            raise InvalidReportInputError(f"duplicate change_id: {change.change_id}")
        seen_change_ids.add(change.change_id)
        current_key = _change_sort_key(change)
        if previous_key is not None and current_key < previous_key:
            raise InvalidReportInputError("changes are not in accepted WP10 canonical order")
        previous_key = current_key
    return changes


def _validate_findings(
    findings: object,
    *,
    change_ids: set[str],
) -> tuple[Finding, ...]:
    if not isinstance(findings, tuple):
        raise InvalidReportInputError("findings must be a tuple")
    seen_finding_ids: set[str] = set()
    previous_key: tuple[str, str] | None = None
    for finding in findings:
        if not isinstance(finding, Finding):
            raise InvalidReportInputError("findings contains a non-Finding member")
        if finding.finding_id in seen_finding_ids:
            raise InvalidReportInputError(f"duplicate finding_id: {finding.finding_id}")
        seen_finding_ids.add(finding.finding_id)
        if len(finding.change_ids) != 1:
            raise InvalidReportInputError(
                "finding must contain the sole change_id produced by accepted WP11"
            )
        if any(change_id not in change_ids for change_id in finding.change_ids):
            raise InvalidReportInputError(
                f"finding {finding.finding_id!r} references an unknown change_id"
            )
        current_key = (finding.rule_id, finding.change_ids[0])
        if previous_key is not None and current_key < previous_key:
            raise InvalidReportInputError("findings are not in accepted WP11 canonical order")
        previous_key = current_key
    return findings


def build_report(
    *,
    generated_at_utc: str,
    baseline_path: str,
    baseline_sha256: str,
    baseline_collected_at_utc: str,
    current_path: str,
    current_collected_at_utc: str,
    diff_result: DiffResult,
    findings: tuple[Finding, ...],
) -> ChangeReport:
    """Build a validated report from already accepted diff and finding tuples."""
    generated_at_utc = _validate_timestamp(
        generated_at_utc, field_name="generated_at_utc"
    )
    baseline_collected_at_utc = _validate_timestamp(
        baseline_collected_at_utc, field_name="baseline_collected_at_utc"
    )
    current_collected_at_utc = _validate_timestamp(
        current_collected_at_utc, field_name="current_collected_at_utc"
    )
    baseline_path = _validate_path_label(baseline_path, field_name="baseline_path")
    current_path = _validate_path_label(current_path, field_name="current_path")
    baseline_sha256 = _validate_sha256(baseline_sha256)

    if not isinstance(diff_result, DiffResult):
        raise InvalidReportInputError("diff_result must be DiffResult")
    if not isinstance(diff_result.status, ComparisonStatus):
        raise InvalidReportInputError("diff_result.status must be ComparisonStatus")
    if not isinstance(diff_result.compared_domains, tuple):
        raise InvalidReportInputError("diff_result.compared_domains must be a tuple")
    if not isinstance(diff_result.skipped_domains, tuple):
        raise InvalidReportInputError("diff_result.skipped_domains must be a tuple")

    changes = _validate_changes(diff_result.changes)
    canonical_findings = _validate_findings(
        findings,
        change_ids={change.change_id for change in changes},
    )

    return ChangeReport(
        generated_at_utc=generated_at_utc,
        baseline_path=baseline_path,
        baseline_sha256=baseline_sha256,
        baseline_collected_at_utc=baseline_collected_at_utc,
        current_path=current_path,
        current_collected_at_utc=current_collected_at_utc,
        comparison_status=diff_result.status,
        compared_domains=diff_result.compared_domains,
        skipped_domains=diff_result.skipped_domains,
        changes=changes,
        findings=canonical_findings,
    )


def _change_to_mapping(change: Change) -> dict[str, object]:
    return {
        "change_id": change.change_id,
        "domain": change.domain,
        "object_type": change.object_type,
        "object_id": change.object_id,
        "object_name": change.object_name,
        "change_type": change.change_type.value,
        "property": change.property,
        "old_value": change.old_value,
        "new_value": change.new_value,
    }


def _finding_to_mapping(finding: Finding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "message": finding.message,
        "domain": finding.domain,
        "change_ids": list(finding.change_ids),
    }


def _severity_counts(findings: tuple[Finding, ...]) -> dict[str, int]:
    counts = {
        FindingSeverity.HIGH.value: 0,
        FindingSeverity.MEDIUM.value: 0,
        FindingSeverity.LOW.value: 0,
        FindingSeverity.INFO.value: 0,
    }
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def report_to_mapping(report: ChangeReport) -> dict[str, object]:
    """Project a typed report to the exact frozen driftape.changes.v1 mapping."""
    return {
        "schema_version": CHANGE_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": report.generated_at_utc,
        "baseline": {
            "path": report.baseline_path,
            "sha256": report.baseline_sha256,
            "collected_at_utc": report.baseline_collected_at_utc,
        },
        "current": {
            "path": report.current_path,
            "collected_at_utc": report.current_collected_at_utc,
        },
        "comparison": {
            "status": report.comparison_status.value,
            "compared_domains": list(report.compared_domains),
            "skipped_domains": list(report.skipped_domains),
            "errors": [],
        },
        "changes": [_change_to_mapping(change) for change in report.changes],
        "findings": [_finding_to_mapping(finding) for finding in report.findings],
        "summary": {
            "changes": len(report.changes),
            "findings": len(report.findings),
            "severity": _severity_counts(report.findings),
        },
    }


def serialize_report(report: ChangeReport) -> bytes:
    """Serialize a report to canonical deterministic UTF-8 JSON bytes."""
    return (
        json.dumps(
            report_to_mapping(report),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
