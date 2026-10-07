"""WP12 reporting contract tests."""

from __future__ import annotations

import math
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from pathlib import Path
from typing import Any, get_type_hints

import pytest

from driftape.constants import CHANGE_SCHEMA_VERSION, TOOL_VERSION
from driftape.diff import Change, ChangeType, ComparisonStatus, DiffResult
from driftape.reporting import (
    ChangeReport,
    InvalidReportInputError,
    build_report,
    render_terminal_summary,
    report_to_mapping,
    serialize_report,
)
from driftape.rules import Finding, FindingSeverity


SHA = "a" * 64


def _change(
    change_id: str = "c1",
    *,
    domain: str = "users.local_users",
    object_id: str = "S-1",
    change_type: ChangeType = ChangeType.ADDED,
    property_name: str | None = None,
    old_value: object = None,
    new_value: object = None,
    object_name: str = "Alice",
) -> Change:
    return Change(
        change_id=change_id,
        domain=domain,
        object_type="local_user",
        object_id=object_id,
        object_name=object_name,
        change_type=change_type,
        property=property_name,
        old_value=old_value,
        new_value=new_value,
    )


def _finding(
    finding_id: str = "f1",
    *,
    rule_id: str = "DA-USR-001",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    change_id: str = "c1",
    title: str = "Local user added",
    message: str = "A local user account was added and should be reviewed.",
    domain: str = "users.local_users",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        domain=domain,
        change_ids=(change_id,),
    )


def _report(
    *,
    status: ComparisonStatus = ComparisonStatus.COMPLETE,
    compared_domains: tuple[str, ...] = ("users.local_users",),
    skipped_domains: tuple[str, ...] = (),
    changes: tuple[Change, ...] | None = None,
    findings: tuple[Finding, ...] | None = None,
    generated_at_utc: str = "2026-08-27T10:00:00Z",
    baseline_path: str = "baseline.json",
    baseline_sha256: str = SHA,
    baseline_collected_at_utc: str = "2026-08-27T09:00:00Z",
    current_path: str = "current.json",
    current_collected_at_utc: str = "2026-08-27T09:30:00Z",
) -> ChangeReport:
    if changes is None:
        changes = (_change(new_value={"enabled": True, "name": "Alice"}),)
    if findings is None:
        findings = (_finding(),)
    return build_report(
        generated_at_utc=generated_at_utc,
        baseline_path=baseline_path,
        baseline_sha256=baseline_sha256,
        baseline_collected_at_utc=baseline_collected_at_utc,
        current_path=current_path,
        current_collected_at_utc=current_collected_at_utc,
        diff_result=DiffResult(status, compared_domains, skipped_domains, changes),
        findings=findings,
    )


def test_change_report_model_is_exact_frozen_slotted_typed() -> None:
    assert is_dataclass(ChangeReport)
    assert [field.name for field in fields(ChangeReport)] == [
        "generated_at_utc",
        "baseline_path",
        "baseline_sha256",
        "baseline_collected_at_utc",
        "current_path",
        "current_collected_at_utc",
        "comparison_status",
        "compared_domains",
        "skipped_domains",
        "changes",
        "findings",
    ]
    hints = get_type_hints(ChangeReport)
    assert hints["comparison_status"] is ComparisonStatus
    assert hints["changes"] == tuple[Change, ...]
    assert hints["findings"] == tuple[Finding, ...]
    report = _report()
    assert not hasattr(report, "__dict__")
    with pytest.raises(FrozenInstanceError):
        report.current_path = "changed"  # type: ignore[misc]


def test_canonical_root_and_nested_keys_are_exact() -> None:
    mapping = report_to_mapping(_report())
    assert set(mapping) == {
        "schema_version",
        "tool_version",
        "generated_at_utc",
        "baseline",
        "current",
        "comparison",
        "changes",
        "findings",
        "summary",
    }
    assert mapping["schema_version"] == CHANGE_SCHEMA_VERSION == "driftape.changes.v1"
    assert mapping["tool_version"] == TOOL_VERSION == "0.1.0"
    assert set(mapping["baseline"]) == {"path", "sha256", "collected_at_utc"}  # type: ignore[arg-type]
    assert set(mapping["current"]) == {"path", "collected_at_utc"}  # type: ignore[arg-type]
    assert set(mapping["comparison"]) == {  # type: ignore[arg-type]
        "status",
        "compared_domains",
        "skipped_domains",
        "errors",
    }
    assert mapping["comparison"]["errors"] == []  # type: ignore[index]
    assert set(mapping["summary"]) == {"changes", "findings", "severity"}  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "timestamp",
    ("2026-08-27T10:00:00Z", "0001-01-01T00:00:00Z", "2000-02-29T23:59:59Z"),
)
def test_canonical_timestamps_accepted(timestamp: str) -> None:
    assert _report(generated_at_utc=timestamp).generated_at_utc == timestamp


@pytest.mark.parametrize(
    "timestamp",
    (
        "1-01-01T00:00:00Z",
        "001-01-01T00:00:00Z",
        "02026-08-27T10:00:00Z",
        "2026-08-27T10:00:00+00:00",
        "2026-08-27T10:00:00.000Z",
        "2026-02-29T10:00:00Z",
        "2026-13-01T10:00:00Z",
        "2026-08-27T24:00:00Z",
        "2026-08-27T10:60:00Z",
        "2026-08-27T10:00:60Z",
    ),
)
def test_malformed_timestamps_rejected(timestamp: str) -> None:
    with pytest.raises(InvalidReportInputError):
        _report(generated_at_utc=timestamp)


@pytest.mark.parametrize("field", ("baseline_collected_at_utc", "current_collected_at_utc"))
def test_all_context_timestamps_are_validated(field: str) -> None:
    kwargs = {field: "2026-08-27T09:30:00+00:00"}
    with pytest.raises(InvalidReportInputError):
        _report(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "sha",
    ("A" * 64, "g" * 64, "a" * 63, "a" * 65, "", "00-" + "a" * 61),
)
def test_malformed_sha256_rejected(sha: str) -> None:
    with pytest.raises(InvalidReportInputError):
        _report(baseline_sha256=sha)


@pytest.mark.parametrize("field", ("baseline_path", "current_path"))
def test_empty_paths_rejected(field: str) -> None:
    kwargs = {field: ""}
    with pytest.raises(InvalidReportInputError):
        _report(**kwargs)  # type: ignore[arg-type]


def test_paths_are_preserved_as_supplied_labels() -> None:
    report = _report(baseline_path="../RAW/../baseline.json", current_path="C:\\x\\current.json")
    assert report.baseline_path == "../RAW/../baseline.json"
    assert report.current_path == "C:\\x\\current.json"


@pytest.mark.parametrize(
    ("change_type", "old_value", "new_value"),
    (
        (ChangeType.ADDED, None, {"name": "Alice", "roles": ["one", {"k": "v"}]}),
        (ChangeType.REMOVED, {"name": "Alice"}, None),
        (ChangeType.MODIFIED, ["old"], ["new"]),
    ),
)
def test_change_projection_is_exact(
    change_type: ChangeType, old_value: object, new_value: object
) -> None:
    change = _change(
        change_type=change_type,
        property_name="name" if change_type is ChangeType.MODIFIED else None,
        old_value=old_value,
        new_value=new_value,
    )
    mapping = report_to_mapping(_report(changes=(change,), findings=()))["changes"][0]  # type: ignore[index]
    assert set(mapping) == {
        "change_id",
        "domain",
        "object_type",
        "object_id",
        "object_name",
        "change_type",
        "property",
        "old_value",
        "new_value",
    }
    assert mapping["change_type"] == change_type.value
    assert mapping["old_value"] == old_value
    assert mapping["new_value"] == new_value
    assert not isinstance(mapping["change_type"], ChangeType)


def test_none_values_serialize_as_json_null_and_nested_values_are_preserved() -> None:
    nested = {"z": [1, True, None, {"nested": "ä"}]}
    change = _change(old_value=None, new_value=nested)
    report = _report(changes=(change,), findings=())
    mapping = report_to_mapping(report)
    assert mapping["changes"][0]["old_value"] is None  # type: ignore[index]
    assert mapping["changes"][0]["new_value"] == nested  # type: ignore[index]
    payload = serialize_report(report)
    assert b'"old_value":null' in payload


def test_finding_projection_exact_and_fixed_wp11_text_preserved() -> None:
    report = _report()
    mapping = report_to_mapping(report)["findings"][0]  # type: ignore[index]
    assert set(mapping) == {
        "finding_id",
        "rule_id",
        "severity",
        "title",
        "message",
        "domain",
        "change_ids",
    }
    assert mapping == {
        "finding_id": "f1",
        "rule_id": "DA-USR-001",
        "severity": "MEDIUM",
        "title": "Local user added",
        "message": "A local user account was added and should be reviewed.",
        "domain": "users.local_users",
        "change_ids": ["c1"],
    }
    assert not isinstance(mapping["severity"], FindingSeverity)


def test_orphan_finding_change_id_rejected() -> None:
    with pytest.raises(InvalidReportInputError, match="unknown change_id"):
        _report(findings=(_finding(change_id="missing"),))


def test_duplicate_finding_id_rejected() -> None:
    changes = (_change("c1", object_id="1"), _change("c2", object_id="2"))
    findings = (
        _finding("dup", rule_id="A", change_id="c1"),
        _finding("dup", rule_id="B", change_id="c2"),
    )
    with pytest.raises(InvalidReportInputError, match="duplicate finding_id"):
        _report(changes=changes, findings=findings)


def test_non_finding_member_rejected() -> None:
    with pytest.raises(InvalidReportInputError, match="non-Finding"):
        _report(findings=("not-a-finding",))  # type: ignore[arg-type]


def test_noncanonical_multiple_change_binding_rejected() -> None:
    changes = (_change("c1", object_id="1"), _change("c2", object_id="2"))
    finding = replace(_finding(), change_ids=("c1", "c2"))
    with pytest.raises(InvalidReportInputError, match="sole change_id"):
        _report(changes=changes, findings=(finding,))


def test_accepted_canonical_change_and_finding_order_succeeds() -> None:
    changes = (
        _change("c1", domain="services.services", object_id="a"),
        _change("c2", domain="services.services", object_id="b"),
    )
    findings = (
        _finding("f1", rule_id="DA-A", change_id="c1", domain="services.services"),
        _finding("f2", rule_id="DA-B", change_id="c2", domain="services.services"),
    )
    report = _report(changes=changes, findings=findings)
    assert report.changes == changes
    assert report.findings == findings


def test_reversed_malformed_change_order_rejected() -> None:
    changes = (
        _change("c2", domain="services.services", object_id="b"),
        _change("c1", domain="services.services", object_id="a"),
    )
    with pytest.raises(InvalidReportInputError, match="WP10 canonical order"):
        _report(changes=changes, findings=())


def test_reversed_malformed_finding_order_rejected() -> None:
    changes = (_change("c1", object_id="a"), _change("c2", object_id="b"))
    findings = (
        _finding("f2", rule_id="DA-B", change_id="c2"),
        _finding("f1", rule_id="DA-A", change_id="c1"),
    )
    with pytest.raises(InvalidReportInputError, match="WP11 canonical order"):
        _report(changes=changes, findings=findings)


def test_duplicate_change_id_rejected() -> None:
    changes = (_change("dup", object_id="a"), _change("dup", object_id="b"))
    with pytest.raises(InvalidReportInputError, match="duplicate change_id"):
        _report(changes=changes, findings=())


def test_empty_changes_and_findings_accepted_with_zero_summary() -> None:
    report = _report(changes=(), findings=())
    summary = report_to_mapping(report)["summary"]
    assert summary == {
        "changes": 0,
        "findings": 0,
        "severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }


def test_summary_mixed_severity_counts_are_exact_and_independent_of_changes() -> None:
    changes = tuple(_change(f"c{i}", object_id=f"{i:02}") for i in range(1, 6))
    findings = (
        _finding("f1", rule_id="A", severity=FindingSeverity.HIGH, change_id="c1"),
        _finding("f2", rule_id="B", severity=FindingSeverity.MEDIUM, change_id="c2"),
        _finding("f3", rule_id="C", severity=FindingSeverity.LOW, change_id="c3"),
        _finding("f4", rule_id="D", severity=FindingSeverity.INFO, change_id="c4"),
    )
    summary = report_to_mapping(_report(changes=changes, findings=findings))["summary"]
    assert summary["changes"] == 5  # type: ignore[index]
    assert summary["findings"] == 4  # type: ignore[index]
    assert summary["severity"] == {  # type: ignore[index]
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1,
    }


def test_all_four_zero_severity_keys_remain_present_when_unmatched_changes_exist() -> None:
    summary = report_to_mapping(_report(findings=()))["summary"]
    assert summary["changes"] == 1  # type: ignore[index]
    assert summary["findings"] == 0  # type: ignore[index]
    assert summary["severity"] == {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}  # type: ignore[index]


def test_exact_representative_canonical_json_bytes() -> None:
    expected = (
        b'{"baseline":{"collected_at_utc":"2026-08-27T09:00:00Z","path":"baseline.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},'
        b'"changes":[{"change_id":"c1","change_type":"ADDED","domain":"users.local_users","new_value":{"enabled":true,"name":"Alice"},"object_id":"S-1","object_name":"Alice","object_type":"local_user","old_value":null,"property":null}],'
        b'"comparison":{"compared_domains":["users.local_users"],"errors":[],"skipped_domains":[],"status":"complete"},'
        b'"current":{"collected_at_utc":"2026-08-27T09:30:00Z","path":"current.json"},'
        b'"findings":[{"change_ids":["c1"],"domain":"users.local_users","finding_id":"f1","message":"A local user account was added and should be reviewed.","rule_id":"DA-USR-001","severity":"MEDIUM","title":"Local user added"}],'
        b'"generated_at_utc":"2026-08-27T10:00:00Z","schema_version":"driftape.changes.v1",'
        b'"summary":{"changes":1,"findings":1,"severity":{"HIGH":0,"INFO":0,"LOW":0,"MEDIUM":1}},"tool_version":"0.1.0"}\n'
    )
    assert serialize_report(_report()) == expected


def test_serialization_has_exact_one_trailing_lf_no_bom_no_indentation() -> None:
    payload = serialize_report(_report())
    assert payload.endswith(b"\n")
    assert not payload.endswith(b"\n\n")
    assert not payload.startswith(b"\xef\xbb\xbf")
    assert b"\n" not in payload[:-1]
    assert b": " not in payload


def test_ensure_ascii_false_preserves_non_ascii_utf8() -> None:
    change = _change(object_name="Jörg", new_value={"name": "Jörg"})
    report = _report(
        baseline_path="bäsëline.json",
        current_path="aktuell-東京.json",
        changes=(change,),
        findings=(),
    )
    payload = serialize_report(report)
    assert "bäsëline.json".encode() in payload
    assert "東京".encode() in payload
    assert "Jörg".encode() in payload
    assert b"\\u00e4" not in payload


def test_same_report_serializes_identically_twice() -> None:
    report = _report()
    assert serialize_report(report) == serialize_report(report)


def test_nested_dictionary_insertion_order_does_not_change_output_bytes() -> None:
    first = {"b": 2, "a": 1}
    second = {"a": 1, "b": 2}
    report_a = _report(changes=(_change(new_value=first),), findings=())
    report_b = _report(changes=(_change(new_value=second),), findings=())
    assert serialize_report(report_a) == serialize_report(report_b)


@pytest.mark.parametrize("bad_number", (math.nan, math.inf, -math.inf))
def test_nan_and_infinity_rejected_by_json_serialization(bad_number: float) -> None:
    report = _report(changes=(_change(new_value=bad_number),), findings=())
    with pytest.raises(ValueError):
        serialize_report(report)


def test_complete_terminal_summary_exact_golden_text() -> None:
    changes = tuple(_change(f"c{i}", object_id=f"{i:02}") for i in range(1, 6))
    findings = (
        _finding("f1", rule_id="A", severity=FindingSeverity.HIGH, change_id="c1"),
        _finding("f2", rule_id="B", severity=FindingSeverity.MEDIUM, change_id="c2"),
        _finding("f3", rule_id="C", severity=FindingSeverity.MEDIUM, change_id="c3"),
        _finding("f4", rule_id="D", severity=FindingSeverity.INFO, change_id="c4"),
        _finding("f5", rule_id="E", severity=FindingSeverity.INFO, change_id="c5"),
    )
    report = _report(
        compared_domains=("d1", "d2", "d3", "d4", "d5", "d6", "d7"),
        changes=changes,
        findings=findings,
    )
    expected = (
        "DriftApe 0.1.0\n"
        "\n"
        "Baseline integrity: VERIFIED\n"
        "Comparison: COMPLETE\n"
        "Domains: 7/7 compared\n"
        "Skipped domains: 0\n"
        "\n"
        "Changes: 5\n"
        "Findings: 5\n"
        "\n"
        "HIGH    1\n"
        "MEDIUM  2\n"
        "LOW     0\n"
        "INFO    2\n"
        "\n"
        "Output: changes.json\n"
    )
    assert render_terminal_summary(report, "changes.json") == expected


def test_partial_terminal_summary_zero_findings_and_nondefault_output_path() -> None:
    report = _report(
        status=ComparisonStatus.PARTIAL,
        compared_domains=("d1", "d2", "d3", "d4", "d5"),
        skipped_domains=("d6", "d7"),
        findings=(),
    )
    text = render_terminal_summary(report, "reports/changes-01.json")
    assert "Comparison: PARTIAL\n" in text
    assert "Domains: 5/7 compared\n" in text
    assert "Skipped domains: 2\n" in text
    assert "Findings: 0\n" in text
    assert "HIGH    0\nMEDIUM  0\nLOW     0\nINFO    0\n" in text
    assert text.endswith("Output: reports/changes-01.json\n")
    assert not text.endswith("\n\n")
    assert "{\"" not in text


def test_terminal_output_path_must_be_nonempty_string() -> None:
    with pytest.raises(InvalidReportInputError):
        render_terminal_summary(_report(), "")


def test_build_report_rejects_non_diff_result() -> None:
    with pytest.raises(InvalidReportInputError, match="DiffResult"):
        build_report(
            generated_at_utc="2026-08-27T10:00:00Z",
            baseline_path="baseline.json",
            baseline_sha256=SHA,
            baseline_collected_at_utc="2026-08-27T09:00:00Z",
            current_path="current.json",
            current_collected_at_utc="2026-08-27T09:30:00Z",
            diff_result="bad",  # type: ignore[arg-type]
            findings=(),
        )


def test_wp12_production_scope_contains_no_forbidden_behavior() -> None:
    root = Path(__file__).resolve().parents[2]
    production_files = (
        root / "driftape" / "reporting" / "json_report.py",
        root / "driftape" / "reporting" / "terminal.py",
    )
    forbidden = (
        "argparse",
        "print(",
        "open(",
        "Path(",
        "write_text",
        "write_bytes",
        "os.replace",
        "subprocess",
        "run_powershell_json",
        "collect_snapshot",
        "compare_snapshots",
        "evaluate_changes",
        "Get-LocalUser",
        "Get-CimInstance",
        "Get-ScheduledTask",
        "Get-MpPreference",
        "Get-MpComputerStatus",
    )
    for path in production_files:
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{token!r} unexpectedly present in {path.name}"
