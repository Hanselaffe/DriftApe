"""Deterministic human-readable DriftApe v0.1 terminal reporting."""

from driftape.constants import TOOL_VERSION
from driftape.diff import ComparisonStatus
from driftape.reporting.json_report import (
    ChangeReport,
    InvalidReportInputError,
    report_to_mapping,
)


def render_terminal_summary(report: ChangeReport, output_path: str) -> str:
    """Render the frozen WP12 terminal summary without performing output I/O."""
    if not isinstance(output_path, str) or output_path == "":
        raise InvalidReportInputError("output_path must be a non-empty string")

    summary = report_to_mapping(report)["summary"]
    if not isinstance(summary, dict):
        raise AssertionError("internal report summary must be a mapping")
    severity = summary["severity"]
    if not isinstance(severity, dict):
        raise AssertionError("internal severity summary must be a mapping")

    comparison = (
        "COMPLETE"
        if report.comparison_status is ComparisonStatus.COMPLETE
        else "PARTIAL"
    )
    lines = [
        f"DriftApe {TOOL_VERSION}",
        "",
        "Baseline integrity: VERIFIED",
        f"Comparison: {comparison}",
        f"Domains: {len(report.compared_domains)}/7 compared",
        f"Skipped domains: {len(report.skipped_domains)}",
        "",
        f"Changes: {summary['changes']}",
        f"Findings: {summary['findings']}",
        "",
        f"{'HIGH':<8}{severity['HIGH']}",
        f"{'MEDIUM':<8}{severity['MEDIUM']}",
        f"{'LOW':<8}{severity['LOW']}",
        f"{'INFO':<8}{severity['INFO']}",
        "",
        f"Output: {output_path}",
    ]
    return "\n".join(lines) + "\n"
