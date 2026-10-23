"""Deterministic, read-only, offline HTML for a validated change report.

The caller must supply a report returned by the strict WP1 JSON reader.
No source path is opened and no output is written by this module.
"""

from __future__ import annotations

import html
import json
from typing import Any

from driftape.reporting.json_reader import LoadedChangeReport

# Static document fragments only. Untrusted data is inserted solely via _text().
_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline';
               base-uri 'none'; form-action 'none'">
<title>DriftApe change report</title>
<style>
:root { color-scheme: light; font-family: system-ui, sans-serif; }
body { max-width: 76rem; margin: 1.5rem auto; padding: 0 1rem; color: #17212b;
       background: white; line-height: 1.5; }
h1, h2, h3 { line-height: 1.2; }
section { margin: 1.4rem 0; }
table { width: 100%; border-collapse: collapse; margin: .7rem 0; }
th, td { border: 1px solid #9da8b1; padding: .45rem .65rem;
         vertical-align: top; text-align: left; overflow-wrap: anywhere; }
th { background: #edf1f3; width: 13rem; }
.warning { border: .2rem solid #8e3705; background: #fff2e7;
           color: #492000; padding: 1rem; font-weight: 700; }
.notice { border: .12rem solid #475867; padding: 1rem; }
.record { border-top: .15rem solid #647482; padding-top: .6rem; break-inside: avoid; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; font: inherit; }
@media print {
  body { max-width: none; margin: 0; padding: 0; color: black; }
  .warning, .notice { background: white; color: black; }
  th { background: white; }
  .record { break-inside: auto; }
}
</style>
</head>
<body>
<h1>DriftApe change report</h1>
"""
_FOOT = "</body>\n</html>\n"


def _text(value: str) -> str:
    """Escape all untrusted text, including HTML-incompatible control codes."""
    # Represent control characters losslessly as printable unicode escape notation.
    printable = "".join(
        f"\\u{ord(char):04x}"
        if (ord(char) < 32 and char not in "\t\n") or ord(char) == 127
        else char
        for char in value
    )
    return html.escape(printable, quote=True)


def _json_text(value: Any) -> str:
    """Render JSON types without conflating null, false, numbers or strings."""
    return _text(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


def _row(label: str, value: str) -> str:
    """Insert already escaped text into a static two-column table row."""
    return f'<tr><th scope="row">{label}</th><td><pre>{value}</pre></td></tr>\n'


def _fields(rows: list[tuple[str, str]]) -> str:
    return (
        "<table>\n<tbody>\n"
        + "".join(_row(*row) for row in rows)
        + "</tbody>\n</table>\n"
    )


def _domain_list(domains: list[str]) -> str:
    if not domains:
        return "<p>None.</p>\n"
    return (
        "<ul>\n"
        + "".join(f"<li>{_text(domain)}</li>\n" for domain in domains)
        + "</ul>\n"
    )


def render_html(report: LoadedChangeReport) -> bytes:
    """Return UTF-8 HTML5 bytes for a strictly reader-validated report.

    Passing any other object raises TypeError. This function does not validate
    a newly fabricated LoadedChangeReport; validation belongs to the WP1 reader.
    The input mapping and canonical bytes are never mutated.
    """
    if not isinstance(report, LoadedChangeReport):
        raise TypeError("render_html expects a validated LoadedChangeReport")

    data = report.mapping
    baseline = data["baseline"]
    current = data["current"]
    comparison = data["comparison"]
    summary = data["summary"]
    changes = data["changes"]
    findings = data["findings"]
    parts = [_HEAD]

    parts.append('<section class="notice" aria-label="Handling warning">\n')
    parts.append("<h2>Security and provenance notice</h2>\n")
    parts.append(
        "<p>This locally generated offline HTML may expose sensitive host "
        "and security information. Handle, store, and share it accordingly.</p>\n"
    )
    parts.append(
        "<p>The baseline SHA-256 is an integrity-reference value, "
        "not a cryptographic authenticity signature or attestation.</p>\n"
    )
    parts.append("</section>\n")

    if comparison["status"] == "partial":
        parts.append(
            '<section class="warning" aria-label="Partial coverage warning">\n'
        )
        parts.append("<h2>PARTIAL — incomplete domain coverage</h2>\n")
        parts.append(
            "<p>Skipped domains were not compared. No absence of drift or "
            "security findings can be inferred for skipped domains or "
            "for the whole host. Exact skipped domains:</p>\n"
        )
        parts.append(_domain_list(comparison["skipped_domains"]))
        parts.append("</section>\n")
    else:
        parts.append("<p><strong>Comparison status: COMPLETE</strong> — ")
        parts.append("all seven defined domains compared; this is not a ")
        parts.append("security clearance.</p>\n")

    parts.append("<section>\n<h2>Report provenance</h2>\n")
    parts.append(
        _fields(
            [
                ("Schema version", _text(data["schema_version"])),
                ("Original tool version", _text(report.tool_version)),
                ("Generated at (UTC)", _text(data["generated_at_utc"])),
                ("Baseline path (label)", _text(baseline["path"])),
                ("Baseline collected (UTC)", _text(baseline["collected_at_utc"])),
                ("Baseline SHA-256", _text(baseline["sha256"])),
                ("Current path (label)", _text(current["path"])),
                ("Current collected (UTC)", _text(current["collected_at_utc"])),
                ("Comparison status", _text(comparison["status"].upper())),
            ]
        )
    )
    parts.append("</section>\n")

    parts.append("<section>\n<h2>Coverage</h2>\n<h3>Compared domains</h3>\n")
    parts.append(_domain_list(comparison["compared_domains"]))
    parts.append("<h3>Skipped domains</h3>\n")
    parts.append(_domain_list(comparison["skipped_domains"]))
    parts.append("</section>\n")

    parts.append("<section>\n<h2>Counts (compared domains only)</h2>\n")
    parts.append(
        _fields(
            [
                ("Changes", _text(str(summary["changes"]))),
                ("Findings", _text(str(summary["findings"]))),
                *[
                    (f"{severity} findings", _text(str(summary["severity"][severity])))
                    for severity in ("HIGH", "MEDIUM", "LOW", "INFO")
                ],
            ]
        )
    )
    parts.append("</section>\n")

    parts.append("<section>\n<h2>Changes</h2>\n")
    if not changes:
        parts.append("<p>No changes reported in compared domains.</p>\n")
    for idx, change in enumerate(changes, start=1):
        parts.append('<section class="record">\n')
        parts.append(f"<h3>Change {idx}</h3>\n")
        parts.append(
            _fields(
                [
                    ("Change ID", _text(change["change_id"])),
                    ("Domain", _text(change["domain"])),
                    ("Object type", _text(change["object_type"])),
                    ("Object ID", _text(change["object_id"])),
                    ("Object name", _text(change["object_name"])),
                    ("Change type", _text(change["change_type"])),
                    ("Property", _json_text(change["property"])),
                    ("Old value (JSON)", _json_text(change["old_value"])),
                    ("New value (JSON)", _json_text(change["new_value"])),
                ]
            )
        )
        parts.append("</section>\n")
    parts.append("</section>\n")

    parts.append("<section>\n<h2>Findings</h2>\n")
    if not findings:
        parts.append("<p>No findings reported in compared domains.</p>\n")
    for idx, finding in enumerate(findings, start=1):
        parts.append('<section class="record">\n')
        parts.append(f"<h3>Finding {idx}</h3>\n")
        parts.append(
            _fields(
                [
                    ("Finding ID", _text(finding["finding_id"])),
                    ("Rule ID", _text(finding["rule_id"])),
                    ("Severity", _text(finding["severity"])),
                    ("Domain", _text(finding["domain"])),
                    ("Title", _text(finding["title"])),
                    ("Message", _text(finding["message"])),
                    ("Linked change IDs", _fields_link_ids(finding["change_ids"])),
                ]
            )
        )
        parts.append("</section>\n")
    parts.append("</section>\n")

    parts.append(_FOOT)
    return "".join(parts).encode("utf-8")


def _fields_link_ids(ids: list[str]) -> str:
    """Display every linked ID as inert escaped text, never a hyperlink."""
    return ", ".join(_text(identifier) for identifier in ids)
