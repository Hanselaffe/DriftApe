"""Offline renderer contract: exact bytes, input integrity and inert HTML."""

from __future__ import annotations

import copy
import hashlib
import html
import json
import os
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from driftape.reporting.html_report import render_html
from driftape.reporting.json_reader import LoadedChangeReport, load_change_report

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "examples" / "changes.synthetic.json"
GOLDENS = ROOT / "tests" / "fixtures" / "html"
SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")


def _canonical(mapping: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            mapping,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _sample() -> dict[str, Any]:
    return json.loads(SAMPLE.read_bytes())


def _scenario(name: str) -> dict[str, Any]:
    data = _sample()
    if name == "complete_no_changes":
        data["changes"] = []
        data["findings"] = []
        data["summary"] = {
            "changes": 0,
            "findings": 0,
            "severity": dict.fromkeys(SEVERITIES, 0),
        }
    elif name == "partial_skipped_domains":
        skipped = {"tasks.tasks", "defender.runtime"}
        covered = data["comparison"]["compared_domains"]
        data["comparison"]["compared_domains"] = [
            domain for domain in covered if domain not in skipped
        ]
        data["comparison"]["skipped_domains"] = [
            domain for domain in covered if domain in skipped
        ]
        data["comparison"]["status"] = "partial"
    elif name != "complete_findings":
        raise ValueError(name)
    return data


def _load(tmp_path: Path, mapping: dict[str, Any]) -> LoadedChangeReport:
    path = tmp_path / "canonical.json"
    path.write_bytes(_canonical(mapping))
    return load_change_report(path)


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, list[tuple[str, str | None]]]] = []
        self.contents: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.append((tag, attrs))

    def handle_data(self, data: str) -> None:
        self.contents.append(data)


def _assert_inert(raw: bytes) -> _DocumentParser:
    text = raw.decode("utf-8", errors="strict")
    assert raw.startswith(b"<!doctype html>\n")
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert text.endswith("</html>\n")
    parsed = _DocumentParser()
    parsed.feed(text)
    parsed.close()
    allowed_tags = {
        "html",
        "head",
        "meta",
        "title",
        "style",
        "body",
        "h1",
        "h2",
        "h3",
        "section",
        "p",
        "strong",
        "table",
        "tbody",
        "tr",
        "th",
        "td",
        "pre",
        "ul",
        "li",
    }
    assert set(parsed.tags) <= allowed_tags
    assert parsed.tags.count("style") == 1
    for tag, attrs in parsed.attributes:
        allowed_attributes = {
            "html": {"lang"},
            "meta": {"charset", "name", "content", "http-equiv"},
            "section": {"class", "aria-label"},
            "th": {"scope"},
        }
        assert all(key in allowed_attributes.get(tag, set()) for key, _ in attrs)
        for key, value in attrs:
            assert not key.startswith("on")
            assert key not in {"href", "src", "srcset", "action"}
            if tag == "meta" and key == "content":
                assert value is not None
                assert (
                    "default-src 'none'" in value
                    or value == "width=device-width, initial-scale=1"
                )
    css = text.split("<style>\n", 1)[1].split("</style>", 1)[0]
    assert "url(" not in css.lower()
    assert "@import" not in css.lower()
    assert "http://" not in css.lower()
    assert "https://" not in css.lower()
    return parsed


@pytest.mark.parametrize(
    "name", ["complete_no_changes", "complete_findings", "partial_skipped_domains"]
)
def test_exact_golden_bytes_and_repeated_run(tmp_path: Path, name: str) -> None:
    loaded = _load(tmp_path, _scenario(name))
    expected = (GOLDENS / f"{name}.html").read_bytes()
    first = render_html(loaded)
    assert first == expected
    assert render_html(loaded) == first
    assert hashlib.sha256(first).digest() == hashlib.sha256(expected).digest()
    _assert_inert(first)


@pytest.mark.parametrize(
    "name", ["complete_no_changes", "complete_findings", "partial_skipped_domains"]
)
def test_independent_process_determinism(tmp_path: Path, name: str) -> None:
    loaded = _load(tmp_path, _scenario(name))
    local = hashlib.sha256(render_html(loaded)).hexdigest()
    script = (
        "import hashlib,sys;"
        "from pathlib import Path;"
        "from driftape.reporting.json_reader import load_change_report;"
        "from driftape.reporting.html_report import render_html;"
        "print(hashlib.sha256(render_html("
        "load_change_report(Path(sys.argv[1])))).hexdigest())"
    )
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    process_hashes = [
        subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / "canonical.json")],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        for _ in range(2)
    ]
    assert process_hashes == [local, local]
    assert loaded.canonical_bytes == _canonical(_scenario(name))


def test_renderer_rejects_nonvalidated_input() -> None:
    for invalid in (None, {}, "not-a-report", b"{}", SAMPLE):
        with pytest.raises(TypeError, match="validated LoadedChangeReport"):
            render_html(invalid)  # type: ignore[arg-type]


def test_complete_zero_is_not_security_clearance(tmp_path: Path) -> None:
    output = render_html(_load(tmp_path, _scenario("complete_no_changes"))).decode()
    assert "Comparison status: COMPLETE" in output
    assert "No changes reported in compared domains." in output
    assert "No findings reported in compared domains." in output
    assert "this is not a security clearance" in output
    assert '<th scope="row">HIGH findings</th><td><pre>0</pre>' in output
    assert '<th scope="row">MEDIUM findings</th><td><pre>0</pre>' in output
    assert '<th scope="row">LOW findings</th><td><pre>0</pre>' in output
    assert '<th scope="row">INFO findings</th><td><pre>0</pre>' in output


def test_partial_coverage_explicit_and_no_global_all_clear(tmp_path: Path) -> None:
    data = _scenario("partial_skipped_domains")
    data["changes"] = []
    data["findings"] = []
    data["summary"] = {
        "changes": 0,
        "findings": 0,
        "severity": dict.fromkeys(SEVERITIES, 0),
    }
    output = render_html(_load(tmp_path, data)).decode()
    assert "PARTIAL — incomplete domain coverage" in output
    assert "Exact skipped domains:" in output
    assert "<li>tasks.tasks</li>" in output
    assert "<li>defender.runtime</li>" in output
    assert "Skipped domains were not compared" in output
    assert "No changes reported in compared domains." in output
    assert "No findings reported in compared domains." in output
    assert "whole host" in output


def test_all_report_data_represented_with_original_version(tmp_path: Path) -> None:
    data = _scenario("complete_findings")
    data["tool_version"] = "0.2.0-test-build"
    raw = render_html(_load(tmp_path, data))
    text = raw.decode()
    for datum in (
        data["schema_version"],
        data["tool_version"],
        data["generated_at_utc"],
        data["baseline"]["path"],
        data["baseline"]["sha256"],
        data["baseline"]["collected_at_utc"],
        data["current"]["path"],
        data["current"]["collected_at_utc"],
    ):
        assert html.escape(datum, quote=True) in text
    for change in data["changes"]:
        for field in (
            "change_id",
            "domain",
            "object_type",
            "object_id",
            "object_name",
            "change_type",
        ):
            assert html.escape(change[field], quote=True) in text
        for field in ("property", "old_value", "new_value"):
            assert (
                html.escape(
                    json.dumps(
                        change[field],
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    quote=True,
                )
                in text
            )
    for finding in data["findings"]:
        for field in (
            "finding_id",
            "rule_id",
            "severity",
            "domain",
            "title",
            "message",
        ):
            assert html.escape(finding[field], quote=True) in text
        for change_id in finding["change_ids"]:
            assert html.escape(change_id, quote=True) in text
    for severity in SEVERITIES:
        expected_count = data["summary"]["severity"][severity]
        assert f">{severity} findings</th><td><pre>{expected_count}" in text
    assert "not a cryptographic authenticity signature or attestation" in text
    assert "may expose sensitive host and security information" in text
    _assert_inert(raw)


def test_adversarial_input_all_untrusted_fields_and_nested_values(
    tmp_path: Path,
) -> None:
    payload = (
        '</style><script>alert("x")</script>'
        "<img src='https://evil.invalid' onerror='run()'>&'日本語"
    )
    data = _sample()
    data["tool_version"] = payload
    data["baseline"]["path"] = payload
    data["current"]["path"] = payload
    c0 = data["changes"][0]
    c0["change_id"] = payload
    c0["object_type"] = payload
    c0["object_id"] = payload
    c0["object_name"] = payload
    c0["new_value"] = {
        "nested": [
            {"k": payload, "bytes": "\x00\r\x1f", "flag": True},
            None,
            False,
            0,
            1.5,
        ],
        payload: {"value": [payload]},
    }
    c1 = data["changes"][1]
    c1["property"] = payload
    c1["old_value"] = [payload, {payload: [False, None, 4]}]
    c1["new_value"] = {"field": payload}
    finding = data["findings"][1]
    finding["finding_id"] = payload
    finding["rule_id"] = payload
    finding["title"] = payload
    finding["message"] = payload
    finding["change_ids"] = [payload]
    # Canonical order is strict: adjust the tuples without weakening the reader.
    data["changes"] = sorted(
        data["changes"],
        key=lambda c: (
            c["domain"],
            c["object_id"],
            c["change_type"],
            c["property"] or "",
        ),
    )
    data["findings"] = sorted(
        data["findings"], key=lambda f: (f["rule_id"], f["change_ids"][0])
    )
    original = copy.deepcopy(data)
    loaded = _load(tmp_path, data)  # Always use WP1 strict reader.
    raw = render_html(loaded)
    parsed = _assert_inert(raw)
    text_nodes = "".join(parsed.contents)
    assert payload in text_nodes
    assert html.escape(payload, quote=True) in raw.decode()
    for escaped in ("\\u0000", "\\r", "\\u001f", "true", "false", "null", "1.5"):
        assert escaped in raw.decode()
    assert loaded.mapping == original
    assert render_html(loaded) == raw


def test_unicode_quotes_controls_and_json_types(tmp_path: Path) -> None:
    data = _sample()
    data["baseline"]["path"] = "C:\\‘日本語’'\\\"<&\x00\r\x1f"
    data["changes"][1]["old_value"] = {
        "zero": 0,
        "false": False,
        "none": None,
        "items": [1, "ü😀", {"b": True}],
    }
    data["changes"][1]["new_value"] = True
    output = render_html(_load(tmp_path, data)).decode()
    assert "日本語" in output and "ü😀" in output
    assert "&lt;&amp;\\u0000\\u000d\\u001f" in output
    assert "&quot;" in output and "&#x27;" in output
    assert "&quot;false&quot;:false" in output
    assert "&quot;none&quot;:null" in output
    assert "&quot;zero&quot;:0" in output
    assert "<pre>true</pre>" in output
    _assert_inert(output.encode())


def test_nontruncation_and_all_severity_counts(tmp_path: Path) -> None:
    data = _scenario("complete_no_changes")
    changes: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for index in range(64):
        cid = f"cid-{index:03d}"
        changes.append(
            {
                "change_id": cid,
                "domain": "services.services",
                "object_type": "service",
                "object_id": f"object-{index:03d}",
                "object_name": f"unique-name-{index:03d}",
                "change_type": "MODIFIED",
                "property": "path_name",
                "old_value": [None, False, index],
                "new_value": {"index": index, "active": True},
            }
        )
        findings.append(
            {
                "finding_id": f"fid-{index:03d}",
                "rule_id": "DA-TEST-001",
                "severity": SEVERITIES[index % 4],
                "title": f"Unique title {index:03d}",
                "message": f"Unique detail {index:03d}",
                "domain": "services.services",
                "change_ids": [cid],
            }
        )
    data["changes"] = changes
    data["findings"] = findings
    data["summary"] = {
        "changes": 64,
        "findings": 64,
        "severity": dict.fromkeys(SEVERITIES, 16),
    }
    output = render_html(_load(tmp_path, data)).decode()
    assert output.count('class="record"') == 128
    for index in range(64):
        assert f"unique-name-{index:03d}" in output
        assert f"Unique detail {index:03d}" in output
        assert f"cid-{index:03d}" in output
        assert f"fid-{index:03d}" in output
    for severity in SEVERITIES:
        assert f">{severity} findings</th><td><pre>16" in output
    _assert_inert(output.encode())


def test_input_unchanged_no_renderer_io_or_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaded = _load(tmp_path, _sample())
    original = copy.deepcopy(loaded.mapping)
    canonical = loaded.canonical_bytes

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("renderer attempted I/O or ambient access")

    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", forbidden)
        patch.setattr("os.open", forbidden)
        patch.setattr("pathlib.Path.open", forbidden)
        patch.setattr("pathlib.Path.read_bytes", forbidden)
        patch.setattr("pathlib.Path.write_bytes", forbidden)
        patch.setattr("time.time", forbidden)
        patch.setattr("uuid.uuid4", forbidden)
        patch.setattr("socket.socket", forbidden)
        first = render_html(loaded)
        second = render_html(loaded)
    assert first == second
    assert loaded.mapping == original
    assert loaded.canonical_bytes == canonical
    assert loaded.tool_version == original["tool_version"]
