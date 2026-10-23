"""WP3 report CLI contract, failure atomicity, and offline-only execution."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from driftape.cli import _build_parser, main
from driftape.reporting.html_report import render_html
from driftape.reporting.json_reader import MAX_REPORT_BYTES, load_change_report

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "examples" / "changes.synthetic.json"
SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _write_report(tmp_path: Path, variant: str = "sample") -> Path:
    data = json.loads(SAMPLE.read_bytes())
    if variant == "v02":
        data["tool_version"] = "0.2.0.dev0"
    elif variant == "partial":
        data["comparison"]["status"] = "partial"
        data["comparison"]["skipped_domains"] = ["defender.runtime"]
        data["comparison"]["compared_domains"].remove("defender.runtime")
    elif variant == "zero":
        data["changes"] = []
        data["findings"] = []
        data["summary"] = {
            "changes": 0,
            "findings": 0,
            "severity": dict.fromkeys(SEVERITIES, 0),
        }
    elif variant == "hostile":
        data["baseline"]["path"] = '<script src="https://evil.invalid/x"></script>'
        data["changes"][0]["object_name"] = '<img src=x onerror="alert(1)">'
        data["findings"][0]["message"] = "<svg/onload=alert(1)>"
    elif variant != "sample":
        raise ValueError(variant)
    path = tmp_path / "input.json"
    path.write_bytes(_canonical(data))
    return path


def test_report_parser_defaults_custom_and_required_path() -> None:
    parser = _build_parser()
    args = parser.parse_args(["report", "saved.json"])
    assert (args.command, args.CHANGES, args.output, args.force) == (
        "report",
        "saved.json",
        "changes.html",
        False,
    )
    custom = parser.parse_args(["report", "a.json", "--output", "b.html", "--force"])
    assert (custom.output, custom.force) == ("b.html", True)
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["report"])
    assert exc.value.code == 2


@pytest.mark.parametrize("variant", ["sample", "v02", "partial", "zero"])
def test_valid_report_exact_bytes_and_provenance(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], variant: str
) -> None:
    source = _write_report(tmp_path, variant)
    original = source.read_bytes()
    target = tmp_path / "nested" / "result.html"
    status = main(["report", str(source), "--output", str(target)])
    captured = capsys.readouterr()
    assert status == 0
    assert captured.err == ""
    assert "Report written:" in captured.out
    assert "<" not in captured.out
    assert target.read_bytes() == render_html(load_change_report(source))
    assert source.read_bytes() == original
    assert load_change_report(source).tool_version.encode() in target.read_bytes()
    if variant == "partial":
        assert b"PARTIAL" in target.read_bytes()


def test_default_output_in_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_report(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert main(["report", "input.json"]) == 0
    assert Path("changes.html").read_bytes() == render_html(load_change_report(source))


def test_refuse_existing_output_without_force_and_allow_force(tmp_path: Path) -> None:
    source = _write_report(tmp_path)
    target = tmp_path / "report.html"
    target.write_bytes(b"original output")
    assert main(["report", str(source), "--output", str(target)]) == 3
    assert target.read_bytes() == b"original output"
    assert main(["report", str(source), "--output", str(target), "--force"]) == 0
    assert target.read_bytes() == render_html(load_change_report(source))


@pytest.mark.parametrize("alias_kind", ["direct", "relative", "symlink", "hardlink"])
def test_never_overwrite_input_alias_even_with_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias_kind: str
) -> None:
    source = _write_report(tmp_path)
    original = source.read_bytes()
    if alias_kind == "direct":
        output = source
    elif alias_kind == "relative":
        monkeypatch.chdir(tmp_path)
        output = Path("./input.json")
    else:
        output = tmp_path / "alias.json"
        if alias_kind == "symlink":
            try:
                output.symlink_to(source)
            except (OSError, NotImplementedError) as exc:
                # Alias safety remains testable when OS denies link creation.
                assert isinstance(exc, (OSError, NotImplementedError))
                output = source
        else:
            os.link(source, output)
    assert main(["report", str(source), "--output", str(output), "--force"]) == 3
    assert source.read_bytes() == original
    assert output.read_bytes() == original
    assert list(tmp_path.glob(".*.tmp")) == []


@pytest.mark.parametrize(
    "bad_kind,expected",
    [
        ("missing", 3),
        ("directory", 6),
        ("schema", 5),
        ("malformed", 6),
        ("duplicate", 6),
        ("noncanonical", 6),
        ("oversized", 6),
    ],
)
def test_input_errors_preserve_existing_destination(
    tmp_path: Path, bad_kind: str, expected: int, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "bad.json"
    if bad_kind == "directory":
        source.mkdir()
    elif bad_kind == "schema":
        data = json.loads(SAMPLE.read_bytes())
        data["schema_version"] = "driftape.changes.v2"
        source.write_bytes(_canonical(data))
    elif bad_kind == "malformed":
        source.write_bytes(b"{bad json")
    elif bad_kind == "duplicate":
        source.write_bytes(b'{"schema_version":"driftape.changes.v1","a":1,"a":2}\n')
    elif bad_kind == "noncanonical":
        source.write_bytes(SAMPLE.read_bytes().rstrip(b"\n"))
    elif bad_kind == "oversized":
        with source.open("wb") as stream:
            stream.truncate(MAX_REPORT_BYTES + 1)
    target = tmp_path / "output.html"
    target.write_bytes(b"unchanged")
    assert main(["report", str(source), "--output", str(target), "--force"]) == expected
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "DriftApe:" in captured.err
    assert "Traceback" not in captured.err
    assert target.read_bytes() == b"unchanged"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_render_failure_does_not_touch_output_or_preflight(tmp_path: Path) -> None:
    source = _write_report(tmp_path)
    target = tmp_path / "output.html"
    target.write_bytes(b"untouched")
    with (
        patch("driftape.cli.render_html", side_effect=RuntimeError("render error")),
        patch("driftape.cli._preflight_output") as preflight,
    ):
        assert main(["report", str(source), "--output", str(target), "--force"]) == 3
    preflight.assert_not_called()
    assert target.read_bytes() == b"untouched"


def test_write_failure_does_not_leave_temp_or_mutate_output(tmp_path: Path) -> None:
    source = _write_report(tmp_path)
    target = tmp_path / "output.html"
    target.write_bytes(b"untouched")
    with patch("driftape.cli.os.replace", side_effect=OSError("write denied")):
        assert main(["report", str(source), "--output", str(target), "--force"]) == 3
    assert target.read_bytes() == b"untouched"
    assert list(tmp_path.glob(".output.html.*.tmp")) == []


def test_reader_and_renderer_errors_do_not_write(tmp_path: Path) -> None:
    source = _write_report(tmp_path)
    target = tmp_path / "not-created.html"
    with patch("driftape.cli._atomic_write_bytes") as writer:
        with patch("driftape.cli.load_change_report", side_effect=OSError("blocked")):
            assert main(["report", str(source), "--output", str(target)]) == 3
        writer.assert_not_called()
    assert not target.exists()


def test_offline_report_does_not_collect_or_execute_or_access_network(
    tmp_path: Path,
) -> None:
    source = _write_report(tmp_path)
    target = tmp_path / "output.html"
    with (
        patch("driftape.cli.collect_snapshot", side_effect=AssertionError("collector")),
        patch("driftape.cli.compare_snapshots", side_effect=AssertionError("diff")),
        patch("driftape.cli.evaluate_changes", side_effect=AssertionError("rules")),
        patch("os.system", side_effect=AssertionError("shell")),
        patch("os.popen", side_effect=AssertionError("shell")),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch("subprocess.Popen", side_effect=AssertionError("process")),
        patch("os.startfile", create=True, side_effect=AssertionError("launch")),
    ):
        assert main(["report", str(source), "--output", str(target)]) == 0
    assert target.is_file()


def test_untrusted_labels_and_payloads_remain_inert(tmp_path: Path) -> None:
    source = _write_report(tmp_path, "hostile")
    target = tmp_path / "output.html"
    assert main(["report", str(source), "--output", str(target)]) == 0
    rendered = target.read_text(encoding="utf-8")
    assert '<script src="https://evil.invalid/x"></script>' not in rendered
    assert '<img src=x onerror="alert(1)">' not in rendered
    assert "<svg/onload=alert(1)>" not in rendered
    assert "&lt;script" in rendered
    assert "&lt;img" in rendered
    assert "&lt;svg" in rendered
    assert "default-src 'none'" in rendered
