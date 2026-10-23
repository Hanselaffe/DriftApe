"""Portable module and installed console report CLI end-to-end checks."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from driftape.reporting.html_report import render_html
from driftape.reporting.json_reader import load_change_report

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "examples" / "changes.synthetic.json"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1"),
        capture_output=True,
        text=True,
        check=False,
    )


def test_module_report_exact_bytes_and_existing_output(tmp_path: Path) -> None:
    input_path = tmp_path / "changes.json"
    input_path.write_bytes(SAMPLE.read_bytes())
    output_path = tmp_path / "changes.html"
    command = [sys.executable, "-m", "driftape", "report", str(input_path)]
    first = _run(command, tmp_path)
    assert first.returncode == 0
    assert first.stderr == ""
    assert output_path.read_bytes() == render_html(load_change_report(input_path))
    assert input_path.read_bytes() == SAMPLE.read_bytes()
    second = _run(command, tmp_path)
    assert second.returncode == 3
    assert output_path.read_bytes() == render_html(load_change_report(input_path))
    third = _run([*command, "--force"], tmp_path)
    assert third.returncode == 0
    assert third.stderr == ""


def test_module_invalid_and_schema_codes(tmp_path: Path) -> None:
    invalid = tmp_path / "bad.json"
    invalid.write_text("not json", encoding="utf-8")
    result = _run([sys.executable, "-m", "driftape", "report", str(invalid)], tmp_path)
    assert result.returncode == 6
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "changes.html").exists()


def test_console_entrypoint_or_module_fallback(tmp_path: Path) -> None:
    executable = shutil.which("driftape")
    input_path = tmp_path / "input.json"
    input_path.write_bytes(SAMPLE.read_bytes())
    target = tmp_path / "out.html"
    argv = (
        [executable] if executable is not None else [sys.executable, "-m", "driftape"]
    )
    result = _run([*argv, "report", str(input_path), "--output", str(target)], tmp_path)
    assert result.returncode == 0, result.stderr
    assert target.read_bytes() == render_html(load_change_report(input_path))
