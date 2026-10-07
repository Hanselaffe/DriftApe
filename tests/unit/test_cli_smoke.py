"""Package and operational CLI smoke tests."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import driftape
from driftape.cli import _build_parser, main

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_package_version() -> None:
    assert driftape.__version__ == "0.1.0"


def test_cli_version_returns_success(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["--version"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == "DriftApe 0.1.0\n"
    assert captured.err == ""


def test_python_module_uses_same_cli_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "driftape", "--version"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == "DriftApe 0.1.0\n"
    assert result.stderr == ""


def test_only_frozen_operational_subcommands_exist() -> None:
    parser = _build_parser()
    subparser_action = next(
        action
        for action in parser._actions  # noqa: SLF001 - parser surface smoke test
        if isinstance(action, __import__("argparse")._SubParsersAction)
    )
    assert set(subparser_action.choices) == {"baseline", "scan", "diff"}
    assert "report" not in subparser_action.choices


def test_parser_defaults_and_force_flags() -> None:
    parser = _build_parser()
    baseline = parser.parse_args(["baseline"])
    scan = parser.parse_args(["scan"])
    diff = parser.parse_args(["diff", "base.json", "current.json"])

    assert (baseline.output, baseline.force) == ("baseline.json", False)
    assert (scan.output, scan.force) == ("current.json", False)
    assert (diff.output, diff.force) == ("changes.json", False)

    baseline_custom = parser.parse_args(["baseline", "--output", "gold.json", "--force"])
    scan_custom = parser.parse_args(["scan", "--output", "now.json", "--force"])
    diff_custom = parser.parse_args(
        ["diff", "b.json", "c.json", "--output", "r.json", "--force"]
    )
    assert (baseline_custom.output, baseline_custom.force) == ("gold.json", True)
    assert (scan_custom.output, scan_custom.force) == ("now.json", True)
    assert (diff_custom.output, diff_custom.force) == ("r.json", True)


def test_diff_requires_baseline_and_current() -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["diff", "base.json"])
    assert exc_info.value.code == 2


def test_no_runtime_third_party_dependencies() -> None:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    assert pyproject["project"]["dependencies"] == []
