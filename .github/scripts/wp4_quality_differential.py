#!/usr/bin/env python3
"""Evidence-only WP4 baseline-relative quality and hosted Windows skip inspection.

This script operates on two immutable source checkouts and stores all output externally.
Global failures are preserved as KNOWN_BASELINE_FAIL, never reclassified as global PASS.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

EXPECTED = {"ruff": 226, "format": 22, "mypy": 22}
MYPY_LINE = re.compile(r"^(.*?):(\d+)(?::(\d+))?: (error|warning|note): (.+)$")
FORMAT_LINE = re.compile(r"^\s*-->\s+(.+?):\d+:\d+\s*$")


def run(argv: list[str], cwd: Path, output: Path, name: str) -> dict:
    env = dict(os.environ)
    env["RUFF_CACHE_DIR"] = str((output / "caches" / name / "ruff").resolve())
    env["MYPY_CACHE_DIR"] = str((output / "caches" / name / "mypy").resolve())
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    p = subprocess.run(argv, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    record = {"command": argv, "cwd": str(cwd), "exit_code": p.returncode}
    dest = output / "logs"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / (name + ".stdout.txt")).write_text(p.stdout, encoding="utf-8", newline="\n")
    (dest / (name + ".stderr.txt")).write_text(p.stderr, encoding="utf-8", newline="\n")
    return {**record, "stdout": p.stdout, "stderr": p.stderr}


def source_check(path: Path, reference: dict[str,str]):
    actual = {}
    for name, want in reference.items():
        p = path / name
        if not p.is_file():
            raise ValueError(f"missing pinned source: {path.name}/{name}")
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        actual[name] = got
        if got != want:
            raise ValueError(f"pinned file mutation: {path.name}/{name}: {got} != {want}")
    return len(actual)


def rel_name(value: str, root: Path) -> str:
    p = Path(value)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(root.resolve())
        except ValueError:
            raise ValueError(f"diagnostic outside source tree: {value}")
    return p.as_posix().replace("\\", "/")


def check_ruff(record: dict, root: Path) -> Counter:
    try:
        rows = json.loads(record["stdout"])
    except Exception as exc:
        raise ValueError("invalid Ruff JSON; see raw logs") from exc
    if not isinstance(rows, list):
        raise ValueError("Ruff JSON is not an array")
    out = Counter()
    for d in rows:
        out[(rel_name(d["filename"], root), str(d.get("code")), d["message"])] += 1
    if record["exit_code"] not in (0, 1):
        raise ValueError("unexpected Ruff subprocess failure")
    return out


def check_format(record: dict, root: Path) -> Counter:
    if record["exit_code"] not in (0, 1):
        raise ValueError("unexpected format subprocess failure")
    out = Counter()
    pending = False
    for line in (record["stdout"] + "\n" + record["stderr"]).splitlines():
        if line.strip().startswith("unformatted: File would be reformatted"):
            pending = True
        elif pending:
            m = FORMAT_LINE.match(line)
            if m:
                out[(rel_name(m.group(1), root),)] += 1
                pending = False
    return out


def check_mypy(record: dict, root: Path) -> Counter:
    if record["exit_code"] not in (0, 1):
        raise ValueError("unexpected mypy subprocess failure")
    out = Counter()
    for line in record["stdout"].splitlines():
        m = MYPY_LINE.match(line.strip())
        if m and m.group(4) in ("error", "warning"):
            out[(rel_name(m.group(1), root), m.group(4), m.group(5))] += 1
    return out


def details(c: Counter) -> list[dict]:
    return [{"identity": list(k), "count": n} for k, n in sorted(c.items())]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--candidate", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    baseline, candidate, output = args.baseline.resolve(), args.candidate.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report: dict = {"version": "WP4_QUALITY_EVIDENCE_R1", "python": sys.version, "tools": {}, "source": {}, "checks": {}, "global_gate": "NOT_GREEN_HISTORICAL", "baseline_relative_gate": "NOT_EVALUATED"}
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        for key, root in (("wp2", baseline), ("wp3", candidate)):
            report["source"][key] = {"file_count": source_check(root, manifest[key]), "pinned_archive_sha256": manifest[key+"_archive_sha256"]}
        for kind, argv, version in (("ruff", ["ruff", "--version"], "ruff 0.17.0"), ("mypy", ["mypy", "--version"], "mypy 1.20.2"), ("pytest", [sys.executable, "-m", "pytest", "--version"], "pytest 8.4.2")):
            r = run(argv, candidate, output, "version_"+kind)
            got = (r["stdout"] + r["stderr"]).strip()
            report["tools"][kind] = {"observed": got, "exit_code": r["exit_code"]}
            if version not in got or r["exit_code"]:
                raise ValueError(f"tool version is not pinned: {kind}: {got}")
        commands = {
            "ruff": ["ruff", "check", ".", "--exclude", ".github", "--output-format=json"],
            "format": ["ruff", "format", "--check", ".", "--exclude", ".github"],
            "mypy": ["mypy", "driftape", "--show-error-codes", "--no-error-summary"],
        }
        parsers = {"ruff": check_ruff, "format": check_format, "mypy": check_mypy}
        passed = True
        for category, command in commands.items():
            a = run(command, baseline, output, "wp2_"+category)
            b = run(command, candidate, output, "wp3_"+category)
            da, db = parsers[category](a, baseline), parsers[category](b, candidate)
            added, removed = db - da, da - db
            equal = not added and not removed
            same_count = sum(db.values()) == EXPECTED[category] and sum(da.values()) == EXPECTED[category]
            passed &= equal and same_count
            report["checks"][category] = {
                "baseline_count": sum(da.values()), "candidate_count": sum(db.values()),
                "expected_count": EXPECTED[category], "baseline_exit": a["exit_code"],
                "candidate_exit": b["exit_code"], "equal_normalized_diagnostics": equal,
                "count_matches_expected": same_count, "added": details(added), "removed": details(removed),
                "global_gate": "KNOWN_BASELINE_FAIL" if b["exit_code"] != 0 else "PASS",
            }
        # Native Win11 WP4 is authoritative; hosted Windows skips may differ. Log explanations.
        test = run([sys.executable, "-m", "pytest", "-q", "-rs"], candidate, output, "wp3_pytest_with_skip_reasons")
        report["hosted_tests"] = {"exit_code": test["exit_code"], "summary_tail": test["stdout"][-4500:]}
        passed &= test["exit_code"] == 0
        # Confirm pinned files remained exactly intact after all tests and tools.
        for key, root in (("wp2", baseline), ("wp3", candidate)):
            source_check(root, manifest[key])
        report["source"]["post_check"] = "PASS"
        report["baseline_relative_gate"] = "PASS" if passed else "FAIL"
    except Exception as exc:
        report["baseline_relative_gate"] = "BLOCKED"
        report["exception"] = f"{type(exc).__name__}: {exc}"
    (output / "QUALITY_EVIDENCE.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    lines = ["# WP4 Hosted Windows quality evidence", "", "Global quality gates are **not green**; only the baseline-relative comparison can pass.", "", f"Baseline relative: **{report['baseline_relative_gate']}**", ""]
    for cat, data in report.get("checks", {}).items():
        lines.append(f"- {cat}: WP2 {data['baseline_count']}, WP3 {data['candidate_count']}, identical normalized diagnostics: {data['equal_normalized_diagnostics']}; global: {data['global_gate']}")
    if report.get("hosted_tests"):
        lines.append(f"- Hosted pytest exit code: {report['hosted_tests']['exit_code']}; skip reasons saved in raw log")
    if report.get("exception"):
        lines.append(f"- Verification error: {report['exception']}")
    (output / "SUMMARY.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if report["baseline_relative_gate"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
