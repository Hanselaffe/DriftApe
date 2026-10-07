# DriftApe

DriftApe is a local, defensive, read-only, CLI-first Windows security configuration and state drift utility.

DriftApe v0.1 records a local baseline, collects a later local snapshot, verifies the baseline bytes against an adjacent SHA-256 manifest, compares the covered security-relevant state, and produces a JSON change report plus a terminal summary.

DriftApe is **not** an EDR, antivirus, malware scanner, pentesting framework, or remediation tool. It does not claim to detect malware or compromise.

## Frozen v0.1 scope

DriftApe v0.1 covers these local Windows data domains:

- local users
- local Administrators membership
- Windows services
- Scheduled Tasks
- Microsoft Defender exclusions
- Microsoft Defender `DisableRealtimeMonitoring`
- Microsoft Defender `RealTimeProtectionEnabled`

The v0.1 workflow provides:

- versioned snapshot contracts
- SHA-256 baseline integrity verification
- coverage-aware generic diffing across seven comparison domains
- security interpretation findings for supported changes
- a JSON change report
- a deterministic terminal summary
- `baseline`, `scan`, and `diff` CLI commands

## Requirements

- Windows x64 (AMD64)
- 64-bit Python 3.12 or 3.13

The collection commands intentionally enforce the supported Windows x64 runtime. The package has no runtime dependencies outside the Python standard library.

DriftApe does not deliberately elevate itself. Run it with the privileges you intend to assess. Limited privileges or unavailable Windows data can result in partial collection rather than silent assumptions.

## Installation

From a local checkout:

```powershell
python -m pip install .
```

For development and CI tooling:

```powershell
python -m pip install -e ".[dev]"
```

Confirm the installed version with either entry point:

```powershell
driftape --version
python -m driftape --version
```

## Quick start

Create a baseline:

```powershell
driftape baseline
```

Later, collect a current snapshot:

```powershell
driftape scan
```

Compare the current snapshot with the baseline:

```powershell
driftape diff baseline.json current.json
```

A successful baseline command writes both `baseline.json` and its adjacent `baseline.manifest.json`. The diff command verifies that baseline pair before comparison.

## CLI commands

### `driftape baseline`

Collects a snapshot with `snapshot_kind` set to `baseline` and writes the snapshot plus a bound SHA-256 manifest.

```powershell
driftape baseline [--output PATH] [--force]
```

### `driftape scan`

Collects a snapshot with `snapshot_kind` set to `current`.

```powershell
driftape scan [--output PATH] [--force]
```

### `driftape diff`

Loads and verifies the baseline pair, validates the current snapshot, checks host compatibility, compares only domains covered by both snapshots, evaluates supported findings, and writes the JSON change report.

```powershell
driftape diff BASELINE CURRENT [--output PATH] [--force]
```

## Default output files

| Command | Default output |
| --- | --- |
| `baseline` | `baseline.json` and `baseline.manifest.json` |
| `scan` | `current.json` |
| `diff` | `changes.json` |

A custom baseline name derives a same-directory manifest name from that baseline path. For example, `--output gold.json` produces `gold.json` and `gold.manifest.json`.

## Overwrite and `--force`

DriftApe refuses to overwrite an existing target by default. For `baseline`, this preflight applies to both the baseline and its manifest before collection begins. For `scan` and `diff`, it applies to the requested output file.

Use `--force` only when replacing the existing target is intentional:

```powershell
driftape scan --output current.json --force
```

## Exit codes

DriftApe v0.1 uses exit codes `0` through `8`:

| Code | Meaning |
| ---: | --- |
| `0` | Successful complete collection, or complete diff with no changes |
| `1` | Complete diff succeeded and changes were found |
| `2` | Collection or comparison completed with partial coverage |
| `3` | Operational, I/O, output, serialization, or internal orchestration failure |
| `4` | Baseline SHA-256 integrity verification failed |
| `5` | Unsupported or mismatched snapshot schema |
| `6` | Invalid baseline manifest/snapshot, current snapshot, or diff input |
| `7` | Baseline and current snapshots identify different hosts |
| `8` | Unsupported collection platform/runtime |

## Partial and incomplete collection

A snapshot records collector status, coverage, collector errors, and snapshot-level completeness. A collector may be `success`, `partial`, or `failed`. Missing coverage is represented explicitly; DriftApe does not treat unavailable data as an empty successful result.

When either snapshot lacks coverage for a comparison domain, that domain is skipped. The change report records `compared_domains` and `skipped_domains`, the overall comparison becomes `partial`, and the CLI returns exit code `2`. This keeps the report truthful about what was and was not compared.

## Baseline integrity model

The baseline command serializes the baseline canonically and writes an adjacent manifest containing a SHA-256 digest of the exact baseline bytes. Before a diff, DriftApe validates the manifest and baseline, verifies canonical encoding, and compares the recorded digest with the actual baseline bytes.

This detects accidental or unauthorized modification when the manifest remains trustworthy. **SHA-256 does not authenticate the baseline against an attacker who can alter both the baseline and its manifest.** DriftApe v0.1 does not provide digital signatures, remote attestation, or another external trust anchor.

## Privileges and read-only behavior

DriftApe is designed to inspect local state without changing Windows configuration. It does not deliberately request elevation, remediate findings, alter Defender settings, change users or group memberships, modify services or tasks, or install a background service.

The process privileges determine what Windows can be collected. Running without administrative access can therefore produce partial results. Review collector errors and coverage before relying on a comparison.

## Data handling and local operation

DriftApe v0.1 operates locally. It has no cloud backend, central server, remote scanning mode, database, telemetry upload, or publishing workflow.

Snapshots and reports can contain security-sensitive host metadata and configuration details. Store and share generated files according to your own security policy. DriftApe does not automatically redact local outputs.

## Synthetic examples

The [`examples`](examples/) directory contains an entirely synthetic baseline → current → changes/findings flow:

- `examples/baseline.synthetic.json`
- `examples/current.synthetic.json`
- `examples/changes.synthetic.json`

See `examples/README.md` for the scenario and synthetic-data guarantees. The examples are demonstrations of the accepted v0.1 contracts, not evidence from a real host.

## Development and CI

Install development tools and run the local quality gates:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q tests/unit
python -m pytest -q
python -m compileall -q driftape tests
python -m driftape --version
driftape --version
python -m pip check
ruff check .
ruff format --check .
mypy driftape
```

GitHub Actions runs the quality job on Windows for Python 3.12 and 3.13 with read-only repository contents permission. Hosted CI is a regression and release-sanity check; it is not a substitute for the real Windows 11 workstation integration gate used for the accepted v0.1 baseline.

## Security policy

See [`SECURITY.md`](SECURITY.md) for supported-version and vulnerability-reporting guidance. Ordinary DriftApe findings or generated reports are not automatically software vulnerabilities in DriftApe itself.

## Non-goals and deferred scope

The frozen v0.1 release does not include HTML reporting, digital signatures, remote operation, Windows Server certification, event-log collection, Sysmon, ETW, YARA, vulnerability scanning, remediation, continuous monitoring, a background service, a database, a central server, a web UI, a cloud backend, plugins, machine learning, or LLM features.

These exclusions are intentional for v0.1 and should not be inferred as promised future features.

## License

DriftApe is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
