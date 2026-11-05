# DriftApe

DriftApe is a local, defensive, CLI-first Windows security configuration and state drift utility. It reads Windows configuration without modifying that configuration; it **does** write local snapshot, manifest, JSON and HTML output files when requested.

**Development status:** the source in this repository is `0.2.0.dev0`, a development/pre-release version. A public `v0.2.0` release is **not** asserted. The frozen `v0.1` scope described below is historical; this development build also supports rendering a locally stored JSON change report as an offline HTML document using `driftape report`.

DriftApe is **not** an EDR, antivirus, malware scanner, pentesting framework, or remediation tool. It does not claim to detect malware or compromise.

## Windows inspection scope (inherited from v0.1)

The frozen v0.1 baseline covers these local Windows data domains:

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

The current `0.2.0.dev0` build additionally exposes the `report` CLI command for offline HTML rendering of a stored JSON change report. This is a **local report conversion**, not an HTML collection mode or a browser/web service.

## Requirements

- **Live collection (`baseline`, `scan`):** Windows x64 (AMD64), 64-bit Python 3.12 or 3.13.
- **Stored-data processing (`diff`, `report`):** Python 3.12 or 3.13; these operations work from existing local files without performing Windows collection. The offline `report` path can be run on non-Windows hosts.

The collection commands intentionally enforce the Windows x64 runtime. The package has no runtime dependencies outside the Python standard library.

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

Compare the current snapshot with the baseline, then render its stored JSON change report as HTML:

```powershell
driftape diff baseline.json current.json
driftape report changes.json
```

A successful baseline command writes both `baseline.json` and its adjacent `baseline.manifest.json`. The diff command verifies that baseline pair before comparison. The `report` command consumes a **stored** JSON change report and does not collect the host again. When the diff finds changes, exit code `1` means differences were found, not a failed comparison.

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

### `driftape report`

Validates an existing local JSON change report against the supported report schema, renders it into a standalone offline HTML document and writes that HTML locally. It neither re-runs collection nor contacts a server. The `CHANGES` argument is a **stored JSON change report** (not a current snapshot). The source JSON remains unchanged.

```powershell
driftape report CHANGES [--output PATH] [--force]
```

For a wholly synthetic, cross-platform demonstration, run from the repository root:

```powershell
driftape report examples/changes.synthetic.json --output synthetic-report.html
```

The sample's `driftape.changes.v1` schema identifier and its v0.1 scenario describe the **data format/example**, not the currently installed software version (`0.2.0.dev0`). Existing HTML paths are not overwritten without `--force`; an output path aliasing the JSON input is refused even with `--force`.

## Default output files

| Command | Default output |
| --- | --- |
| `baseline` | `baseline.json` and `baseline.manifest.json` |
| `scan` | `current.json` |
| `diff` | `changes.json` |
| `report` | `changes.html` |

A custom baseline name derives a same-directory manifest name from that baseline path. For example, `--output gold.json` produces `gold.json` and `gold.manifest.json`.

## Overwrite and `--force`

DriftApe refuses to overwrite an existing target by default. For `baseline`, this preflight applies to both the baseline and its manifest before collection begins. For `scan`, `diff`, and `report`, it applies to the requested output file. The report command also protects its input from output-path aliases (including existing hard links and symlinks), even with `--force`.

Use `--force` only when replacing the existing target is intentional:

```powershell
driftape scan --output current.json --force
```

## Exit codes

The current CLI uses the following exit codes (`report` uses `0`, `3`, `5` and `6` for its documented outcomes):

| Code | Meaning |
| ---: | --- |
| `0` | Successful complete collection, complete diff with no changes, or successful offline HTML report conversion |
| `1` | Complete diff succeeded and changes were found |
| `2` | Collection or comparison completed with partial coverage |
| `3` | Operational, I/O, output, serialization, or internal orchestration failure |
| `4` | Baseline SHA-256 integrity verification failed |
| `5` | Unsupported or mismatched snapshot or stored change-report schema |
| `6` | Invalid baseline manifest/snapshot, current snapshot, diff input, or stored JSON change report |
| `7` | Baseline and current snapshots identify different hosts |
| `8` | Unsupported collection platform/runtime |

## Partial and incomplete collection

A snapshot records collector status, coverage, collector errors, and snapshot-level completeness. A collector may be `success`, `partial`, or `failed`. Missing coverage is represented explicitly; DriftApe does not treat unavailable data as an empty successful result.

When either snapshot lacks coverage for a comparison domain, that domain is skipped. The change report records `compared_domains` and `skipped_domains`, the overall comparison becomes `partial`, and the CLI returns exit code `2`. This keeps the report truthful about what was and was not compared.

## Baseline integrity model

The baseline command serializes the baseline canonically and writes an adjacent manifest containing a SHA-256 digest of the exact baseline bytes. Before a diff, DriftApe validates the manifest and baseline, verifies canonical encoding, and compares the recorded digest with the actual baseline bytes.

This detects accidental or unauthorized modification when the manifest remains trustworthy. **SHA-256 does not authenticate the baseline against an attacker who can alter both the baseline and its manifest.** The current `0.2.0.dev0` build likewise does not provide digital signatures, remote attestation, or another external trust anchor.

## Privileges and read-only behavior

DriftApe is designed to inspect local state without changing Windows configuration. It does not deliberately request elevation, remediate findings, alter Defender settings, change users or group memberships, modify services or tasks, or install a background service.

The process privileges determine what Windows can be collected. Running without administrative access can therefore produce partial results. Review collector errors and coverage before relying on a comparison.

## Data handling and local operation

DriftApe processes data locally. It has no cloud backend, central server, remote scanning mode, database, telemetry upload, or publishing workflow. Offline HTML reporting does not require access to the original Windows host.

Snapshots, manifests, JSON change reports and HTML reports are **written to local files** and can contain sensitive host metadata, paths, account/group names, configuration values and security findings. Treat them as sensitive evidence: restrict access, retention and sharing according to your organization's policy. DriftApe does **not** automatically redact, encrypt or digitally sign these outputs; report rendering is not a substitute for reviewing sensitive contents before distribution.

## Synthetic examples

The [`examples`](examples/) directory contains an entirely synthetic baseline → current → changes/findings flow:

- `examples/baseline.synthetic.json`
- `examples/current.synthetic.json`
- `examples/changes.synthetic.json`

See `examples/README.md` for the scenario and synthetic-data guarantees. The examples demonstrate the inherited v0.1 schema contracts and are not evidence from a real host or a statement of the current application version. They can also be used as offline HTML-rendering input without collecting anything from Windows.

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

The historical frozen `v0.1` release did **not** have HTML reporting. The `0.2.0.dev0` development build **does** provide local, offline HTML rendering from a saved JSON change report via `driftape report`; it does not provide a web UI, live HTML collection, or an online reporting service.

The development build does not claim digital signatures, remote operation, Windows Server certification, event-log collection, Sysmon, ETW, YARA, vulnerability scanning, remediation, continuous monitoring, a background service, a database, a central server, a web UI, a cloud backend, plugins, machine learning or LLM features. These are not promises of future delivery.

## License

DriftApe is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).

Copyright 2026 Hanselaffe.
