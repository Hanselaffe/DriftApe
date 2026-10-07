# DriftApe v0.1.0

Initial public release of DriftApe.

DriftApe is a local, defensive, read-only, CLI-first Windows security configuration and state drift
utility. It records a local baseline, collects a later snapshot, verifies baseline integrity,
compares covered security-relevant state, and produces deterministic change findings and reports.

## Included in v0.1.0

- Local users and local Administrators membership
- Windows services
- Scheduled Tasks
- Microsoft Defender exclusions
- Defender `DisableRealtimeMonitoring`
- Defender `RealTimeProtectionEnabled`
- Versioned baseline/current snapshots
- SHA-256 baseline integrity verification
- Coverage-aware diffing across seven logical domains
- Security interpretation findings
- JSON change reports
- Terminal summaries
- `baseline`, `scan`, and `diff` CLI commands
- Synthetic public examples
- Windows CI for Python 3.12 and 3.13

## Requirements

- Windows x64
- 64-bit Python 3.12 or 3.13
- No runtime dependencies outside the Python standard library

## Validation

The accepted v0.1 release completed:

```text
Windows integration: 9/9 PASS
Unit regression:     807/807 PASS
Windows full suite:  816/816 PASS
Skipped tests:       0
Runtime dependencies: []
```

The public-release hardening regression also completed with 807/807 unit tests passing and the
expected Windows-only integration skips on a non-Windows verification runtime.

## Important scope boundaries

DriftApe v0.1.0 is **not**:

- an EDR
- an antivirus product
- a malware scanner
- a pentesting framework
- a remediation tool

It does not provide remote operation, continuous monitoring, a background service, a web UI, cloud
backend, vulnerability scanning, YARA, event-log/Sysmon/ETW collection, or Windows Server
certification.

## Baseline integrity note

DriftApe verifies baseline bytes against an adjacent SHA-256 manifest. This detects modification
when the manifest remains trustworthy, but it does not authenticate the baseline against an attacker
who can alter both files.

## License

Apache License 2.0.
