# Security Policy

## Supported versions

DriftApe v0.1 is the currently supported release line for security reports.

## Reporting a software vulnerability

If the repository hosting service provides private vulnerability reporting, prefer that private channel for suspected security vulnerabilities in DriftApe. Do not place secrets, credentials, private keys, sensitive host data, or unredacted production snapshots/reports in a public issue.

Provide enough reproducible technical detail to let maintainers understand and verify the issue where practical, including the affected DriftApe version, operating-system and Python context, relevant command or code path, expected behavior, observed behavior, and a minimal reproduction that does not expose sensitive data.

This policy does not publish or imply a dedicated security email address, response-time SLA, or bug-bounty program.

## DriftApe findings are not automatically DriftApe vulnerabilities

A DriftApe change or security interpretation finding describes observed drift in the local data that DriftApe compares. Such output can be important to investigate, but it is distinct from a vulnerability in the DriftApe software itself.

Report a DriftApe software vulnerability when the issue concerns DriftApe's own security behavior, trust boundaries, parsing, validation, integrity handling, local file handling, dependency/build behavior, or another defect in the software rather than an ordinary finding about the inspected Windows host.
