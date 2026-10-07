# Synthetic DriftApe v0.1 examples

Everything in this directory is synthetic test/demo material. It does not describe a real host, user, organization, domain, IP address, MachineGuid, filesystem deployment, or production finding.

The identifiers deliberately use `SYNTH`, `LAB`, and `EXAMPLE` markers. The machine fingerprint is a made-up SHA-256-shaped value used only to demonstrate the snapshot contract. Paths such as `C:\SyntheticDriftApeLab\...` are fictional lab paths and are not copied from a real system.

The three JSON files show one small complete v0.1 flow:

1. `baseline.synthetic.json` — a complete synthetic baseline snapshot.
2. `current.synthetic.json` — the same synthetic host after three deliberate lab changes: a local administrator is added, a service command path changes, and a Defender exclusion is added.
3. `changes.synthetic.json` — the coverage-complete diff and corresponding security interpretation findings generated from those two snapshots.

The JSON files use the accepted `driftape.snapshot.v1` and `driftape.changes.v1` contracts. They are examples only; do not use the synthetic baseline as a trust anchor for any real machine.
