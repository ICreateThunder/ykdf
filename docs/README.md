# YKDF documentation

Start at the top-level [README](../README.md) for the overview and quick start.

## Guides

- [design.md](design.md) - how and why YKDF works: problem, architecture,
  entropy sources, key derivation, security properties.
- [usage.md](usage.md) - the `ykdf` CLI: deriving keys, formats, transports.
- [provisioning.md](provisioning.md) - preparing a YubiKey, Linux permissions,
  gpg coexistence, and two-key backup.
- [verifying-releases.md](verifying-releases.md) - checking release signatures
  and provenance.

## Reference

- [SPEC.md](SPEC.md) - the byte-level v1 derivation format (canonical), with
  golden vectors in [vectors/v1.json](../vectors/v1.json).
- [signatures.md](signatures.md) - the `ykdf sign` / `verify` formats: ed25519
  SSHSIG and the frozen `ykdf-sig:v1` ML-DSA container.
- [references/](../references/README.md) - independent reimplementations of the
  format (Go and C in tree) that must reproduce every golden vector.
- [transport-notes.md](transport-notes.md) - hardware-verified desktop transport
  details (PC/SC, hidraw, scdaemon passthrough).
- [hardware-acceptance.md](hardware-acceptance.md) - bench procedure for the
  two-device shared-backup and slot-2 write-path tests (uses
  `scripts/hw-acceptance.sh`).
- [assurance-case.md](assurance-case.md) - the security assurance argument and
  its evidence.
- [android-spike.md](android-spike.md) - the Android NFC transport feasibility
  work.
- [ideas.md](ideas.md) - deferred ideas, experiments, and open design questions.

## Project

- [SECURITY.md](../SECURITY.md) - reporting policy, threat model, crypto notes.
- [CONTRIBUTING.md](../CONTRIBUTING.md) - dev setup, signing, PR process.
- [ROADMAP.md](../ROADMAP.md) - phases and what's in/out of scope.
- [GOVERNANCE.md](../GOVERNANCE.md) - roles, decisions, transition plan.
- [CHANGELOG.md](../CHANGELOG.md) - release history.
