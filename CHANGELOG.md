# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffold: LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, GOVERNANCE.md
- CI: lint, test, DCO check, CodeQL, OpenSSF Scorecard
- Cargo workspace: ykdf-core, ykdf-yubikey, apps/cli
- Tooling: cargo-deny, gitleaks, typos
- `ykdf-core`: extract-then-expand key derivation with three runtime-selectable pipelines (`hkdf-sha512`, `hkdf-sha3-512`, `shake256`) producing a 512-bit master key
- `ykdf-core`: self-describing context strings (`ykdf:v1:<pipeline>:<profile>:<purpose>:<index>`) with output length bound into the expand input
- `ykdf-core`: key profiles for x25519, ed25519, age-x25519, symmetric, ml-kem-512/768/1024, and raw, with per-profile pipeline acceptance policy
- `ykdf-core`: zeroizing key-material types and fallible IKM construction with a minimum-entropy guard
