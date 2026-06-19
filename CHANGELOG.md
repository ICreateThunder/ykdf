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
- `ykdf-core`: cascaded extract (TLS 1.3 pattern) for multi-factor entropy combining hardware and passphrase
- `ykdf-core`: Argon2id passphrase stretching behind `argon2` feature flag, tuned for offline derivation (m=128 MiB, t=3, p=1) with stateless fixed-salt default
- `ykdf-core`: `cascade_passphrase()` binds a canonical stretch descriptor (`argon2id:m,t,p`) into the derivation, making passphrase derivations self-describing and domain-separating future stretch algorithms additively
- `ykdf-core`: `derive_raw()` for variable-length raw output
- `ykdf-core`: direct HMAC-based expand (RFC 5869 S2.3), dropping the `hkdf` crate dependency
- `ykdf-core`: sponge domain separation tags (0x01 extract, 0x02 cascade)
- `ykdf-yubikey`: PIV ECDH transport via self-ECDH on slot 9d (reads own public key from certificate)
- `ykdf-yubikey`: HMAC-SHA1 challenge-response on OTP slot 2 for layered mode
- `ykdf-yubikey`: provisioning module for on-device PIV slot 9d key generation and OTP slot 2 HMAC programming
- CLI: `ykdf init` command to provision a YubiKey (on-device slot 9d key + carrier cert, optional `--layered` HMAC slot 2), with an overwrite guard and a non-backup warning
- CLI: `ykdf init --exportable` (host-generated slot 9d key, displayed once) and `--import <hex>` to provision a backup device with the same key, using the OS CSPRNG for key generation
- CLI: `ykdf init --mgmt-key protected|derived` to authenticate with a PIN-protected or PIN-derived PIV management key stored on the device (in addition to an explicit hex key or the factory default)
- CLI: `ykdf derive` command with all eight profiles, pipeline override, key rotation, passphrase cascading
- CLI: `ykdf pubkey` command for x25519, ed25519, age, and ML-KEM public key extraction
- CLI: output formats: base64 (WireGuard), OpenSSH PEM, age bech32 identity, hex, binary
- CLI: `--ikm-file` flag for testing without YubiKey hardware
- CLI: `--layered` flag for PIV + HMAC combined entropy
- CLI: `--passphrase` flag for Argon2id-stretched additional factor

### Changed

- `ykdf-core`: `Argon2Params` cost fields (`m_cost`, `t_cost`, `p_cost`) are now private, fixing the cost at the hardened tier (m=128 MiB, t=3, p=1). The only constructors are `Default` and `with_salt`, so integrators can no longer set sub-floor costs or break cross-device determinism by varying them (#21)
