# YKDF - YubiKey Key Derivation Framework

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ICreateThunder/ykdf/badge)](https://scorecard.dev/viewer/?uri=github.com/ICreateThunder/ykdf)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13313/badge)](https://www.bestpractices.dev/projects/13313)
[![dependency status](https://deps.rs/repo/github/ICreateThunder/ykdf/status.svg)](https://deps.rs/repo/github/ICreateThunder/ykdf)

A minimal, extensible framework for deterministically deriving cryptographic keys
from a hardware root of trust (YubiKey 5 series). Supports WireGuard, Ed25519,
ML-KEM and ML-DSA (post-quantum), age identities, and arbitrary future key types.

Keys are never stored - each is re-derived on demand from the YubiKey (PIV ECDH,
optionally layered with an HMAC-SHA1 factor) through a specified extract-then-expand
pipeline, and exists in memory only during use. Two YubiKeys carrying the same
secrets produce identical keys, so backups are exact. See [docs/design.md](docs/design.md)
for how and why it works.

**Status:** core library, YubiKey transport, Linux CLI, and an Android NFC app -
all implemented. Released through 0.2.0.

**Specification:** the byte-level v1 derivation format is defined in
[docs/SPEC.md](docs/SPEC.md), with language-neutral golden test vectors in
[vectors/v1.json](vectors/v1.json) (the cross-platform conformance suite).

## Quick start

```bash
# Provision a YubiKey: generate the slot 9d key on-device, write its carrier cert.
# Add --layered to also program the HMAC-SHA1 factor on OTP slot 2.
ykdf init

# Derive a WireGuard private key (ephemeral - never hits disk).
ykdf derive --profile x25519 --purpose wg-home
# Enter PIV PIN, touch the YubiKey → prints the base64 private key.

# Show the matching public key.
ykdf pubkey --profile x25519 --purpose wg-home

# Or assemble a ready-to-use WireGuard config (the key stays derived, never stored).
ykdf wg config --purpose wg-home --address 10.0.0.2/24 \
  --peer-pubkey <server-pubkey> --endpoint vpn.example.com:51820 --allowed-ips 0.0.0.0/0
```

More commands in [docs/usage.md](docs/usage.md); YubiKey setup, Linux permissions,
gpg coexistence, and two-key backup in [docs/provisioning.md](docs/provisioning.md).

## Security and quality

- **Released:** through 0.2.0, with GPG-signed tags and keyless
  [cosign](https://www.sigstore.dev/) signatures plus SLSA provenance on every
  artifact. See [docs/verifying-releases.md](docs/verifying-releases.md).
- **OpenSSF Best Practices:** Passing and Silver badges earned (see badges above).
- **Frozen, specified format:** byte-level [SPEC](docs/SPEC.md) plus golden
  vectors, cross-checked against the independent `hkdf` crate.
- **Tested:** ~96% region coverage, property tests for the security-critical
  length-binding invariant, fuzzing
  ([cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)), and Miri
  (undefined-behaviour) checks in CI.
- **Side-channel measured:** a [dudect](https://github.com/oreparaz/dudect) timing
  rig shows no measurable secret-dependent timing in extract/derive.
- **Memory-safe:** `unsafe` forbidden workspace-wide.
- **Assurance case:** the security argument and its evidence are written up in
  [docs/assurance-case.md](docs/assurance-case.md).

## Documentation

| Guide | What it covers |
|-------|----------------|
| [docs/design.md](docs/design.md) | How and why YKDF works: problem, architecture, entropy, key derivation, security properties |
| [docs/usage.md](docs/usage.md) | The `ykdf` CLI: deriving keys, formats, transports |
| [docs/provisioning.md](docs/provisioning.md) | Preparing a YubiKey, Linux permissions, gpg coexistence, two-key backup |
| [docs/verifying-releases.md](docs/verifying-releases.md) | Checking release signatures and provenance |
| [docs/SPEC.md](docs/SPEC.md) | The byte-level v1 derivation format (canonical) |
| [docs/transport-notes.md](docs/transport-notes.md) | Hardware-verified desktop transport details |
| [docs/](docs/) | Index of all documentation |

## Comparison with existing tools

| Tool | Root of Trust | Key Types | Extensible | PQ-Ready | Hardware-Bound |
|------|--------------|-----------|------------|----------|----------------|
| age | Passphrase / file | X25519 | Via plugins | No | No |
| SOPS | age / PGP / KMS | Wraps backends | Via backends | Inherited | Via KMS |
| BIP-32 / SLIP-10 | Seed phrase | secp256k1 / ed25519 | Fixed | No | Optional (HW wallets) |
| libsodium KDF | Software key | Raw bytes | Yes | No | No |
| PIV / PKCS#11 | Hardware | RSA / ECC only | No | No | Yes |
| **YKDF** | YubiKey HMAC + PIV | Any (via profiles) | Yes | Yes (ML-KEM, ML-DSA) | Yes |

## Contributing and security

Contributions go through signed commits and the
[Conventional Commits](https://www.conventionalcommits.org/) PR flow described in
[CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see
[SECURITY.md](SECURITY.md). Planned work is in [ROADMAP.md](ROADMAP.md).

## License

GPLv3. See [LICENSE](LICENSE).
