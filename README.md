# YKDF - YubiKey Key Derivation Framework

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ICreateThunder/ykdf/badge)](https://scorecard.dev/viewer/?uri=github.com/ICreateThunder/ykdf)

A minimal, extensible framework for deterministically deriving cryptographic keys from a hardware root of trust (YubiKey 5 series). Supports WireGuard, Ed25519, ML-KEM (post-quantum), age identities, and arbitrary future key types.

**Status:** Design phase

## Problem

Modern systems require keys across many different cryptographic schemes - WireGuard (Curve25519), SSH/Git signing (Ed25519), post-quantum encryption (ML-KEM), file encryption (age/ChaCha20), and more. Managing these independently is fragile: keys get lost, backups diverge, and there's no unified trust anchor.

YubiKey hardware can protect secrets, but doesn't natively support many of these algorithms (no Curve25519, no ML-KEM). We need a software layer that bridges hardware-bound entropy to arbitrary key types.

## Approach

Derive all keys deterministically from hardware-bound secrets on a YubiKey. The derivation is structured as a three-layer pipeline:

```
Layer 1: Entropy Extraction (hardware)
    YubiKey PIV ECDH + optional HMAC-SHA1 → raw input key material

Layer 2: Master Key Derivation (extract)
    HKDF-Extract(salt, IKM) → 256-bit master key

Layer 3: Domain-Specific Expansion (expand)
    KDF(master_key, context_string) → raw bytes → key-type post-processing
```

Keys are never stored - they are re-derived on demand from the YubiKey and exist in memory only during use.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        YubiKey 5C                           │
│                                                             │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│   │  PIV Applet  │    │  OTP Applet  │    │ FIDO2 Applet │  │
│   │  P-256 ECDH  │    │  HMAC-SHA1   │    │  (unused)    │  │
│   │  PIN + Touch │    │  Touch only  │    │              │  │
│   └──────┬───────┘    └──────┬───────┘    └──────────────┘  │
│          │ 32 bytes          │ 20 bytes                     │
└──────────┼───────────────────┼──────────────────────────────┘
           │                   │
           ▼                   ▼
    ┌─────────────────────────────────┐
    │  IKM = ecdh_out ‖ hmac_out      │   Layered mode (52 bytes)
    │     or ecdh_out alone           │   Standard mode (32 bytes)
    └───────────────┬─────────────────┘
                    ▼
    ┌─────────────────────────────────┐
    │  HKDF-Extract(                  │
    │    salt = "ykdf-v1",            │
    │    ikm  = IKM                   │
    │  ) → 256-bit master_key         │
    └───────────────┬─────────────────┘
                    │
      ┌─────────────┼─────────────┬──────────────┐
      ▼             ▼             ▼              ▼
 ┌─────────┐  ┌──────────┐ ┌──────────┐   ┌──────────┐
 │ x25519  │  │ ed25519  │ │ mlkem768 │   │  raw     │
 │ Profile │  │ Profile  │ │ Profile  │   │ Profile  │
 └─────────┘  └──────────┘ └──────────┘   └──────────┘
```

### Why Not FIDO2?

FIDO2 credentials are bound to the individual authenticator by design - they cannot be cloned. Two YubiKeys would produce different outputs for the same input, breaking deterministic derivation across backup keys. PIV and HMAC secrets can be imported identically to both keys.

### Applet Isolation

YubiKey 5 runs each applet in a separate security domain. Applets cannot read each other's key material. The layered mode (PIV + HMAC) provides genuine defense in depth - compromising one applet doesn't expose the other's secrets.

## Entropy Sources

| Source | Applet | Output | Access Control | Cloneable |
|--------|--------|--------|----------------|-----------|
| **PIV ECDH** (primary) | PIV slot 9d | 32 bytes | PIN + touch | Yes (import same P-256 key) |
| **HMAC-SHA1** (optional layer) | OTP slot 2 | 20 bytes | Touch only | Yes (program same secret) |
| **Passphrase** (optional 2nd factor) | N/A | Argon2id output | Knowledge | N/A |

### Security Modes

| Mode | Entropy Sources | Access Required |
|------|----------------|-----------------|
| **Standard** | PIV ECDH | PIN + touch + YubiKey |
| **Layered** | PIV ECDH + HMAC-SHA1 | PIN + touch + YubiKey (two applets) |
| **Hardened** | PIV ECDH + HMAC-SHA1 + passphrase | PIN + touch + YubiKey + passphrase |
| **Simple** | HMAC-SHA1 only | Touch + YubiKey |

## Key Derivation

### Domain Separation

Every derived key uses a unique context string that ensures cryptographic independence:

```
ykdf:v1:<kdf>:<profile>:<purpose>:<index>
```

Examples:
```
ykdf:v1:hkdf-sha512:x25519:wg-home:0
ykdf:v1:shake256:mlkem768:email:0
ykdf:v1:blake3:ed25519:git-signing:0
ykdf:v1:hkdf-sha256:symmetric:disk-encryption:0
```

The `index` field enables key rotation - bump the index, re-share the new public key.

### KDF Algorithms

The framework is KDF-agile. The context string names the KDF, so derivations are never ambiguous.

| KDF | Use Case | Rationale |
|-----|----------|-----------|
| **HKDF-SHA256/512** | Default for fixed-length keys (WG, Ed25519, age) | RFC 5869, battle-tested, constant-time |
| **SHAKE128/256** | Variable-length and post-quantum keys (ML-KEM) | Native XOF, no counter mode needed. ML-KEM uses SHA3 internally |
| **BLAKE3 KDF** | Symmetric keys, bulk derivation | Fast, built-in domain separation, variable output |
| **Argon2id** | Passphrase hardening layer | Memory-hard, resists offline brute-force |

> **Note:** The HKDF design - specifically how Extract and Expand interact, salt handling, and whether to support algorithm negotiation - is under active discussion and will be refined before implementation.

### Key Profiles

Each profile defines output length, preferred KDF, and any post-processing:

| Profile | KDF | Output | Post-Processing |
|---------|-----|--------|-----------------|
| `x25519` | HKDF-SHA256 | 32 bytes | Curve25519 clamping |
| `ed25519` | HKDF-SHA256 | 32 bytes | Used as seed for keypair generation |
| `mlkem512` | SHAKE256 | 64 bytes | Split into `(d, z)` for `KeyGen(d, z)` |
| `mlkem768` | SHAKE256 | 64 bytes | Split into `(d, z)` for `KeyGen(d, z)` |
| `mlkem1024` | SHAKE256 | 64 bytes | Split into `(d, z)` for `KeyGen(d, z)` |
| `age-x25519` | HKDF-SHA256 | 32 bytes | Bech32 encoding as age identity |
| `symmetric` | BLAKE3 KDF | 32 bytes | Direct use (AES-256, ChaCha20, etc.) |
| `raw` | Configurable | Configurable | None - caller decides |

## Platform Support

Must work on Linux and Android (via USB-C). Both platforms have mature YubiKey libraries.

### Implementation

Core library in Rust, cross-compiling to both targets:

```
ykdf/
├── ykdf-core/              # Platform-independent derivation logic
│   ├── extract.rs          # IKM collection → master key
│   ├── expand.rs           # Master key + context → derived bytes
│   ├── context.rs          # Context string parsing and validation
│   ├── kdf/
│   │   ├── hkdf.rs
│   │   ├── shake.rs
│   │   ├── blake3.rs
│   │   └── argon2.rs
│   └── profile/
│       ├── x25519.rs
│       ├── ed25519.rs
│       ├── mlkem.rs
│       ├── age.rs
│       ├── symmetric.rs
│       └── raw.rs
│
├── ykdf-cli/               # Linux command-line tool
│
├── ykdf-yubikey/           # YubiKey interaction layer
│   ├── piv.rs              # PIV ECDH operations
│   └── hmac.rs             # OTP HMAC challenge-response
│
└── ykdf-android/           # Android JNI/NDK bindings
```

### CLI Usage

```bash
# Derive a WireGuard private key (ephemeral - never hits disk)
ykdf derive --profile x25519 --purpose wg-home
# Enter PIV PIN, touch YubiKey → prints base64 private key

# Derive and configure WireGuard directly
wg set wg0 private-key <(ykdf derive --profile x25519 --purpose wg-home)

# Derive Ed25519 for SSH
ykdf derive --profile ed25519 --purpose ssh-github --format openssh

# Derive ML-KEM-768 keypair
ykdf derive --profile mlkem768 --purpose secure-email --format pem

# Derive a raw symmetric key
ykdf derive --profile symmetric --kdf blake3 --purpose backup-encryption

# Key rotation - bump index, re-share public key
ykdf derive --profile x25519 --purpose wg-home --index 1

# Layered mode (PIV + HMAC)
ykdf derive --profile ed25519 --purpose high-value --layered

# Add passphrase as additional factor
ykdf derive --profile ed25519 --purpose high-value --passphrase

# Show public key only
ykdf pubkey --profile x25519 --purpose wg-home
```

## Backup & Setup

Both YubiKeys are programmed with identical secrets at setup time:

```bash
# Generate and import P-256 key to both YubiKeys (PIV slot 9d)
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/piv.pem
openssl req -new -x509 -key /tmp/piv.pem -out /tmp/piv-cert.pem \
  -days 36500 -subj "/CN=ykdf"

ykman -d <serial_1> piv keys import --touch-policy always 9d /tmp/piv.pem
ykman -d <serial_1> piv certificates import 9d /tmp/piv-cert.pem
ykman -d <serial_2> piv keys import --touch-policy always 9d /tmp/piv.pem
ykman -d <serial_2> piv certificates import 9d /tmp/piv-cert.pem

# Program identical HMAC secret to both (OTP slot 2)
HMAC_SECRET=$(openssl rand -hex 20)
ykman -d <serial_1> otp chalresp --touch 2 "$HMAC_SECRET"
ykman -d <serial_2> otp chalresp --touch 2 "$HMAC_SECRET"

# Destroy originals
shred -u /tmp/piv.pem /tmp/piv-cert.pem
unset HMAC_SECRET
```

After setup, both YubiKeys produce identical derivations. Lose one, the other is a full backup.

## Security Properties

- **Hardware-bound:** Master entropy requires physical YubiKey
- **PIN-protected:** PIV requires PIN (3 attempts before PUK lockout)
- **Touch-required:** Physical presence confirmation per derivation
- **Deterministic:** Same inputs produce same keys - no state to sync
- **Domain-separated:** Mathematically independent outputs per context string
- **No key storage:** Keys exist in memory only during use
- **Forward-compatible:** New profiles and KDFs added without breaking existing derivations
- **Backup-friendly:** Two YubiKeys with identical secrets

## Open Design Questions

- **HKDF specifics:** Extract/Expand separation, salt handling, algorithm negotiation - needs further discussion
- **ML-KEM seed interface:** FIPS 203 `KeyGen` takes `(d, z)` internally but some libraries only expose RNG-based APIs; may need to target `KeyGen_internal` paths
- **Manifest file:** Fully stateless (context strings documented externally) vs. a local manifest listing derived keys for usability
- **Peer public key management:** How/where to store the fixed P-256 point used for PIV ECDH derivation

## Comparison with Existing Tools

| Tool | Root of Trust | Key Types | Extensible | PQ-Ready | Hardware-Bound |
|------|--------------|-----------|------------|----------|----------------|
| age | Passphrase / file | X25519 | Via plugins | No | No |
| SOPS | age / PGP / KMS | Wraps backends | Via backends | Inherited | Via KMS |
| BIP-32 / SLIP-10 | Seed phrase | secp256k1 / ed25519 | Fixed | No | Optional (HW wallets) |
| libsodium KDF | Software key | Raw bytes | Yes | No | No |
| PIV / PKCS#11 | Hardware | RSA / ECC only | No | No | Yes |
| **YKDF** | YubiKey HMAC + PIV | Any (via profiles) | Yes | Yes (ML-KEM) | Yes |

## License

GPLv3. See [LICENSE](LICENSE).
