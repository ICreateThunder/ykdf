# YKDF - YubiKey Key Derivation Framework

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ICreateThunder/ykdf/badge)](https://scorecard.dev/viewer/?uri=github.com/ICreateThunder/ykdf)

A minimal, extensible framework for deterministically deriving cryptographic keys from a hardware root of trust (YubiKey 5 series). Supports WireGuard, Ed25519, ML-KEM (post-quantum), age identities, and arbitrary future key types.

**Status:** Core library, YubiKey transport, and Linux CLI implemented

## Problem

Modern systems require keys across many different cryptographic schemes - WireGuard (Curve25519), SSH/Git signing (Ed25519), post-quantum encryption (ML-KEM), file encryption (age/ChaCha20), and more. Managing these independently is fragile: keys get lost, backups diverge, and there's no unified trust anchor.

YubiKey hardware can protect secrets, but doesn't natively support many of these algorithms (no Curve25519, no ML-KEM). We need a software layer that bridges hardware-bound entropy to arbitrary key types.

## Approach

Derive all keys deterministically from hardware-bound secrets on a YubiKey. The derivation is structured as a three-layer pipeline:

```
Layer 1: Entropy Extraction (hardware)
    YubiKey PIV ECDH + optional HMAC-SHA1 → raw input key material

Layer 2: Master Key Derivation (extract)
    HKDF-Extract(salt, IKM) → 512-bit master key

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
    │  ) → 512-bit master_key         │
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
ykdf:v1:<pipeline>:<profile>:<purpose>:<index>
```

Examples:
```
ykdf:v1:hkdf-sha512:x25519:wg-home:0
ykdf:v1:hkdf-sha3-512:ed25519:git-signing:0
ykdf:v1:shake256:mlkem768:email:0
ykdf:v1:hkdf-sha512:symmetric:disk-encryption:0
```

The `index` field enables key rotation - bump the index, re-share the new public key.

### Pipelines

The framework is pipeline-agile. A pipeline names the extract-then-expand primitives, and the context string records which pipeline produced a key, so derivations are never ambiguous. All pipelines are compiled in and selected at runtime; changing the pipeline changes every derived key.

| Pipeline (label) | Extract | Expand | Use Case |
|------------------|---------|--------|----------|
| `hkdf-sha512` | HKDF-Extract-SHA512 | HKDF-Expand-SHA512 | Default for fixed-length keys (WG, Ed25519, age). RFC 5869, constant-time |
| `hkdf-sha3-512` | HKDF-Extract-SHA3-512 | HKDF-Expand-SHA3-512 | Same construction with Keccak-family hash diversity |
| `shake256` | SHAKE256(salt ‖ IKM) | SHAKE256(master ‖ context) | Variable-length and post-quantum keys (ML-KEM). Native XOF, no counter mode |

Each pipeline produces a 512-bit master key. The requested output length is bound into the expand input so that different lengths under the same context yield independent key streams.

### Key Profiles

Each profile defines output length, a default pipeline, the pipelines it accepts, and any post-processing:

| Profile | Default Pipeline | Accepts | Output | Post-Processing |
|---------|------------------|---------|--------|-----------------|
| `x25519` | `hkdf-sha512` | either HKDF variant | 32 bytes | Curve25519 clamping |
| `ed25519` | `hkdf-sha512` | either HKDF variant | 32 bytes | Used as seed for keypair generation |
| `age-x25519` | `hkdf-sha512` | either HKDF variant | 32 bytes | Bech32 encoding as age identity |
| `symmetric` | `hkdf-sha512` | either HKDF variant | 32 bytes | Direct use (AES-256, ChaCha20, etc.) |
| `mlkem512` | `shake256` | `shake256` only | 64 bytes | Seed `(d, z)` for `KeyGen(d, z)` |
| `mlkem768` | `shake256` | `shake256` only | 64 bytes | Seed `(d, z)` for `KeyGen(d, z)` |
| `mlkem1024` | `shake256` | `shake256` only | 64 bytes | Seed `(d, z)` for `KeyGen(d, z)` |
| `raw` | `hkdf-sha512` | any pipeline | 32 bytes | None - caller decides |

## Platform Support

Must work on Linux and Android (via USB-C). Both platforms have mature YubiKey libraries.

### Implementation

Core library in Rust, cross-compiling to both targets:

```
ykdf/
├── crates/
│   ├── ykdf-core/              # Platform-independent derivation logic
│   │   └── src/
│   │       ├── types.rs        # Ikm, MasterKey, ExpandedBytes (zeroizing)
│   │       ├── error.rs        # Concrete Error enum
│   │       ├── pipeline.rs     # Pipeline enum + wire-format labels
│   │       ├── context.rs      # Context string parsing and validation
│   │       ├── extract/        # IKM → master key
│   │       │   ├── hkdf.rs     # HKDF-Extract-SHA512 / -SHA3-512
│   │       │   └── sponge.rs   # SHAKE256(salt ‖ IKM)
│   │       ├── expand/         # Master key + context → derived bytes
│   │       │   ├── hkdf.rs     # HKDF-Expand-SHA512 / -SHA3-512
│   │       │   └── sponge.rs   # SHAKE256(master ‖ context)
│   │       ├── profile/        # Per-key-type post-processing
│   │       │   ├── x25519.rs
│   │       │   ├── ed25519.rs
│   │       │   ├── mlkem.rs
│   │       │   ├── age.rs
│   │       │   ├── symmetric.rs
│   │       │   └── raw.rs
│   │       └── derive.rs       # extract() + derive() orchestration
│   │
│   └── ykdf-yubikey/           # YubiKey interaction layer
│       └── src/
│           ├── piv.rs          # PIV ECDH (slot 9d, self-ECDH via cert)
│           ├── hmac.rs         # HMAC-SHA1 challenge-response (OTP slot 2)
│           └── lib.rs          # derive_ikm() orchestration
│
└── apps/
    └── cli/                    # Linux command-line tool (ykdf)
        └── src/
            ├── cli.rs          # clap subcommands and argument types
            ├── derive.rs       # derive/pubkey orchestration
            ├── format.rs       # output formatting (base64, hex, OpenSSH, age)
            └── ikm.rs          # IKM source (YubiKey or --ikm-file)
```

### CLI Usage

```bash
# Provision a YubiKey first (generate the slot 9d key on-device, write its cert)
ykdf init
# ...or also program HMAC-SHA1 on OTP slot 2 for layered mode
ykdf init --layered

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
ykdf derive --profile symmetric --purpose backup-encryption

# Override the pipeline (any profile that accepts it)
ykdf derive --profile ed25519 --pipeline hkdf-sha3-512 --purpose git-signing

# Key rotation - bump index, re-share public key
ykdf derive --profile x25519 --purpose wg-home --index 1

# Layered mode (PIV + HMAC)
ykdf derive --profile ed25519 --purpose high-value --layered

# Add passphrase as additional factor
ykdf derive --profile ed25519 --purpose high-value --passphrase

# Show public key only
ykdf pubkey --profile x25519 --purpose wg-home
```

## How PIV ECDH Works

YKDF uses a self-ECDH approach: it reads the P-256 public key from the
certificate in PIV slot 9d and sends it back to the YubiKey as the ECDH
peer point. The YubiKey computes `ECDH(private_key, own_public_key)` and
returns a deterministic 32-byte shared secret. No config file or external
peer point storage is needed.

## Setup

### Single YubiKey (on-device generation)

```bash
# Provision slot 9d: generate the P-256 key on-device (private key never
# leaves the YubiKey) and write the carrier certificate the derive path reads.
ykdf init

# Or also program HMAC-SHA1 on OTP slot 2 for layered mode in one step:
ykdf init --layered
```

`ykdf init` refuses to overwrite an already-provisioned slot 9d unless given
`--force`. On-device generation is non-extractable, so the slot 9d key cannot
be backed up; if the device is lost, keys derived from the PIV factor are
unrecoverable. Back up the derived outputs you rely on, or use the two-YubiKey
backup setup below.

The equivalent manual steps with `ykman`:

```bash
# Generate P-256 key on-device (private key never leaves the YubiKey)
ykman piv keys generate --algorithm ECCP256 --touch-policy ALWAYS 9d /tmp/ykdf-pub.pem

# Create a self-signed certificate from the public key
ykman piv certificates generate --subject "CN=ykdf" 9d /tmp/ykdf-pub.pem

# Clean up (public key is now stored in the certificate on the YubiKey)
rm /tmp/ykdf-pub.pem
```

### Backup (two YubiKeys with identical secrets)

To use two YubiKeys as interchangeable backups, generate the key externally
and import to both:

```bash
# Generate and import P-256 key to both YubiKeys (PIV slot 9d)
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/piv.pem
openssl req -new -x509 -key /tmp/piv.pem -out /tmp/piv-cert.pem \
  -days 36500 -subj "/CN=ykdf"

ykman -d <serial_1> piv keys import --touch-policy always 9d /tmp/piv.pem
ykman -d <serial_1> piv certificates import 9d /tmp/piv-cert.pem
ykman -d <serial_2> piv keys import --touch-policy always 9d /tmp/piv.pem
ykman -d <serial_2> piv certificates import 9d /tmp/piv-cert.pem

# Program identical HMAC secret to both (OTP slot 2, for --layered mode)
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
- **Forward-compatible:** New profiles and pipelines added without breaking existing derivations
- **Backup-friendly:** Two YubiKeys with identical secrets

## Open Design Questions

- **Manifest file:** Fully stateless (context strings documented externally) vs. a local manifest listing derived keys for usability
- **HMAC challenge strategy:** Fixed challenge (`b"ykdf-v1"`) vs. context-as-challenge for hardware-level domain separation (limited to 64 bytes by YubiKey HMAC-SHA1)

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
