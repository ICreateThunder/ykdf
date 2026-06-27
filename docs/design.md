# YKDF design

How and why YKDF works. For the byte-level derivation format see
[SPEC.md](SPEC.md); for the desktop transport details see
[transport-notes.md](transport-notes.md); for the security argument and its
evidence see [assurance-case.md](assurance-case.md).

## Problem

Modern systems require keys across many different cryptographic schemes -
WireGuard (Curve25519), SSH/Git signing (Ed25519), post-quantum encryption
(ML-KEM), file encryption (age/ChaCha20), and more. Managing these independently
is fragile: keys get lost, backups diverge, and there's no unified trust anchor.

YubiKey hardware can protect secrets, but doesn't natively support many of these
algorithms (no Curve25519, no ML-KEM). We need a software layer that bridges
hardware-bound entropy to arbitrary key types.

## Approach

Derive all keys deterministically from hardware-bound secrets on a YubiKey. The
derivation is structured as a three-layer pipeline:

```
Layer 1: Entropy Extraction (hardware)
    YubiKey PIV ECDH + optional HMAC-SHA1 → raw input key material

Layer 2: Master Key Derivation (extract)
    HKDF-Extract(salt, IKM) → 512-bit master key

Layer 3: Domain-Specific Expansion (expand)
    KDF(master_key, context_string) → raw bytes → key-type post-processing
```

Keys are never stored - they are re-derived on demand from the YubiKey and exist
in memory only during use.

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

### Why not FIDO2?

FIDO2 credentials are bound to the individual authenticator by design - they
cannot be cloned. Two YubiKeys would produce different outputs for the same
input, breaking deterministic derivation across backup keys. PIV and HMAC secrets
can be imported identically to both keys.

### Applet isolation

YubiKey 5 runs each applet in a separate security domain. Applets cannot read
each other's key material. The layered mode (PIV + HMAC) provides genuine defense
in depth - compromising one applet doesn't expose the other's secrets.

### Implementation layout

Core library in Rust, cross-compiling to Linux and Android:

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
│   └── ykdf-yubikey/           # YubiKey interaction layer (desktop)
│       └── src/
│           ├── piv.rs          # PIV ECDH (slot 9d, self-ECDH via cert)
│           ├── hmac.rs         # HMAC-SHA1 challenge-response (OTP slot 2)
│           ├── scd.rs          # scdaemon passthrough transport
│           └── lib.rs          # derive_ikm() orchestration
│
└── apps/
    ├── cli/                    # Linux command-line tool (ykdf)
    └── android/               # Android NFC app (+ crates/ykdf-jni)
```

## Entropy sources

| Source | Applet | Output | Access Control | Cloneable |
|--------|--------|--------|----------------|-----------|
| **PIV ECDH** (primary) | PIV slot 9d | 32 bytes | PIN + touch | Yes (import same P-256 key) |
| **HMAC-SHA1** (optional layer) | OTP slot 2 | 20 bytes | Touch only | Yes (program same secret) |
| **Passphrase** (optional 2nd factor) | N/A | Argon2id output | Knowledge | N/A |

### Security modes

| Mode | Entropy Sources | Access Required |
|------|----------------|-----------------|
| **Standard** | PIV ECDH | PIN + touch + YubiKey |
| **Layered** | PIV ECDH + HMAC-SHA1 | PIN + touch + YubiKey (two applets) |
| **Hardened** | PIV ECDH + HMAC-SHA1 + passphrase | PIN + touch + YubiKey + passphrase |
| **Simple** | HMAC-SHA1 only | Touch + YubiKey |

## Key derivation

The authoritative byte-level definition is [SPEC.md](SPEC.md); this section is the
conceptual overview.

### Domain separation

Every derived key uses a unique context string that ensures cryptographic
independence:

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

The `index` field enables key rotation - bump the index, re-share the new public
key.

### Pipelines

The framework is pipeline-agile. A pipeline names the extract-then-expand
primitives, and the context string records which pipeline produced a key, so
derivations are never ambiguous. All pipelines are compiled in and selected at
runtime; changing the pipeline changes every derived key.

| Pipeline (label) | Extract | Expand | Use Case |
|------------------|---------|--------|----------|
| `hkdf-sha512` | HKDF-Extract-SHA512 | HKDF-Expand-SHA512 | Default for fixed-length keys (WG, Ed25519, age). RFC 5869, constant-time |
| `hkdf-sha3-512` | HKDF-Extract-SHA3-512 | HKDF-Expand-SHA3-512 | Same construction with Keccak-family hash diversity |
| `shake256` | SHAKE256(salt ‖ IKM) | SHAKE256(master ‖ context) | Variable-length and post-quantum keys (ML-KEM). Native XOF, no counter mode |

Each pipeline produces a 512-bit master key. The requested output length is bound
into the expand input so that different lengths under the same context yield
independent key streams.

### Key profiles

Each profile defines output length, a default pipeline, the pipelines it accepts,
and any post-processing:

| Profile | Default Pipeline | Accepts | Output | Post-Processing |
|---------|------------------|---------|--------|-----------------|
| `x25519` | `hkdf-sha512` | either HKDF variant | 32 bytes | Curve25519 clamping |
| `ed25519` | `hkdf-sha512` | either HKDF variant | 32 bytes | Used as seed for keypair generation |
| `age-x25519` | `hkdf-sha512` | either HKDF variant | 32 bytes | Bech32 encoding as age identity |
| `symmetric` | `hkdf-sha512` | either HKDF variant | 32 bytes | Direct use (AES-256, ChaCha20, etc.) |
| `mlkem512` | `shake256` | `shake256` only | 64 bytes | Seed `(d, z)` for `KeyGen(d, z)` |
| `mlkem768` | `shake256` | `shake256` only | 64 bytes | Seed `(d, z)` for `KeyGen(d, z)` |
| `mlkem1024` | `shake256` | `shake256` only | 64 bytes | Seed `(d, z)` for `KeyGen(d, z)` |
| `mldsa44` / `mldsa65` / `mldsa87` | `shake256` | `shake256` only | 32-byte seed | ML-DSA (FIPS 204) signing-key seed |
| `raw` | `hkdf-sha512` | any pipeline | 32 bytes | None - caller decides |

## How PIV ECDH works

YKDF uses a self-ECDH approach: it reads the P-256 public key from the
certificate in PIV slot 9d and sends it back to the YubiKey as the ECDH peer
point. The YubiKey computes `ECDH(private_key, own_public_key)` and returns a
deterministic 32-byte shared secret. No config file or external peer point
storage is needed.

## Security properties

- **Hardware-bound:** master entropy requires the physical YubiKey.
- **PIN-protected:** PIV requires the PIN (3 attempts before PUK lockout).
- **Touch-required:** physical presence confirmation per derivation.
- **Deterministic:** same inputs produce same keys - no state to sync.
- **Domain-separated:** mathematically independent outputs per context string.
- **No key storage:** keys exist in memory only during use.
- **Forward-compatible:** new profiles and pipelines added without breaking
  existing derivations.
- **Backup-friendly:** two YubiKeys with identical secrets (see
  [provisioning.md](provisioning.md)).

The vulnerability-reporting policy and threat model live in
[SECURITY.md](../SECURITY.md).
