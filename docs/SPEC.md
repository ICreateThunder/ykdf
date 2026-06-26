# YKDF v1 Derivation Specification

Status: **frozen**. This document defines the byte-level behaviour of the YKDF
v1 key-derivation format. It is the conformance contract: any implementation
(the reference Rust `ykdf-core`, plus future WASM/Android ports) MUST reproduce
the exact bytes defined here and pinned in [`vectors/v1.json`](../vectors/v1.json).

The format is versioned independently of the software's SemVer. The version
token is `v1`, embedded in the context string (see [Versioning](#versioning)).

## Conventions

- `||` denotes byte concatenation.
- Byte strings written as ASCII (e.g. `"ykdf-v1"`) are the literal ASCII bytes,
  no terminator. `"ykdf-v1"` is the 7 bytes `79 6b 64 66 2d 76 31`.
- `HMAC-H(key, msg)` is HMAC (RFC 2104) with hash `H`, full untruncated output.
- `H` is SHA-512 or SHA3-512 depending on pipeline; both have a 64-byte output.
- `SHAKE256(x)` is the SHAKE256 XOF absorbing `x`; "squeeze N" reads N output bytes.
- The master key is always 64 bytes (512 bits).

## Overview

YKDF derives keys with an extract-then-expand construction (the TLS 1.3 / HKDF
pattern):

```
IKM ──extract──▶ master_key(64) ──expand(context,len)──▶ okm ──post-process──▶ key
                      ▲
   passphrase ──stretch+cascade (optional)
```

A **pipeline** selects the primitives for both phases. A **profile** selects the
output length and post-processing. The derivation is fully deterministic: the
same inputs always produce the same bytes, with no stored state.

### Pipelines

| Pipeline label   | Extract / Expand primitive        |
|------------------|-----------------------------------|
| `hkdf-sha512`    | HKDF over HMAC-SHA-512            |
| `hkdf-sha3-512`  | HKDF over HMAC-SHA3-512           |
| `shake256`       | SHAKE256 sponge                   |

### Profiles

| Profile label | Expand length | Post-processing                        |
|---------------|---------------|----------------------------------------|
| `x25519`      | 32            | Curve25519 clamp                       |
| `ed25519`     | 32            | Ed25519 seed (verbatim)                |
| `age-x25519`  | 32            | Curve25519 clamp + age bech32 identity |
| `symmetric`   | 32            | verbatim                               |
| `mlkem512`    | 64            | ML-KEM-512 keygen from seed            |
| `mlkem768`    | 64            | ML-KEM-768 keygen from seed            |
| `mlkem1024`   | 64            | ML-KEM-1024 keygen from seed           |
| `mldsa44`     | 32            | ML-DSA-44 keygen from seed             |
| `mldsa65`     | 32            | ML-DSA-65 keygen from seed             |
| `mldsa87`     | 32            | ML-DSA-87 keygen from seed             |
| `raw`         | caller-chosen | verbatim                               |

## 1. Input Key Material (IKM)

IKM is raw entropy from the hardware root of trust. The transport (YubiKey PIV
ECDH on slot 9d, optional HMAC-SHA1 challenge-response on OTP slot 2) is out of
scope for this format; this spec begins once the IKM bytes exist.

- **Standard mode:** IKM is the 32-byte PIV P-256 ECDH shared secret.
- **Layered mode:** IKM is `ecdh_secret(32) || hmac_response(20)` = 52 bytes,
  in that order. The HMAC-SHA1 response is concatenated, not separately mixed.
- IKM MUST be at least 16 bytes; shorter input is rejected.

The SHA-1 used to produce the layered HMAC response is a hardware-mandated
PRF whose output is treated only as additional entropy; see
[SECURITY.md](../SECURITY.md#cryptographic-algorithm-notes).

## 2. Extract

Extract maps IKM to the 64-byte master key. The salt is the fixed ASCII string
`"ykdf-v1"` (bytes `79 6b 64 66 2d 76 31`).

**HKDF pipelines** (`hkdf-sha512`, `hkdf-sha3-512`) — this is HKDF-Extract
(RFC 5869 §2.2):

```
master_key = HMAC-H("ykdf-v1", IKM)        # 64 bytes
```

**Sponge pipeline** (`shake256`):

```
master_key = SHAKE256( 0x01 || "ykdf-v1" || IKM ), squeeze 64
```

The leading `0x01` is the extract domain-separation tag (see also `0x02` for
cascade, below), ensuring extract and cascade cannot collide.

## 3. Passphrase factor (optional)

When a passphrase is supplied it is stretched and cascaded into the master key
*after* extract and *before* expand.

### 3.1 Stretch

```
stretched = Argon2id( password,
                      salt = "ykdf-v1-argon2id",   # 16 ASCII bytes
                      m = 131072 KiB (128 MiB),
                      t = 3,
                      p = 1,
                      version = 0x13,              # Argon2 v1.3
                      output = 64 bytes )
```

The cost parameters are fixed; they are not configurable (this both prevents
weakening the KDF and preserves cross-device determinism).

### 3.2 Descriptor

The stretch is identified by a canonical ASCII descriptor:

```
descriptor = "argon2id:m=131072,t=3,p=1"
```

The descriptor is bound into the derivation (below) so a passphrase derivation
is self-describing; a future stretch algorithm is added additively as a new
descriptor, not by changing v1.

### 3.3 Cascade

The cascade input prefixes the descriptor with its length (one byte) so the
encoding is unambiguous:

```
cascade_ikm = len(descriptor) (1 byte) || descriptor || stretched(64)
```

The master key is then replaced by the cascade output:

**HKDF pipelines** (the early secret takes the HMAC key / salt position):

```
master_key = HMAC-H( key = master_key, msg = cascade_ikm )    # 64 bytes
```

**Sponge pipeline:**

```
master_key = SHAKE256( 0x02 || master_key || cascade_ikm ), squeeze 64
```

`0x02` is the cascade domain-separation tag.

## 4. Context string

The expand phase is bound to a self-describing context string:

```
ykdf:v1:<pipeline>:<profile>:<purpose>:<index>
```

- `pipeline` ∈ { `hkdf-sha512`, `hkdf-sha3-512`, `shake256` }
- `profile` ∈ { `x25519`, `ed25519`, `age-x25519`, `symmetric`, `mlkem512`,
  `mlkem768`, `mlkem1024`, `mldsa44`, `mldsa65`, `mldsa87`, `raw` }
- `purpose`: 1–64 characters, each `a`–`z`, `0`–`9`, or `-`; no leading or
  trailing `-`. (No field may contain `:`, so the encoding is unambiguous.)
- `index`: a `u32` rendered in decimal (`0`–`4294967295`), for key rotation.

The pipeline MUST be one the profile accepts (see [Accept policy](#accept-policy)).

### Length binding

The KDF input appends the output length as a final field:

```
kdf_info = "<context>:<length>"
```

e.g. `ykdf:v1:hkdf-sha512:x25519:test:0:32`. Both HKDF-Expand and SHAKE have the
prefix property (output for length `a` is a prefix of output for length `b > a`).
Binding the length into the info defeats this: a request for a different length
is a different derivation.

## 5. Expand

Expand stretches the master key to `length` bytes, bound to `kdf_info`.

**HKDF pipelines** — HKDF-Expand (RFC 5869 §2.3) with PRK = master key:

```
N      = ceil(length / 64)            # 1 ≤ N ≤ 255
T(0)   = "" (empty)
T(i)   = HMAC-H( master_key, T(i-1) || kdf_info || byte(i) )   for i = 1..N
okm    = (T(1) || T(2) || ... || T(N)) truncated to length
```

`byte(i)` is the single byte `i`. `length` MUST be ≤ `255 * 64 = 16320`.

**Sponge pipeline:**

```
okm = SHAKE256( master_key || kdf_info ), squeeze length
```

(No domain tag here: the master key is always exactly 64 bytes, so the boundary
with `kdf_info` is unambiguous.)

The expand length per profile is fixed (32 for classical, ML-DSA, and
`raw`-by-default, 64 for ML-KEM); `raw` may request any length 1..=16320 via the
API.

## 6. Profile post-processing

Applied to the `okm` from expand.

### x25519 (32 bytes in → 32-byte secret key)

Curve25519 clamping (RFC 7748):

```
key[0]  &= 0xF8
key[31] &= 0x7F
key[31] |= 0x40
```

### ed25519 (32 → 32-byte seed)

The 32 bytes are the Ed25519 secret seed verbatim (RFC 8032; the secret scalar
and prefix are derived from it by SHA-512 inside the signing implementation).

### age-x25519 (32 → age identity)

Clamp as x25519, then bech32-encode:

- HRP `age-secret-key-`, **Bech32** checksum (not Bech32m).
- The whole string is upper-cased, yielding `AGE-SECRET-KEY-1...`.

The raw 32-byte clamped secret is also exposed.

### symmetric (32 → 32 bytes)

The 32 bytes verbatim.

### mlkem512 / mlkem768 / mlkem1024 (64 → keypair)

The 64-byte `okm` is the ML-KEM seed `(d || z)`. ML-KEM key generation
(FIPS 203) is run on this seed to produce:

- `encapsulation_key`: the standard encoded ML-KEM encapsulation key
  (800 / 1184 / 1568 bytes for 512 / 768 / 1024).
- `decapsulation_key`: the **64-byte seed representation** (the `(d, z)` seed),
  not the expanded FIPS 203 decapsulation key. Reconstruct the full key by
  re-running keygen on the seed.

FIPS 203 compliance of the primitive is provided by the underlying ML-KEM
implementation, cross-checked by an encapsulate/decapsulate round-trip in the
test suite.

### mldsa44 / mldsa65 / mldsa87 (32 → keypair)

The 32-byte `okm` is the ML-DSA seed `xi`. ML-DSA key generation (FIPS 204) is
run on this seed to produce:

- `verifying_key`: the standard encoded ML-DSA verifying key
  (1312 / 1952 / 2592 bytes for 44 / 65 / 87).
- `signing_key`: the **32-byte seed `xi`**, not the expanded FIPS 204 signing
  key. Reconstruct the full signing key by re-running keygen on the seed.

FIPS 204 compliance of the primitive is provided by the underlying ML-DSA
implementation, cross-checked by a sign/verify round-trip in the test suite.

### raw (length → length bytes)

The `okm` verbatim.

## Accept policy

| Profile      | `hkdf-sha512` | `hkdf-sha3-512` | `shake256` | Default        |
|--------------|:-------------:|:---------------:|:----------:|----------------|
| `x25519`     | ✅            | ✅              | ❌         | `hkdf-sha512`  |
| `ed25519`    | ✅            | ✅              | ❌         | `hkdf-sha512`  |
| `age-x25519` | ✅            | ✅              | ❌         | `hkdf-sha512`  |
| `symmetric`  | ✅            | ✅              | ❌         | `hkdf-sha512`  |
| `mlkem512`   | ❌            | ❌              | ✅         | `shake256`     |
| `mlkem768`   | ❌            | ❌              | ✅         | `shake256`     |
| `mlkem1024`  | ❌            | ❌              | ✅         | `shake256`     |
| `mldsa44`    | ❌            | ❌              | ✅         | `shake256`     |
| `mldsa65`    | ❌            | ❌              | ✅         | `shake256`     |
| `mldsa87`    | ❌            | ❌              | ✅         | `shake256`     |
| `raw`        | ✅            | ✅              | ✅         | `hkdf-sha512`  |

A context with a disallowed pipeline/profile combination is rejected.

## Versioning

The format version (`v1`) is encoded in the context string and is independent
of the software SemVer. Adding a new pipeline, profile, or stretch algorithm is
**additive**: it introduces a new label (or descriptor), leaving every existing
derivation byte-identical, and does **not** change the version. A `v1` → `v2`
bump re-namespaces every output and is reserved for a redesign that cannot be
expressed additively.

## Constants

| Constant                | Value                                   |
|-------------------------|-----------------------------------------|
| Extract salt            | `"ykdf-v1"` (`79 6b 64 66 2d 76 31`)    |
| Argon2 salt             | `"ykdf-v1-argon2id"`                    |
| Extract domain tag      | `0x01`                                  |
| Cascade domain tag      | `0x02`                                  |
| Stretch descriptor      | `"argon2id:m=131072,t=3,p=1"`           |
| Layered HMAC challenge  | `"ykdf-v1"`                             |
| Master key length       | 64 bytes                                |
| Minimum IKM length      | 16 bytes                                |

## Test vectors

[`vectors/v1.json`](../vectors/v1.json) is the canonical conformance suite. Each
entry fixes the inputs and records the `master_key_hex`, `expanded_hex`, and the
profile output, so a reimplementation can pinpoint which stage diverges. The
reference test suite (`crates/ykdf-core/tests/vectors.rs`):

1. recomputes every vector and asserts equality with the committed JSON;
2. independently recomputes the HKDF master key and expand output with the
   `hkdf` crate (a separate RFC 5869 implementation) and asserts equality.

### Worked example

`x25519` over `hkdf-sha512`, `purpose = "test"`, `index = 0`:

```
IKM         = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
master_key  = HMAC-SHA512("ykdf-v1", IKM)
            = 8e22c35391d73f13a76190c201eeb75aae8fa1199b9b08a3f7748e81a4704af9
              76525b27c9a928a38d9a848b45e2780d1396d135c1bd446707369dd12093e3dd
kdf_info    = "ykdf:v1:hkdf-sha512:x25519:test:0:32"
okm         = HKDF-Expand(master_key, kdf_info, 32)
            = a9c32c4b55de73616d3f29c5b5623bbba32d481b4bf35ccb7548cab2dc26589a
secret_key  = clamp(okm)
            = a8c32c4b55de73616d3f29c5b5623bbba32d481b4bf35ccb7548cab2dc26585a
```
