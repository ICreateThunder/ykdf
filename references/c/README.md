# YKDF C reference implementation

An independent C reimplementation of the YKDF v1 derivation format, written from
[docs/SPEC.md](../../docs/SPEC.md) to corroborate the canonical Rust
`ykdf-core`. Like the [Go reference](../go/), it is a conformance reference, not
a product: no YubiKey transport, only the deterministic
`IKM -> extract -> expand -> derive` pipeline.

Its value is a *different primitive stack* from the Rust core (RustCrypto) and
the Go reference (Cloudflare circl): if all three agree on every vector, the v1
format is genuinely portable rather than tied to one library's quirks.

## Requirements

- A C11 compiler, `make`, `pkg-config`, and `python3`.
- **libsodium** (Argon2id).
- **OpenSSL >= 3.5** — its providers do native ML-KEM (FIPS 203) and ML-DSA
  (FIPS 204) key generation deterministically from the standard seed. Earlier
  OpenSSL lacks these algorithms; Debian trixie, Fedora 42+, Homebrew, and
  similar ship a new enough build.

## Running the conformance suite

```bash
cd references/c
make test          # builds and checks every vector in ../../vectors/v1.json
make clean
```

The runner recomputes each vector stage by stage (master key, expanded output,
profile output) and compares against the canonical values, so a mismatch points
at the exact stage that diverged. Exit status is non-zero on any failure.

## What is independent vs delegated

| Step | Source | Why |
|------|--------|-----|
| HKDF-Extract / HKDF-Expand | hand-written from RFC 5869 (`src/ykdf.c`) | independent of any library KDF |
| SHAKE256 sponge (extract / cascade / expand) | OpenSSL EVP (FIPS 202) | XOF |
| Curve25519 clamp, Bech32 age identity | hand-written (`src/ykdf.c`, `src/bech32.c`) | small, spec-defined |
| Argon2id passphrase stretch | libsodium `crypto_pwhash` | battle-tested, fixed cost (p=1) |
| ML-KEM / ML-DSA keygen from seed | OpenSSL >= 3.5 providers | FIPS 203 / 204; checks YKDF seed handling against a third implementation |

## Layout

- `include/ykdf.h` — the public API.
- `src/ykdf.c` — constants, context string, extract / cascade / expand, clamp.
- `src/bech32.{c,h}` — Bech32 (not Bech32m) encoder for age identities.
- `src/pqc.c` — ML-KEM / ML-DSA seed key generation via OpenSSL.
- `test/gen_vectors.py` — transcribes `vectors/v1.json` into a compile-time
  table (no runtime JSON parser, no vendored copy; regenerated each build).
- `test/conformance.c` — the runner.

Secret-bearing intermediates are wiped with `sodium_memzero`. The build directory
(`build/`) is generated and gitignored.
