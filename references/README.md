# Independent reference implementations

The canonical YKDF implementation is the Rust `ykdf-core` crate. The byte-level
v1 format it produces is **frozen** and defined, independently of any code, in
[docs/SPEC.md](../docs/SPEC.md) with golden vectors in
[vectors/v1.json](../vectors/v1.json).

This directory holds **separate, from-the-spec reimplementations** of the
derivation. Their job is to prove the format is genuinely portable: each one
must reproduce every byte in `vectors/v1.json`. A second implementation passing
the golden vectors is the gate for the 1.0 release (see
[ROADMAP.md](../ROADMAP.md)); the Go and C references both pass it on
independent primitive stacks.

To be real evidence, a reference must be *independent*: it re-derives the
HKDF/SHAKE/cascade construction from the spec prose rather than calling the same
library the Rust core uses. Heavy standardised primitives (Argon2id, ML-KEM,
ML-DSA) are delegated to a vetted library, which doubles as a check that YKDF's
seed handling matches the FIPS definitions those libraries implement.

## Implementations

| Language | Path | Status | Primitive sources |
|----------|------|--------|-------------------|
| Go | [go/](go/) | All 32 vectors passing | hand-written HKDF/SHAKE; Cloudflare circl (ML-KEM/ML-DSA); `x/crypto` (Argon2id) |
| C | [c/](c/) | All 32 vectors passing | hand-written HKDF/SHAKE; OpenSSL >= 3.5 (SHAKE, ML-KEM/ML-DSA); libsodium (Argon2id) |

Each reference uses a deliberately different primitive stack (RustCrypto for the
core, circl for Go, OpenSSL for C), so agreement across all three is evidence the
format is portable, not an artifact of one library.

The vectors are read in place from `vectors/v1.json`; references do not vendor a
copy, so there is a single source of truth.
