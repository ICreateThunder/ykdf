# YKDF Go reference implementation

An independent Go reimplementation of the YKDF v1 derivation format, written
from [docs/SPEC.md](../../docs/SPEC.md) to corroborate the canonical Rust
`ykdf-core`. It is a conformance reference, not a product: there is no YubiKey
transport here, only the deterministic `IKM -> extract -> expand -> derive`
pipeline that the spec defines.

## Running the conformance suite

```bash
cd references/go
go test ./...          # checks every vector in ../../vectors/v1.json
go test -v ./...       # one sub-test per vector, plus PQ round-trips
```

`TestVectors` recomputes each vector stage by stage — master key, expanded
output, then the profile output — and compares against the committed JSON, so a
mismatch points at the exact stage that diverged. `TestMLKEMRoundTrip` and
`TestMLDSARoundTrip` confirm the derived seeds yield working keypairs
(encapsulate/decapsulate and sign/verify), not just matching bytes.

## What is independent vs delegated

| Step | Source | Why |
|------|--------|-----|
| HKDF-Extract / HKDF-Expand | hand-written from RFC 5869 (`pipeline.go`) | independent of the Rust `hkdf` crate |
| SHAKE256 sponge (extract / cascade / expand) | stdlib `crypto/sha3` | FIPS 202 XOF |
| Curve25519 clamp, Bech32 age identity | hand-written (`profile.go`, `bech32.go`) | small, spec-defined |
| Argon2id passphrase stretch | `golang.org/x/crypto/argon2` | standardised, fixed cost |
| ML-KEM / ML-DSA keygen from seed | Cloudflare circl | FIPS 203 / 204; also checks YKDF's seed handling matches |

## Layout

- `ykdf.go` — constants, context string, `Extract` / `Cascade` / `Expand`.
- `pipeline.go` — HKDF, SHAKE, and Argon2id primitives.
- `profile.go` — accept policy, expand lengths, and post-processing.
- `bech32.go` — Bech32 (not Bech32m) encoder for age identities.
- `*_test.go` — the conformance vectors and PQ round-trips.
