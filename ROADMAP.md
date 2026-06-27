# Roadmap

This roadmap describes the intended direction of YKDF. It is indicative, not a
commitment: priorities shift, and items may move between milestones. Dated
releases and concrete history live in [CHANGELOG.md](CHANGELOG.md).

## Guiding principle

The byte-level v1 derivation format is **frozen** (see [docs/SPEC.md](docs/SPEC.md)
and the golden vectors in [vectors/v1.json](vectors/v1.json)). Everything below
is additive within v1 or strictly out-of-process (new platforms, tooling). A
format change would be a new `v2` namespace, not a silent modification of v1
outputs.

## Shipped

- Core derivation engine, YubiKey desktop transport, Linux CLI.
- Key profiles including ML-KEM (FIPS 203) and ML-DSA (FIPS 204) post-quantum.
- Frozen v1 format + golden vectors; OpenSSF Passing and Silver badges.
- Signed releases through 0.2.0 (cosign signatures + SLSA provenance).
- Android NFC app (custom IsoDep APDU handler + JNI over the core).
- Desktop transport hardening: pure-Rust hidraw HMAC (libusb dropped) and a
  scdaemon passthrough so the PIV path coexists with gpg.

## Now - toward 1.0

- **Independent reference implementation(s)** consuming `vectors/v1.json` - the
  1.0 gate (below). Go (Cloudflare circl) first, then C/C++.
- **Cheap hardening:** move secrets passed as CLI arguments (`--hmac-secret`,
  `--mgmt-key`, `--import`) to file/stdin/fd input; SBOM on releases; an MSRV
  policy with a CI check.
- **Hardware acceptance:** the shared-backup test (two devices, same scalar +
  HMAC secret, assert byte-identical derivation) and the destructive slot-2
  write-path test on a spare key.
- App-relevant ergonomics: a WireGuard config helper, shell completions, an AUR
  package.

## Later

- Android build-out on the proven transport (WireGuard config + QR share,
  ML-KEM/ML-DSA key screens, signed APK).
- A Windows desktop port: the PIV path is portable over PC/SC, and the libusb
  blocker for the HMAC factor is resolved by the hidraw work, leaving a native
  Windows-HID port.
- FrodoKEM / Classic McEliece as optional / break-glass KEM profiles, gated on a
  new DRBG-based derivation mode and crate vetting.

## 1.0.0 - conformance-gated

1.0.0 is gated on **a second, independent implementation passing the golden
vectors** in `vectors/v1.json`. That cross-implementation conformance is the
signal that the v1 format is genuinely portable and stable enough to promise
long-term compatibility.

## Deprioritized

- **WebAssembly / browser:** a browser tab cannot reach the YubiKey at CLI-grade
  security (no PC/SC; secrets cross the JS/wasm boundary). The core stays
  `wasm32`-clean, but a browser transport is not a near-term goal.

## Explicitly out of scope

- Telemetry or any phone-home behaviour.
- Non-GPL-compatible dependencies.
- Format changes that would silently alter existing v1 derivations.

Larger speculative ideas are tracked in [docs/ideas.md](docs/ideas.md).
