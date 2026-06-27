# Android NFC feasibility spike

Status: validated end to end on hardware (an NFC-capable Android phone and a
YubiKey 5 NFC). The NFC-derived key matches the desktop CLI byte-for-byte.
Interface-level transport findings (incl. why HMAC cannot run over USB CCID) are
in `transport-notes.md`.

This spike de-risks an Android YKDF app ahead of committing to a full build-out.
It answers two independent questions:

- **R1, toolchain:** does the Rust derivation core build and link for Android,
  callable from Kotlin?
- **R2, transport:** can both YubiKey factors be read over the phone's NFC radio?

## R1: toolchain (proven)

`crates/ykdf-jni` wraps `ykdf-core` behind a single hand-written JNI entry point
(`Java_app_ykdf_Native_derive`). The binding is split so the logic stays
auditable and testable off-device:

- `derive_secret(...)` is pure Rust (no JNI types). It assembles the canonical
  context string, runs extract then derive, and returns the profile's secret
  bytes. It is unit-tested against the frozen golden vector
  `symmetric/hkdf-sha512`, so the bytes the app sees are provably the same bytes
  the CLI and every reference implementation must produce.
- The `extern "system"` shim only marshals `byte[]`/`String` arguments, wipes
  the IKM copy it pulls across the boundary, and returns `byte[]` or throws.

Verified in this environment:

- `cargo test -p ykdf-jni` passes (4 tests, including the golden-vector match).
- `cargo ndk -t arm64-v8a -t x86_64 build -p ykdf-jni --release` produces valid
  `libykdf_jni.so` for both ABIs (NDK r27, Android 21+), each exporting the JNI
  symbol. The full crypto stack (ml-dsa, ml-kem, ed25519, x25519, argon2, sha3)
  cross-compiles cleanly; no C/libusb dependency is pulled in.

`apps/android/build-native.sh` stages the `.so` into `app/src/main/jniLibs/`,
which Gradle packages by default.

## R2: NFC transport (proven on hardware)

The decisive point: Android talks to a YubiKey over `android.nfc.tech.IsoDep`,
which is ISO 14443-4 and therefore **APDU-native**. Every exchange is an APDU,
so the desktop libusb/rusb dependency that blocks the `--layered` HMAC path on
Windows simply does not exist on Android. Both factors ride the same IsoDep
channel:

| Factor | Applet | Exchange |
| --- | --- | --- |
| PIV ECDH (slot 9d) | PIV, AID `A0 00 00 03 08` | SELECT, VERIFY PIN, GENERAL AUTHENTICATE (INS `0x87`) for key agreement; card returns the shared point |
| HMAC-SHA1 CR (slot 2) | OTP | challenge-response over the same IsoDep connection |

Rather than depend on Yubico's `yubikit-android`, the shipped app
(`apps/android`, merged in #50) hand-rolls a small, dependency-free IsoDep APDU
handler for supply-chain control, mirroring the desktop sequence exactly (SELECT
PIV, GET DATA cert, VERIFY PIN, GENERAL AUTHENTICATE; SELECT OTP, challenge-
response). Both factors were confirmed reachable over NFC on a YubiKey 5 NFC.

The derived-secret bytes from either or both factors become the `ikm` argument
to `Native.derive`, after which the derivation is identical to the CLI - and was
verified **byte-identical** to the desktop CLI on a Pixel 6 Pro, for both
standard and layered modes.

## Architecture

```
YubiKey 5 NFC
   | ISO 14443-4 (IsoDep, APDUs)
   v
Kotlin NFC layer (custom IsoDep APDU handler, no yubikit)
   | secret bytes (IKM)
   v
Native.derive(ikm, pipeline, profile, purpose, index)   [JNI]
   |
   v
crates/ykdf-jni  ->  ykdf-core (deterministic, no I/O)
   |
   v
secret bytes  ->  Compose UI / WireGuard config / key export
```

## Outcome

The spike graduated into the merged Android app (#50): a Jetpack Compose
reader-mode UI over the custom IsoDep handler, with the Gradle/AGP/Kotlin/Compose
matrix reconciled (see `apps/android`). On-device equivalence was confirmed -
deriving on Android and on the CLI from the same YubiKey yields byte-identical
output for both standard and layered modes. Remaining Android work (full app
features, signed APK) is tracked in [ROADMAP.md](../ROADMAP.md).
