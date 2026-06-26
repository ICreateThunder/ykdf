# Android NFC feasibility spike

Status: toolchain proven, app skeleton in place, NFC transport pending hardware.

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

## R2: NFC transport (feasibility, pending on-device confirmation)

The decisive point: Android talks to a YubiKey over `android.nfc.tech.IsoDep`,
which is ISO 14443-4 and therefore **APDU-native**. Every exchange is an APDU,
so the desktop libusb/rusb dependency that blocks the `--layered` HMAC path on
Windows simply does not exist on Android. Both factors ride the same IsoDep
channel:

| Factor | Applet | Exchange |
| --- | --- | --- |
| PIV ECDH (slot 9d) | PIV, AID `A0 00 00 03 08` | SELECT, VERIFY PIN, GENERAL AUTHENTICATE (INS `0x87`) for key agreement; card returns the shared point |
| HMAC-SHA1 CR (slot 2) | OTP | challenge-response over the same IsoDep connection |

Yubico's `yubikit-android` already implements both over NFC (`PivSession` for
PIV key agreement, `YubiOtpSession.calculateHmacSha1` for challenge-response),
so the spike does not need to hand-roll the APDU sequences; it can either use the
library or mirror its exchanges. The on-device hardware step (a phone plus a
YubiKey 5 NFC) is what remains to confirm end to end, in particular that slot 2
challenge-response is reachable over NFC on the target keys.

The derived-secret bytes from either or both factors become the `ikm` argument
to `Native.derive`, after which the derivation is identical to the CLI.

## Architecture

```
YubiKey 5 NFC
   | ISO 14443-4 (IsoDep, APDUs)
   v
Kotlin NFC layer (yubikit-android: PivSession / YubiOtpSession)   <-- TODO, hardware
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

## Deferred to the hardware step

- Wire `MainActivity.deriveFromNfc()` to IsoDep and the YubiKey sessions.
- Confirm slot 2 HMAC challenge-response over NFC on the target YubiKeys.
- Run the Gradle build and reconcile the AGP/Kotlin/Compose/SDK version matrix
  (not executed in the spike environment; see `apps/android/README.md`).
- On-device equivalence: derive on Android and on the CLI from the same YubiKey,
  assert byte-identical output (the same shared-backup acceptance test, on NFC).
