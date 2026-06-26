# YKDF Android (spike)

A minimal Android app that reads a YubiKey over NFC and runs YKDF derivation
on-device by calling `ykdf-core` through JNI (`crates/ykdf-jni`). This started as
a feasibility spike and has been validated end to end on hardware.

## What is proven (on hardware)

Verified on an NFC-capable Android phone with a YubiKey 5 NFC:

- `crates/ykdf-jni` cross-compiles to `arm64-v8a` and `x86_64` (NDK r27),
  exporting `Java_app_ykdf_Native_derive`; the pure-Rust helper reproduces the
  golden vector `symmetric/hkdf-sha512` byte-for-byte (`cargo test -p ykdf-jni`).
- The custom, dependency-free NFC handler (`app/.../nfc/`) reads the slot-9d
  self-ECDH secret over NFC ISO-DEP and the app derives the **same x25519 key the
  desktop CLI produces over USB**, byte-for-byte.
- The layered path (PIV ECDH + HMAC-SHA1 on OTP slot 2) also runs over NFC and
  produces the expected distinct key. See `docs/transport-notes.md` for why NFC
  is the cleaner transport for the HMAC factor.

## NFC handler

`app/src/main/java/app/ykdf/nfc/` is a small, zero-dependency APDU layer (no
yubikit), so the entire YubiKey-facing surface is auditable:

- `Apdu.kt` - command/response APDUs, `61xx` GET RESPONSE chaining, BER-TLV.
- `YubiKeyNfc.kt` - reproduces the desktop IKM exactly: PIV self-ECDH on slot 9d
  (32 bytes), and layered = ECDH ‖ HMAC-SHA1 on OTP slot 2 (52 bytes).

## Build the native library

```sh
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.3.13750724"
./build-native.sh
```

This stages `libykdf_jni.so` into `app/src/main/jniLibs/<abi>/`, which Gradle
packages into the APK automatically.

## Build the app

A Gradle wrapper (8.11.1) is included. The verified toolchain is JDK 21 +
AGP 8.10.1 + Kotlin 2.0.21 + Compose BOM 2024.09.00 + compileSdk 36. Point
`JAVA_HOME` at a JDK 21 (a newer JDK may be rejected by Gradle/AGP):

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk   # or your JDK 21
export ANDROID_HOME="$HOME/Android/Sdk"
./build-native.sh
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`local.properties` (with `sdk.dir=...`) is created locally and not committed.

## Using the app

Type the PIV PIN, set the profile/purpose, optionally tick Layered, then tap the
YubiKey to the back of the phone.
