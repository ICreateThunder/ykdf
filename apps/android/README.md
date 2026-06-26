# YKDF Android (spike)

A minimal Android app that runs YKDF derivation on-device by calling
`ykdf-core` through JNI (`crates/ykdf-jni`). This is a **feasibility spike**: it
proves the Rust crypto core builds and links for Android and that the full chain
Compose UI -> JNI -> `ykdf-core` -> bytes is sound. The NFC transport that will
read the YubiKey secret is stubbed (see `MainActivity.deriveFromNfc`).

## What is proven

- `crates/ykdf-jni` cross-compiles to `arm64-v8a` and `x86_64` with NDK r27,
  exporting `Java_app_ykdf_Native_derive`.
- The pure-Rust helper behind that symbol reproduces the frozen golden vector
  `symmetric/hkdf-sha512` byte-for-byte (unit-tested in `cargo test -p ykdf-jni`).

## Build the native library

```sh
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.3.13750724"
./build-native.sh
```

This stages `libykdf_jni.so` into `app/src/main/jniLibs/<abi>/`, which Gradle
packages into the APK automatically.

## Build the app

```sh
gradle wrapper        # one-time: generate the wrapper for this Gradle
./gradlew :app:assembleDebug
```

> NOTE: the Gradle build was **not** executed in the spike environment (no
> network for AGP/Compose artifacts). The version pins in `build.gradle.kts` and
> `app/build.gradle.kts` (AGP 8.7.3, Kotlin 2.0.21, Compose BOM 2024.09.00,
> compileSdk 35) are a coherent starting point; reconcile them in Android Studio
> against the installed SDK platforms and Gradle version before relying on them.

## Remaining work (needs hardware)

Wire `deriveFromNfc()` to `android.nfc.tech.IsoDep`. Because IsoDep is
APDU-native (ISO 14443-4), both YubiKey factors travel as APDUs with no libusb
involved:

- **PIV ECDH (slot 9d):** SELECT PIV applet, VERIFY PIN, GENERAL AUTHENTICATE.
- **HMAC-SHA1 CR (OTP slot 2):** challenge-response over the same channel.

Yubico's `yubikit-android` (`PivSession`, `YubiOtpSession`) implements both over
NFC and is the reference for the APDU exchanges. See `docs/android-spike.md`.
