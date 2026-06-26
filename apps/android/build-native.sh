#!/usr/bin/env sh
# Build the Rust JNI library (crates/ykdf-jni) for Android and stage it into the
# app's jniLibs so Gradle packages it into the APK.
#
# Requires:
#   - rustup targets: aarch64-linux-android, x86_64-linux-android
#   - cargo-ndk (cargo install cargo-ndk)
#   - an installed NDK, with ANDROID_NDK_HOME pointing at it
set -eu

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your NDK, e.g. \$ANDROID_HOME/ndk/27.3.13750724}"

unset CDPATH
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
OUT="$SCRIPT_DIR/app/src/main/jniLibs"

cd "$ROOT"
cargo ndk \
    -t arm64-v8a \
    -t x86_64 \
    -o "$OUT" \
    build -p ykdf-jni --release

echo "Staged libykdf_jni.so into $OUT"
