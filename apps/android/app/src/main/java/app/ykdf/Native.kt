package app.ykdf

/**
 * The native derivation boundary. Loads `libykdf_jni.so` (built from
 * `crates/ykdf-jni` by `build-native.sh`) and exposes the single deterministic
 * entry point.
 *
 * The exported symbol must stay in lockstep with the Rust shim
 * `Java_app_ykdf_Native_derive`: package `app.ykdf`, class `Native`, method
 * `derive`. Renaming any of the three breaks symbol resolution at call time.
 */
object Native {
    init {
        System.loadLibrary("ykdf_jni")
    }

    /**
     * Derive a key from input key material.
     *
     * @param ikm raw input key material (the YubiKey secret read over NFC, or
     *   test material). Must be at least 16 bytes.
     * @param pipeline KDF pipeline label, e.g. `hkdf-sha512`, `shake256`.
     * @param profile output profile label, e.g. `x25519`, `symmetric`, `mldsa65`.
     * @param purpose self-describing purpose, lowercase `[a-z0-9-]`, 1..=64 chars.
     * @param index key index for rotation.
     * @return the profile's primary secret bytes (equivalent to the CLI's
     *   `--format binary`).
     * @throws IllegalArgumentException if inputs are invalid or the
     *   profile/pipeline combination is not accepted.
     */
    external fun derive(
        ikm: ByteArray,
        pipeline: String,
        profile: String,
        purpose: String,
        index: Int,
    ): ByteArray
}
