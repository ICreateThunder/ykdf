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

    /**
     * Derive and format the public key for a derivation: the same string the
     * CLI's `ykdf pubkey` prints (base64 for x25519/ML-KEM/ML-DSA, an OpenSSH
     * line for ed25519, an `age1` recipient for age). Not secret.
     *
     * @throws IllegalArgumentException on invalid inputs or a profile with no
     *   public key (`symmetric`, `raw`).
     */
    external fun derivePublic(
        ikm: ByteArray,
        pipeline: String,
        profile: String,
        purpose: String,
        index: Int,
    ): String

    /**
     * The profile labels ykdf-core accepts, in canonical order (the same set as
     * the CLI's `--profile`). Sourced from `Profile::ALL` in core so the UI
     * cannot drift from the supported profiles. Not secret; takes no input.
     */
    external fun profiles(): Array<String>
}
