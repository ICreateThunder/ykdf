//! JNI bindings exposing `ykdf-core` key derivation to Android/Kotlin.
//!
//! The Android app reads the `YubiKey` secret over NFC (Kotlin `IsoDep` APDUs),
//! then calls into this library to run the deterministic, platform-independent
//! derivation in `ykdf-core`. The secret bytes cross the JNI boundary as a
//! `byte[]`; nothing here does I/O or touches the `YubiKey` directly.
//!
//! Two layers keep the FFI surface auditable:
//! - [`derive_secret`] is pure Rust (no JNI types) and carries the real logic,
//!   so it is unit-tested in-process against the frozen golden vectors.
//! - `Java_app_ykdf_Native_derive` is a thin marshalling shim over it: it
//!   converts the Java arguments, calls [`derive_secret`], wipes the input copy
//!   it pulled across the boundary, and returns a `byte[]` (or throws).

use ykdf_core::{Context, Ikm, ProfileOutput, derive, extract};

/// Run a YKDF derivation from raw input key material.
///
/// `pipeline`, `profile`, and `purpose` are the self-describing context fields
/// (see `docs/SPEC.md`). They are assembled into the canonical context string
/// `ykdf:v1:<pipeline>:<profile>:<purpose>:<index>` and parsed, so an invalid
/// or disallowed profile/pipeline combination is rejected exactly as the CLI
/// rejects it.
///
/// Returns the profile's primary secret bytes: the same bytes the CLI emits in
/// `--format binary`.
///
/// # Errors
///
/// Returns a human-readable message if the IKM is too short, the context is
/// invalid, the profile/pipeline combination is not accepted, or derivation
/// fails.
pub fn derive_secret(
    ikm: &[u8],
    pipeline: &str,
    profile: &str,
    purpose: &str,
    index: u32,
) -> Result<Vec<u8>, String> {
    let ctx_str = format!("ykdf:v1:{pipeline}:{profile}:{purpose}:{index}");
    let context: Context = ctx_str.parse().map_err(|e| format!("{e}"))?;

    let ikm = Ikm::new(ikm.to_vec()).map_err(|e| format!("{e}"))?;
    let master_key = extract(&ikm, context.pipeline()).map_err(|e| format!("{e}"))?;
    let output = derive(&master_key, &context).map_err(|e| format!("{e}"))?;
    Ok(secret_bytes(&output))
}

/// Extract the primary secret bytes from a profile output, mirroring the CLI's
/// `--format binary` selection.
fn secret_bytes(output: &ProfileOutput) -> Vec<u8> {
    match output {
        ProfileOutput::SecretKey(k) => k.0.to_vec(),
        ProfileOutput::Ed25519Seed(s) => s.0.to_vec(),
        ProfileOutput::MlKemKeypair(kp) => kp.decapsulation_key.clone(),
        ProfileOutput::MlDsaKeypair(kp) => kp.signing_key.clone(),
        ProfileOutput::AgeIdentity(a) => a.secret_key.to_vec(),
        ProfileOutput::Raw(r) => r.0.clone(),
    }
}

// --- JNI marshalling shim ---
//
// Confined to this module so the `unsafe` attribute the export requires does
// not bleed into the logic above. `#[unsafe(no_mangle)] extern "system"` is the
// only way the JVM can resolve the native method by symbol name.

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint};
use zeroize::Zeroize;

/// JNI entry point for `app.ykdf.Native.derive(...)`.
///
/// On success returns a freshly allocated `byte[]`. On any error it throws a
/// Java `IllegalArgumentException` carrying the message and returns null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_ykdf_Native_derive<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    ikm: JByteArray<'local>,
    pipeline: JString<'local>,
    profile: JString<'local>,
    purpose: JString<'local>,
    index: jint,
) -> jbyteArray {
    match run(&mut env, &ikm, &pipeline, &profile, &purpose, index) {
        Ok(bytes) => env
            .byte_array_from_slice(&bytes)
            .map_or(std::ptr::null_mut(), JByteArray::into_raw),
        Err(msg) => {
            // Leaves a pending exception on the JVM; the returned null is
            // ignored once an exception is set.
            let _ = env.throw_new("java/lang/IllegalArgumentException", msg);
            std::ptr::null_mut()
        }
    }
}

fn run(
    env: &mut JNIEnv<'_>,
    ikm: &JByteArray<'_>,
    pipeline: &JString<'_>,
    profile: &JString<'_>,
    purpose: &JString<'_>,
    index: jint,
) -> Result<Vec<u8>, String> {
    let mut ikm_bytes = env.convert_byte_array(ikm).map_err(|e| e.to_string())?;
    let pipeline = jstring(env, pipeline)?;
    let profile = jstring(env, profile)?;
    let purpose = jstring(env, purpose)?;
    let index = u32::try_from(index).map_err(|_| "index must be non-negative".to_owned())?;

    let result = derive_secret(&ikm_bytes, &pipeline, &profile, &purpose, index);
    // Wipe the IKM copy we pulled across the boundary regardless of outcome.
    ikm_bytes.zeroize();
    result
}

fn jstring(env: &mut JNIEnv<'_>, s: &JString<'_>) -> Result<String, String> {
    env.get_string(s)
        .map(|js| js.to_string_lossy().into_owned())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::derive_secret;

    /// Pinned to the frozen golden vector `symmetric/hkdf-sha512` in
    /// `vectors/v1.json` (ikm 00..1f, purpose "test", index 0). Proves the JNI
    /// helper reproduces the canonical derivation byte-for-byte, so the value
    /// the Android app sees equals the value the CLI and every reference
    /// implementation must produce.
    #[test]
    fn matches_golden_symmetric_vector() {
        let ikm: Vec<u8> = (0u8..32).collect();
        let out = derive_secret(&ikm, "hkdf-sha512", "symmetric", "test", 0).unwrap();
        let expected: [u8; 32] = [
            0x65, 0x9b, 0x58, 0xbf, 0xaa, 0x1b, 0x96, 0x74, 0xad, 0xf3, 0x12, 0xb3, 0x95, 0xd5,
            0x8a, 0x07, 0xea, 0x57, 0x15, 0xf7, 0xe9, 0x50, 0x14, 0x2a, 0xdd, 0x22, 0x9a, 0x0b,
            0x42, 0xa5, 0x38, 0x03,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn is_deterministic() {
        let ikm: Vec<u8> = (0u8..32).collect();
        let a = derive_secret(&ikm, "hkdf-sha512", "x25519", "wg-home", 0).unwrap();
        let b = derive_secret(&ikm, "hkdf-sha512", "x25519", "wg-home", 0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_short_ikm() {
        assert!(derive_secret(&[0u8; 8], "hkdf-sha512", "symmetric", "test", 0).is_err());
    }

    #[test]
    fn rejects_disallowed_pipeline() {
        let ikm: Vec<u8> = (0u8..32).collect();
        // x25519 is classical: SHAKE256 is not an accepted pipeline for it.
        assert!(derive_secret(&ikm, "shake256", "x25519", "test", 0).is_err());
    }
}
