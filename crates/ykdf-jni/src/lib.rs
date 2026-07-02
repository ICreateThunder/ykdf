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

use ykdf_core::{Context, Ikm, Pipeline, Profile, ProfileOutput, derive, extract};

/// Run a YKDF derivation from raw input key material.
///
/// `profile` and `purpose` are the self-describing context fields (see
/// `docs/SPEC.md`). `pipeline` may be empty, in which case the profile's
/// default pipeline is used (the common case); otherwise it is an explicit
/// override that the profile must accept. An invalid or disallowed combination
/// is rejected exactly as the CLI rejects it.
///
/// Returns the profile's primary secret bytes: the same bytes the CLI emits in
/// `--format binary`.
///
/// # Errors
///
/// Returns a human-readable message if the profile or pipeline label is
/// unknown, the IKM is too short, the profile/pipeline combination is not
/// accepted, or derivation fails.
pub fn derive_secret(
    ikm: &[u8],
    pipeline: &str,
    profile: &str,
    purpose: &str,
    index: u32,
) -> Result<Vec<u8>, String> {
    let (_profile, output) = derive_output(ikm, pipeline, profile, purpose, index)?;
    Ok(secret_bytes(&output))
}

/// Derive and format the public key for a derivation: the same string the CLI's
/// `ykdf pubkey` prints (base64 for x25519/ML-KEM/ML-DSA, an OpenSSH line for
/// ed25519, an `age1` recipient for age). The public key is not secret.
///
/// # Errors
///
/// Returns a message for an unknown profile/pipeline, invalid IKM, a disallowed
/// combination, or a profile that has no public key (`symmetric`, `raw`).
pub fn public_key(
    ikm: &[u8],
    pipeline: &str,
    profile: &str,
    purpose: &str,
    index: u32,
) -> Result<String, String> {
    let (profile_enum, output) = derive_output(ikm, pipeline, profile, purpose, index)?;
    ykdf_core::public_key_string(&output, profile_enum)
        .ok_or_else(|| format!("the {profile} profile has no public key"))
}

/// Resolve the context and run the derivation, returning the resolved profile
/// with its output so callers can take either the secret bytes or the public
/// key. Shared by [`derive_secret`] and [`public_key`].
fn derive_output(
    ikm: &[u8],
    pipeline: &str,
    profile: &str,
    purpose: &str,
    index: u32,
) -> Result<(Profile, ProfileOutput), String> {
    let profile =
        Profile::from_str_label(profile).ok_or_else(|| format!("unknown profile: {profile}"))?;
    let context = if pipeline.is_empty() {
        Context::new(profile, purpose, index).map_err(|e| format!("{e}"))?
    } else {
        let pipeline = Pipeline::from_str_label(pipeline)
            .ok_or_else(|| format!("unknown pipeline: {pipeline}"))?;
        Context::with_pipeline(profile, pipeline, purpose, index).map_err(|e| format!("{e}"))?
    };

    let ikm = Ikm::new(ikm.to_vec()).map_err(|e| format!("{e}"))?;
    let master_key = extract(&ikm, context.pipeline()).map_err(|e| format!("{e}"))?;
    let output = derive(&master_key, &context).map_err(|e| format!("{e}"))?;
    Ok((profile, output))
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
use jni::sys::{jbyteArray, jint, jstring};
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
        Ok(mut bytes) => {
            // Copy into the JVM, then wipe this last native-side copy. The
            // derived secret would otherwise sit in freed heap after drop,
            // escaping the ZeroizeOnDrop chain of Ikm/MasterKey/ProfileOutput.
            let array = env
                .byte_array_from_slice(&bytes)
                .map_or(std::ptr::null_mut(), JByteArray::into_raw);
            bytes.zeroize();
            array
        }
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

/// JNI entry point for `app.ykdf.Native.derivePublic(...)`.
///
/// On success returns a Java `String` with the formatted public key. On any
/// error (including a profile with no public key) it throws a Java
/// `IllegalArgumentException` and returns null. The public key is not secret,
/// so it is not zeroized.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_ykdf_Native_derivePublic<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    ikm: JByteArray<'local>,
    pipeline: JString<'local>,
    profile: JString<'local>,
    purpose: JString<'local>,
    index: jint,
) -> jstring {
    match run_public(&mut env, &ikm, &pipeline, &profile, &purpose, index) {
        Ok(s) => env
            .new_string(s)
            .map_or(std::ptr::null_mut(), jni::objects::JString::into_raw),
        Err(msg) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", msg);
            std::ptr::null_mut()
        }
    }
}

fn run_public(
    env: &mut JNIEnv<'_>,
    ikm: &JByteArray<'_>,
    pipeline: &JString<'_>,
    profile: &JString<'_>,
    purpose: &JString<'_>,
    index: jint,
) -> Result<String, String> {
    let mut ikm_bytes = env.convert_byte_array(ikm).map_err(|e| e.to_string())?;
    let pipeline = jstring(env, pipeline)?;
    let profile = jstring(env, profile)?;
    let purpose = jstring(env, purpose)?;
    let index = u32::try_from(index).map_err(|_| "index must be non-negative".to_owned())?;

    let result = public_key(&ikm_bytes, &pipeline, &profile, &purpose, index);
    // Wipe the IKM copy we pulled across the boundary regardless of outcome.
    ikm_bytes.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::{derive_secret, public_key};

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
    fn empty_pipeline_uses_profile_default() {
        // symmetric's default pipeline is hkdf-sha512, so an empty pipeline must
        // reproduce the same golden vector as the explicit label above.
        let ikm: Vec<u8> = (0u8..32).collect();
        let explicit = derive_secret(&ikm, "hkdf-sha512", "symmetric", "test", 0).unwrap();
        let default = derive_secret(&ikm, "", "symmetric", "test", 0).unwrap();
        assert_eq!(default, explicit);
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

    #[test]
    fn public_key_is_deterministic_base64() {
        let ikm: Vec<u8> = (0u8..32).collect();
        let a = public_key(&ikm, "", "x25519", "wg-home", 0).unwrap();
        let b = public_key(&ikm, "", "x25519", "wg-home", 0).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 44); // base64 of the 32-byte x25519 public key
    }

    #[test]
    fn public_key_rejects_symmetric() {
        let ikm: Vec<u8> = (0u8..32).collect();
        assert!(public_key(&ikm, "", "symmetric", "test", 0).is_err());
    }
}
