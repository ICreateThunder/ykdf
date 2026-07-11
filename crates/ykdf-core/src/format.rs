//! Optional public-key formatting, shared by the CLI and the JNI bridge.
//!
//! Enabled by the `format` feature so the default core stays minimal. The
//! output is the canonical public representation for each profile, byte-identical
//! to what `ykdf pubkey` prints.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::{Profile, ProfileOutput};

/// The public key for a derivation, in the canonical form for its profile:
/// base64 for x25519 (also the `WireGuard` public-key encoding) and for ML-KEM /
/// ML-DSA, a one-line OpenSSH key for ed25519, and an `age1` recipient for age.
///
/// Returns `None` for profiles that have no public key (`symmetric`, `raw`).
#[must_use]
pub fn public_key_string(output: &ProfileOutput, profile: Profile) -> Option<String> {
    match output {
        ProfileOutput::SecretKey(k) if profile == Profile::X25519 => {
            let secret = x25519_dalek::StaticSecret::from(k.0);
            Some(BASE64.encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
        }
        ProfileOutput::Ed25519Seed(s) => {
            let verifying = ed25519_dalek::SigningKey::from_bytes(&s.0).verifying_key();
            let mut blob = Vec::new();
            write_openssh_string(&mut blob, b"ssh-ed25519");
            write_openssh_string(&mut blob, verifying.as_bytes());
            Some(format!("ssh-ed25519 {}", BASE64.encode(&blob)))
        }
        ProfileOutput::AgeIdentity(a) => {
            let secret = x25519_dalek::StaticSecret::from(a.secret_key);
            let public = x25519_dalek::PublicKey::from(&secret);
            let hrp = bech32::Hrp::parse("age").ok()?;
            bech32::encode::<bech32::Bech32>(hrp, public.as_bytes()).ok()
        }
        ProfileOutput::MlKemKeypair(kp) => Some(BASE64.encode(&kp.encapsulation_key)),
        ProfileOutput::MlDsaKeypair(kp) => Some(BASE64.encode(&kp.verifying_key)),
        // Symmetric (a SecretKey without the x25519 guard) and raw have no
        // public key.
        ProfileOutput::SecretKey(_) | ProfileOutput::Raw(_) => None,
    }
}

/// Write a length-prefixed OpenSSH string (u32 big-endian length + bytes).
pub(crate) fn write_openssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::public_key_string;
    use crate::{Context, Ikm, Profile, derive, extract};

    /// Derive the public key for a profile from the golden IKM (0x00..0x1f).
    fn pubkey(profile_label: &str) -> Option<String> {
        let profile = Profile::from_str_label(profile_label).unwrap();
        let ctx = Context::new(profile, "test", 0).unwrap();
        let ikm = Ikm::new((0u8..32).collect()).unwrap();
        let mk = extract(&ikm, ctx.pipeline()).unwrap();
        let out = derive(&mk, &ctx).unwrap();
        public_key_string(&out, profile)
    }

    #[test]
    fn x25519_is_44_char_base64() {
        assert_eq!(pubkey("x25519").unwrap().len(), 44);
    }

    #[test]
    fn ed25519_is_openssh_one_line() {
        assert!(pubkey("ed25519").unwrap().starts_with("ssh-ed25519 "));
    }

    #[test]
    fn age_is_a_recipient() {
        assert!(pubkey("age-x25519").unwrap().starts_with("age1"));
    }

    #[test]
    fn mlkem_and_mldsa_have_public_keys() {
        assert!(!pubkey("mlkem768").unwrap().is_empty());
        assert!(!pubkey("mldsa65").unwrap().is_empty());
    }

    #[test]
    fn symmetric_has_no_public_key() {
        assert!(pubkey("symmetric").is_none());
    }

    #[test]
    fn deterministic() {
        assert_eq!(pubkey("x25519"), pubkey("x25519"));
    }
}
