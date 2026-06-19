use bech32::{Bech32, Hrp};

use crate::Result;
use crate::error::Error;
use crate::profile::{AgeIdentityBytes, ProfileOutput, take_fixed};
use crate::types::ExpandedBytes;

const AGE_HRP: Hrp = Hrp::parse_unchecked("age-secret-key-");

/// Clamp as x25519 and encode as an age identity (bech32).
///
/// # Errors
///
/// Returns `Error::ExpandLength` if `expanded` is not 32 bytes.
/// Returns `Error::PostProcessing` if bech32 encoding fails.
pub fn post_process(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let mut key = take_fixed::<32>(expanded)?;

    // Curve25519 clamping
    key[0] &= 0xF8;
    key[31] &= 0x7F;
    key[31] |= 0x40;

    let identity = bech32::encode::<Bech32>(AGE_HRP, &key).map_err(|e| Error::PostProcessing {
        detail: e.to_string(),
    })?;

    let identity = identity.to_uppercase();

    Ok(ProfileOutput::AgeIdentity(AgeIdentityBytes {
        secret_key: key,
        identity,
    }))
}

#[cfg(test)]
mod tests {
    use super::{AGE_HRP, post_process};
    use crate::profile::ProfileOutput;
    use crate::types::ExpandedBytes;
    use bech32::{Bech32, Bech32m};

    /// Interop closer: the emitted identity must be a structurally valid age
    /// x25519 secret key. age uses uppercase Bech32 (not Bech32m) over the HRP
    /// `age-secret-key-` and the 32-byte clamped scalar. This decodes the
    /// identity independently and pins every one of those facts, so a
    /// regression in HRP, checksum variant, clamping, or length is caught
    /// before any golden vector blesses the output.
    #[test]
    fn identity_is_valid_age_secret_key() {
        let raw = [0x11u8; 32];
        let out = post_process(&ExpandedBytes::new(raw.to_vec())).unwrap();
        let (secret_key, identity) = match &out {
            ProfileOutput::AgeIdentity(a) => (a.secret_key, a.identity.clone()),
            _ => panic!("expected AgeIdentity"),
        };

        // Independently clamp the same bytes; post_process must agree.
        let mut expected = raw;
        expected[0] &= 0xF8;
        expected[31] &= 0x7F;
        expected[31] |= 0x40;
        assert_eq!(secret_key, expected);

        // age identities are uppercase and prefixed.
        assert!(identity.starts_with("AGE-SECRET-KEY-1"));
        assert_eq!(identity, identity.to_uppercase());

        // Decode independently (lowercase first; bech32 rejects mixed case).
        let (hrp, data) = bech32::decode(&identity.to_lowercase()).expect("valid bech32");
        assert_eq!(hrp.to_string(), "age-secret-key-");
        assert_eq!(data, expected);

        // Variant must be Bech32, not Bech32m.
        let as_bech32 = bech32::encode::<Bech32>(AGE_HRP, &expected)
            .unwrap()
            .to_uppercase();
        let as_bech32m = bech32::encode::<Bech32m>(AGE_HRP, &expected)
            .unwrap()
            .to_uppercase();
        assert_eq!(identity, as_bech32);
        assert_ne!(identity, as_bech32m);

        // The checksum is enforced: a single-character corruption fails to decode.
        let mut chars: Vec<char> = identity.to_lowercase().chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(bech32::decode(&corrupted).is_err());
    }
}
