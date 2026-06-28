//! Property tests for the v1 derivation core.
//!
//! These exercise the boundaries the golden vectors cannot: the length-binding
//! security property (output for one length is never a prefix of another), the
//! context grammar round-trip over arbitrary valid inputs, and the IKM
//! minimum-entropy guard. Run as part of the correctness gate, before any
//! vectors freeze the byte output.

use proptest::prelude::*;
use ykdf_core::{Context, Ikm, Pipeline, Profile, ProfileOutput, derive_raw, extract};

const ALL_PROFILES: [Profile; 8] = [
    Profile::X25519,
    Profile::Ed25519,
    Profile::AgeX25519,
    Profile::Symmetric,
    Profile::MlKem512,
    Profile::MlKem768,
    Profile::MlKem1024,
    Profile::Raw,
];

const ALL_PIPELINES: [Pipeline; 3] = [Pipeline::HkdfSha512, Pipeline::HkdfSha3, Pipeline::Shake256];

/// A purpose string matching the `Purpose` grammar: lowercase ASCII
/// alphanumeric and hyphens, 1-64 chars, no leading or trailing hyphen.
fn valid_purpose() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?").unwrap()
}

/// At least `MIN_IKM_LEN` bytes so `extract` always has usable material.
fn good_ikm() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 16..96)
}

fn raw_bytes(output: &ProfileOutput) -> Vec<u8> {
    match output {
        ProfileOutput::Raw(raw) => raw.0.clone(),
        _ => panic!("expected Raw output"),
    }
}

proptest! {
    /// Every well-formed context round-trips through its string form unchanged,
    /// for every profile and every pipeline that profile accepts.
    #[test]
    fn context_round_trips(purpose in valid_purpose(), index in any::<u32>()) {
        for profile in ALL_PROFILES {
            for pipeline in ALL_PIPELINES {
                if !profile.accepts(pipeline) {
                    continue;
                }
                let ctx = Context::with_pipeline(profile, pipeline, &purpose, index).unwrap();
                let parsed: Context = ctx.to_string().parse().unwrap();
                prop_assert_eq!(&ctx, &parsed);
            }
        }
    }

    /// Length binding: output for length `a` is NEVER a prefix of output for a
    /// longer length `b`. This defeats the HKDF/XOF prefix property and is the
    /// core security guarantee of embedding the length in `kdf_info`. Checked
    /// across all three pipelines via the Raw profile (which accepts any).
    ///
    /// `a` starts at 16 bytes: a non-length-bound implementation fails this for
    /// every `a` (its streams share a prefix), but two *correctly* independent
    /// streams can coincide in their first few bytes by chance (~256^-a). The
    /// 16-byte floor makes that 2^-128 - impossible - so the test stays
    /// deterministic instead of flaking ~1/256 of the time at `a == 1`.
    #[test]
    fn length_binding_defeats_prefix(
        ikm_bytes in good_ikm(),
        purpose in valid_purpose(),
        index in any::<u32>(),
        a in 16usize..200,
        delta in 1usize..200,
    ) {
        let b = a + delta;
        let ikm = Ikm::new(ikm_bytes).unwrap();
        for pipeline in ALL_PIPELINES {
            let mk = extract(&ikm, pipeline).unwrap();
            let ctx = Context::with_pipeline(Profile::Raw, pipeline, &purpose, index).unwrap();

            let out_a = raw_bytes(&derive_raw(&mk, &ctx, a).unwrap());
            let out_b = raw_bytes(&derive_raw(&mk, &ctx, b).unwrap());

            prop_assert_eq!(out_a.len(), a);
            prop_assert_eq!(out_b.len(), b);
            // The shorter output must not be a prefix of the longer one.
            prop_assert_ne!(&out_a[..], &out_b[..a]);
        }
    }

    /// Derivation is deterministic: identical inputs yield identical bytes.
    #[test]
    fn derivation_is_deterministic(
        ikm_bytes in good_ikm(),
        purpose in valid_purpose(),
        index in any::<u32>(),
        len in 1usize..128,
    ) {
        let ikm = Ikm::new(ikm_bytes).unwrap();
        for pipeline in ALL_PIPELINES {
            let mk = extract(&ikm, pipeline).unwrap();
            let ctx = Context::with_pipeline(Profile::Raw, pipeline, &purpose, index).unwrap();
            let first = raw_bytes(&derive_raw(&mk, &ctx, len).unwrap());
            let second = raw_bytes(&derive_raw(&mk, &ctx, len).unwrap());
            prop_assert_eq!(first, second);
        }
    }

    /// The IKM guard accepts exactly the inputs at or above the 16-byte floor
    /// and rejects everything shorter.
    #[test]
    fn ikm_enforces_minimum(bytes in prop::collection::vec(any::<u8>(), 0..40)) {
        let result = Ikm::new(bytes.clone());
        if bytes.len() >= 16 {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Distinct purposes under one pipeline produce distinct outputs (domain
    /// separation). Collisions are cryptographically negligible.
    #[test]
    fn distinct_purposes_diverge(
        ikm_bytes in good_ikm(),
        p1 in valid_purpose(),
        p2 in valid_purpose(),
    ) {
        prop_assume!(p1 != p2);
        let ikm = Ikm::new(ikm_bytes).unwrap();
        let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
        let ctx1 = Context::with_pipeline(Profile::Raw, Pipeline::HkdfSha512, &p1, 0).unwrap();
        let ctx2 = Context::with_pipeline(Profile::Raw, Pipeline::HkdfSha512, &p2, 0).unwrap();
        let out1 = raw_bytes(&derive_raw(&mk, &ctx1, 32).unwrap());
        let out2 = raw_bytes(&derive_raw(&mk, &ctx2, 32).unwrap());
        prop_assert_ne!(out1, out2);
    }
}
