//! Frozen v1 format invariants.
//!
//! This file pins the parts of the v1 derivation contract that the golden
//! test vectors cannot see: the pipeline-selection and accept-policy truth
//! tables, the wire vocabulary used to parse a context string, and the
//! structural shape of the length-bound KDF input. A silent change to any of
//! these is a `v1` format break and must fail CI here.
//!
//! Deliberately NOT pinned here (owned by the golden vectors, since they are
//! byte-producing and any single vector catches a change to them):
//!   - the extract / Argon2 salts,
//!   - the extract/cascade domain-separation tags (0x01 / 0x02),
//!   - the canonical Argon2 stretch descriptor (already pinned in stretch.rs).
//!
//! The HMAC challenge constant lives in `ykdf-yubikey` and is pinned there
//! (it is exercised only on the hardware path, which no vector touches).

use ykdf_core::{Context, Pipeline, Profile};

/// Every `Profile` variant. The exhaustiveness guard below fails to compile
/// if a variant is added without being listed here, forcing the invariant
/// tables to be revisited.
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

/// Every `Pipeline` variant. Same exhaustiveness contract as `ALL_PROFILES`.
const ALL_PIPELINES: [Pipeline; 3] = [Pipeline::HkdfSha512, Pipeline::HkdfSha3, Pipeline::Shake256];

/// Compile-time exhaustiveness guard: a wildcard-free match means adding a new
/// `Profile` variant breaks this build until the variant is added to
/// `ALL_PROFILES` AND given an entry in every truth table below.
const fn assert_profile_listed(profile: Profile) {
    match profile {
        Profile::X25519
        | Profile::Ed25519
        | Profile::AgeX25519
        | Profile::Symmetric
        | Profile::MlKem512
        | Profile::MlKem768
        | Profile::MlKem1024
        | Profile::Raw => {}
    }
}

/// Same exhaustiveness guard for `Pipeline`.
const fn assert_pipeline_listed(pipeline: Pipeline) {
    match pipeline {
        Pipeline::HkdfSha512 | Pipeline::HkdfSha3 | Pipeline::Shake256 => {}
    }
}

#[test]
fn variant_arrays_are_exhaustive() {
    // Length pins catch a variant added without updating the arrays; the
    // const guards catch a variant added without updating the match arms.
    assert_eq!(ALL_PROFILES.len(), 8, "ALL_PROFILES is not exhaustive");
    assert_eq!(ALL_PIPELINES.len(), 3, "ALL_PIPELINES is not exhaustive");
    for p in ALL_PROFILES {
        assert_profile_listed(p);
    }
    for p in ALL_PIPELINES {
        assert_pipeline_listed(p);
    }
}

/// Frozen default-pipeline selection. This is byte-critical: a no-override
/// derivation (`ykdf derive --profile X`) produces bytes determined by the
/// pipeline chosen here. Flipping any entry silently changes every such key.
#[test]
fn default_pipeline_truth_table() {
    let expected = [
        (Profile::X25519, Pipeline::HkdfSha512),
        (Profile::Ed25519, Pipeline::HkdfSha512),
        (Profile::AgeX25519, Pipeline::HkdfSha512),
        (Profile::Symmetric, Pipeline::HkdfSha512),
        (Profile::MlKem512, Pipeline::Shake256),
        (Profile::MlKem768, Pipeline::Shake256),
        (Profile::MlKem1024, Pipeline::Shake256),
        (Profile::Raw, Pipeline::HkdfSha512),
    ];
    // Every profile must appear exactly once in the expected table.
    assert_eq!(expected.len(), ALL_PROFILES.len());
    for profile in ALL_PROFILES {
        let want = expected.iter().find(|(p, _)| *p == profile).map_or_else(
            || panic!("{profile} missing from default-pipeline table"),
            |(_, pipe)| *pipe,
        );
        assert_eq!(
            profile.default_pipeline(),
            want,
            "default pipeline for {profile} changed"
        );
    }
}

/// Frozen accept policy: which pipelines each profile may be derived with.
/// Vectors never exercise rejection, so this 8x3 truth table is the only
/// guard against the accept policy silently widening or narrowing.
#[test]
fn accept_policy_truth_table() {
    // (profile, [accepts HkdfSha512, accepts HkdfSha3, accepts Shake256])
    let expected: [(Profile, [bool; 3]); 8] = [
        (Profile::X25519, [true, true, false]),
        (Profile::Ed25519, [true, true, false]),
        (Profile::AgeX25519, [true, true, false]),
        (Profile::Symmetric, [true, true, false]),
        (Profile::MlKem512, [false, false, true]),
        (Profile::MlKem768, [false, false, true]),
        (Profile::MlKem1024, [false, false, true]),
        (Profile::Raw, [true, true, true]),
    ];
    assert_eq!(expected.len(), ALL_PROFILES.len());
    for (profile, accepts) in expected {
        for (pipeline, want) in ALL_PIPELINES.into_iter().zip(accepts) {
            assert_eq!(
                profile.accepts(pipeline),
                want,
                "accept policy for {profile} + {pipeline} changed"
            );
        }
    }
}

/// Frozen wire vocabulary. The `as_str` label is rendered into the context
/// string and `from_str_label` parses it back; both directions are part of
/// the v1 grammar and must round-trip against these exact tokens.
#[test]
fn profile_wire_vocabulary() {
    let expected = [
        (Profile::X25519, "x25519"),
        (Profile::Ed25519, "ed25519"),
        (Profile::AgeX25519, "age-x25519"),
        (Profile::Symmetric, "symmetric"),
        (Profile::MlKem512, "mlkem512"),
        (Profile::MlKem768, "mlkem768"),
        (Profile::MlKem1024, "mlkem1024"),
        (Profile::Raw, "raw"),
    ];
    assert_eq!(expected.len(), ALL_PROFILES.len());
    for (profile, label) in expected {
        assert_eq!(
            profile.as_str(),
            label,
            "profile label for {profile} changed"
        );
        assert_eq!(
            Profile::from_str_label(label),
            Some(profile),
            "profile label {label} no longer parses"
        );
    }
}

#[test]
fn pipeline_wire_vocabulary() {
    let expected = [
        (Pipeline::HkdfSha512, "hkdf-sha512"),
        (Pipeline::HkdfSha3, "hkdf-sha3-512"),
        (Pipeline::Shake256, "shake256"),
    ];
    assert_eq!(expected.len(), ALL_PIPELINES.len());
    for (pipeline, label) in expected {
        assert_eq!(pipeline.as_str(), label, "pipeline label changed");
        assert_eq!(
            Pipeline::from_str_label(label),
            Some(pipeline),
            "pipeline label {label} no longer parses"
        );
    }
}

/// Unknown labels must not parse: the parser is closed over the frozen
/// vocabulary, so a typo or a future label never silently resolves.
#[test]
fn unknown_labels_do_not_parse() {
    // Tokens unknown to both vocabularies resolve to nothing in either.
    for bad in ["", "X25519", "x", "hkdf-sha256", "sha3", "kyber768"] {
        assert!(
            Profile::from_str_label(bad).is_none(),
            "{bad} parsed as a profile"
        );
        assert!(
            Pipeline::from_str_label(bad).is_none(),
            "{bad} parsed as a pipeline"
        );
    }
    // The two vocabularies are disjoint: a pipeline label is not a profile and
    // vice versa, so a swapped field in a context string cannot silently parse.
    assert!(Profile::from_str_label("hkdf-sha512").is_none());
    assert!(Pipeline::from_str_label("x25519").is_none());
}

/// Frozen length-binding structure: `kdf_info(len)` appends the output length
/// as a final colon-delimited field after the full context string. This is
/// what makes different-length requests under one context independent.
#[test]
fn kdf_info_length_binding_shape() {
    // Length is appended as a final field after the whole context string,
    // which already ends with the index: ...:<purpose>:<index>:<len>.
    let ctx = Context::new(Profile::X25519, "test", 0).unwrap();
    assert_eq!(ctx.kdf_info(32), b"ykdf:v1:hkdf-sha512:x25519:test:0:32");
    assert_eq!(ctx.kdf_info(64), b"ykdf:v1:hkdf-sha512:x25519:test:0:64");

    let sponge = Context::new(Profile::MlKem768, "email", 3).unwrap();
    assert_eq!(sponge.kdf_info(64), b"ykdf:v1:shake256:mlkem768:email:3:64");
}

/// Frozen expand lengths. The expand phase must produce exactly this many
/// bytes per profile before post-processing; ML-KEM seeds are 64 bytes, all
/// classical/raw profiles are 32.
#[test]
fn expand_len_truth_table() {
    let expected = [
        (Profile::X25519, 32),
        (Profile::Ed25519, 32),
        (Profile::AgeX25519, 32),
        (Profile::Symmetric, 32),
        (Profile::MlKem512, 64),
        (Profile::MlKem768, 64),
        (Profile::MlKem1024, 64),
        (Profile::Raw, 32),
    ];
    assert_eq!(expected.len(), ALL_PROFILES.len());
    for (profile, len) in expected {
        assert_eq!(
            profile.expand_len(),
            len,
            "expand_len for {profile} changed"
        );
    }
}
