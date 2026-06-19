//! Miri-friendly exercise of the core byte-paths.
//!
//! Drives extract -> expand -> derive/cascade across all three pipelines and
//! the classical profiles, hitting the manual array/slice/zeroize code where
//! undefined behaviour could hide. Deliberately excludes ML-KEM, Argon2, and
//! proptest so it stays fast enough to run under Miri in CI. The classical
//! profiles post-process by byte manipulation only (clamping, seed
//! passthrough), so no curve scalar arithmetic runs here.

use ykdf_core::{
    Context, Ikm, Pipeline, Profile, ProfileOutput, cascade, derive, derive_raw, extract,
};

const PIPELINES: [Pipeline; 3] = [Pipeline::HkdfSha512, Pipeline::HkdfSha3, Pipeline::Shake256];

fn test_ikm() -> Ikm {
    Ikm::new((0u8..32).collect()).unwrap()
}

#[test]
fn extract_all_pipelines() {
    let ikm = test_ikm();
    for pipeline in PIPELINES {
        let mk = extract(&ikm, pipeline).unwrap();
        assert_eq!(mk.as_bytes().len(), 64);
    }
}

/// Lengths crossing the 64-byte hash-block boundary exercise the HKDF-Expand
/// counter loop, the per-iteration truncation, and the SHAKE squeeze.
#[test]
fn expand_multiblock_and_truncation() {
    let ikm = test_ikm();
    for pipeline in PIPELINES {
        let mk = extract(&ikm, pipeline).unwrap();
        let ctx = Context::with_pipeline(Profile::Raw, pipeline, "miri", 0).unwrap();
        for len in [1usize, 31, 64, 65, 127, 200] {
            let out = derive_raw(&mk, &ctx, len).unwrap();
            match &out {
                ProfileOutput::Raw(raw) => assert_eq!(raw.0.len(), len),
                _ => panic!("expected Raw output"),
            }
        }
    }
}

/// Classical profiles post-process expanded bytes in place; no curve math.
#[test]
fn classical_profiles_derive() {
    let ikm = test_ikm();
    let mk = extract(&ikm, Pipeline::HkdfSha512).unwrap();
    for profile in [
        Profile::X25519,
        Profile::Ed25519,
        Profile::AgeX25519,
        Profile::Symmetric,
        Profile::Raw,
    ] {
        let ctx = Context::new(profile, "miri", 0).unwrap();
        derive(&mk, &ctx).unwrap();
    }
}

#[test]
fn cascade_paths() {
    let ikm = test_ikm();
    for pipeline in PIPELINES {
        let early = extract(&ikm, pipeline).unwrap();
        let cascaded = cascade(&early, b"second-factor", pipeline).unwrap();
        assert_ne!(early.as_bytes(), cascaded.as_bytes());
    }
}
